package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/policy"
	"github.com/GurdyAI/gurdy/proxy/internal/tis"
)

// The sideband TIS API (D1, §5.9): root mint and child derive, and nothing
// else. Three deliberate boundaries, each of which was the wrong answer at
// some point in the design:
//
//   - Not the admin API. §7's disarm row — a prompt-injected agent on the box
//     calling /policy/rollback — is already unmitigated; adding credential
//     issuance to that surface widens a hole instead of opening a separate,
//     narrow one.
//   - Not a reverse-proxy path carve-out. A governed agent reaches the proxy's
//     tool endpoint by definition, so any mint path mounted there is reachable
//     by exactly the party that must not be able to quietly re-identify itself.
//   - No /derive-call. Per-call assertions are derived by the proxy from the
//     txn token it is already handed; exposing that would let an agent choose
//     the `tool` its own assertion names.
//
// A Unix socket, not a port: the SDK runs beside the proxy in every topology
// that has one (dev mode's embedded core, the sidecar's shared volume), and a
// socket cannot be reached from another host by accident or by scan.
//
// **Mint is unauthenticated in v1, deliberately.** What it issues is *asserted*
// identity (§5.2) — a claim the ledger records as a claim and policy sees only
// as reserved context. Gating it would distribute a secret to every agent
// without changing what a record means. The file mode is the access control:
// owner-only, so "who may mint" is "who may act as this user", which is
// already true of anything running here. `cnf` proof-of-possession lands with
// the SDK. **This stops being adequate the moment enforcement or a
// scope-reading policy exists** — MintTxn accepts any root scope, so an
// injected agent can mint `scope=*` (roadmap §3.B, Phase 2 gate).
func mintMux(t *tis.TIS, store *policy.Store) http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, code int, err error) {
		writeJSON(w, code, map[string]string{"error": err.Error()})
	}

	// POST /mint — a task's root transaction credential. Agent and human actor
	// are the caller's claims about itself; they reach a record as asserted_*
	// and never as the policy principal, which is why accepting them unchecked
	// is sound (§5.5).
	mux.HandleFunc("POST /mint", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent      string    `json:"agent"`
			HumanActor string    `json:"human_actor"`
			Scope      tis.Scope `json:"scope"`
			TTLSeconds int       `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		tok, err := t.MintTxn(req.Agent, req.HumanActor, req.Scope,
			store.Current().Version, time.Duration(req.TTLSeconds)*time.Second)
		if errors.Is(err, tis.ErrNoAgent) {
			// The library owns the rule (every caller routes through it); the
			// endpoint only has to report it as the caller's mistake, not the
			// server's.
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"txn": tok})
	})

	// POST /derive — a sub-agent's transaction, from a live parent. The
	// narrow-only algebra is enforced here exactly as it is internally: this
	// endpoint is the spawn-time round trip §5.2 describes, and a scope that
	// is not provably a narrowing is rejected rather than clamped, because
	// clamping would silently hand back a credential nobody asked for.
	mux.HandleFunc("POST /derive", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Parent string    `json:"parent"`
			Agent  string    `json:"agent"`
			Scope  tis.Scope `json:"scope"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		tok, err := t.DeriveChildTxn(req.Parent, req.Agent, req.Scope)
		if errors.Is(err, tis.ErrNoAgent) {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err != nil {
			// A widening attempt is a client error, not a server one, and it
			// is worth saying which: the SDK author who sees "scope widens"
			// learns the rule, and the corpus trace asserts on it.
			fail(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"txn": tok})
	})
	return mux
}

// listenMint opens the sideband socket owner-only. A stale socket file from a
// crashed proxy is removed; a *live* one is not — two proxies sharing a state
// directory would otherwise fight over it, and the second one silently winning
// is worse than refusing to start.
func listenMint(path string) (net.Listener, error) {
	// 0700, not 0755: this directory holds the deployment's signing keys, so a
	// wider mode was already wrong, and it is what actually gates the socket —
	// between bind and chmod the socket itself is briefly world-addressable,
	// and a private parent closes that window rather than narrowing it.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		// Only ever unlink an actual socket. A typo in -tis-socket must not
		// delete the file it happens to name — deleting someone's work because
		// a path was wrong is precisely the failure this project spent a day
		// recovering from.
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("tis: %s exists and is not a socket; refusing to remove it", path)
		}
		if c, derr := net.DialTimeout("unix", path, 200*time.Millisecond); derr == nil {
			c.Close()
			return nil, fmt.Errorf("tis: %s is already served by another process", path)
		}
		os.Remove(path) // stale socket: nobody is listening
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		// The kernel caps socket paths at ~104 bytes (macOS) / 108 (Linux),
		// and the failure it returns for an over-long one is "invalid
		// argument", which says nothing about length. A deep -state-dir is an
		// ordinary way to hit it.
		if len(path) > 100 {
			return nil, fmt.Errorf("tis: socket path %q is %d bytes; the kernel limit is ~104 — "+
				"use a shorter -state-dir or set -tis-socket explicitly: %w", path, len(path), err)
		}
		return nil, err
	}
	// The file mode *is* the authorization in v1 (see mintMux). Set it after
	// listen: the socket does not exist before that, and a window at 0755
	// would be a window in which anyone on the box could mint.
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
