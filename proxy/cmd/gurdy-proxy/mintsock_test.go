package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mintClient serves the sideband API on a real Unix socket and returns a client
// speaking to it, so the tests exercise the transport the SDK will use rather
// than the handler in isolation.
func mintClient(t *testing.T, h *harness) (*http.Client, string) {
	t.Helper()
	// A short dir, not t.TempDir(): that path encodes the test name, and the
	// kernel caps socket paths at ~104 bytes — the same limit a deep
	// -state-dir hits in the field.
	dir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "tis.sock")
	l, err := listenMint(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mintMux(h.tis, h.store)}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}, path
}

func post(t *testing.T, c *http.Client, route, body string) (int, map[string]string) {
	t.Helper()
	resp, err := c.Post("http://tis"+route, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]string
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// D1: an SDK can obtain a transaction credential at task start, and a call
// carrying it produces a record with the *asserted* identity filled in —
// while the observed principal stays whatever the proxy saw (§5.2, §5.5).
func TestMintSocketIssuesUsableTxn(t *testing.T) {
	h := newHarness(t)
	c, _ := mintClient(t, h)

	code, out := post(t, c, "/mint", `{"agent":"orchestrator","human_actor":"alice@example.com",
		"scope":{"compartments":["*"],"resource_types":["*"],"actions":["*"],"purpose":"ticket-9"}}`)
	if code != http.StatusOK || out["txn"] == "" {
		t.Fatalf("mint failed: %d %v", code, out)
	}

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(benignCall))
	req.Header.Set(TxnHeader, out["txn"])
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	rec := h.lastDecision(t)
	if rec["assertion_status"] != "valid" {
		t.Fatalf("a minted credential did not verify on the call path: %v", rec)
	}
	if rec["asserted_principal"] != "orchestrator" {
		t.Errorf("asserted principal missing: %v", rec)
	}
	// The claim enriches the record; it must not become the identity policy
	// evaluated on — that is the whole point of the split (§5.5).
	if !strings.HasPrefix(rec["principal"].(string), "svc:") {
		t.Errorf("asserted identity displaced the observed principal: %v", rec)
	}
}

// Narrow-only is enforced at the API boundary exactly as it is internally: a
// sub-agent that could ask for more scope than its parent is the confused
// deputy this algebra exists to prevent (§5.2).
func TestMintSocketDeriveIsNarrowOnly(t *testing.T) {
	h := newHarness(t)
	c, _ := mintClient(t, h)

	_, parent := post(t, c, "/mint", `{"agent":"orchestrator",
		"scope":{"compartments":["billing"],"resource_types":["invoice"],"actions":["read"],"purpose":"audit"}}`)

	code, out := post(t, c, "/derive", `{"parent":"`+parent["txn"]+`","agent":"child",
		"scope":{"compartments":["billing"],"resource_types":["invoice"],"actions":["read"],"purpose":"audit"}}`)
	if code != http.StatusOK || out["txn"] == "" {
		t.Fatalf("equal scope should derive: %d %v", code, out)
	}
	claims, err := h.tis.VerifyTxn(out["txn"])
	if err != nil {
		t.Fatalf("derived token does not verify: %v", err)
	}
	if len(claims.Lineage) != 2 || claims.Lineage[1] != "child" {
		t.Errorf("lineage did not extend: %v", claims.Lineage)
	}

	for _, widening := range []string{
		`{"compartments":["*"],"resource_types":["invoice"],"actions":["read"],"purpose":"audit"}`,
		`{"compartments":["billing"],"resource_types":["invoice"],"actions":["read","write"],"purpose":"audit"}`,
		`{"compartments":["billing"],"resource_types":["invoice"],"actions":["read"],"purpose":"*"}`,
		`{"compartments":["hr"],"resource_types":["invoice"],"actions":["read"],"purpose":"audit"}`,
	} {
		code, out := post(t, c, "/derive", `{"parent":"`+parent["txn"]+`","agent":"child","scope":`+widening+`}`)
		if code == http.StatusOK {
			t.Errorf("scope widening accepted: %s -> %v", widening, out)
		}
	}
}

// The surface is exactly two routes. /derive-call is absent on purpose: the
// proxy derives per-call assertions itself, and exposing it would let an agent
// choose the tool its own assertion names (§5.9).
func TestMintSocketSurfaceIsMinimal(t *testing.T) {
	h := newHarness(t)
	c, _ := mintClient(t, h)

	for _, route := range []string{"/derive-call", "/policy/reload", "/health", "/"} {
		if code, _ := post(t, c, route, `{}`); code != http.StatusNotFound {
			t.Errorf("%s answered %d — the mint socket must not carry it", route, code)
		}
	}
	resp, err := c.Get("http://tis/mint")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /mint = %d, want 405", resp.StatusCode)
	}
	if code, _ := post(t, c, "/mint", `{"agent":`); code != http.StatusBadRequest {
		t.Errorf("malformed mint request = %d, want 400", code)
	}
	if code, _ := post(t, c, "/mint", `{"human_actor":"alice"}`); code != http.StatusBadRequest {
		t.Errorf("mint with no agent = %d, want 400", code)
	}
}

// The file mode is the access control in v1, so it is a control and not a
// detail: anything wider means any local account can mint credentials in this
// deployment's name.
func TestMintSocketIsOwnerOnly(t *testing.T) {
	h := newHarness(t)
	_, path := mintClient(t, h)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %o, want 600 — anyone on the box could mint", perm)
	}
}

// Socket lifecycle, all three cases. The middle one is the important one: a
// typo in -tis-socket must not delete the file it happens to name.
func TestSocketLifecycle(t *testing.T) {
	shortDir := func(t *testing.T) string {
		t.Helper()
		d, err := os.MkdirTemp("", "gs") // socket paths cap at ~104 bytes
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(d) })
		return d
	}

	t.Run("stale socket reclaimed", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "tis.sock")
		l, err := listenMint(path)
		if err != nil {
			t.Fatal(err)
		}
		l.(*net.UnixListener).SetUnlinkOnClose(false) // what a crash leaves behind
		l.Close()
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("fixture wrong — no leftover socket: %v", err)
		}
		l2, err := listenMint(path)
		if err != nil {
			t.Fatalf("a crashed proxy's socket blocks restart: %v", err)
		}
		l2.Close()
	})

	t.Run("non-socket file refused, not deleted", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "important.txt")
		if err := os.WriteFile(path, []byte("someone's work"), 0o600); err != nil {
			t.Fatal(err)
		}
		if l, err := listenMint(path); err == nil {
			l.Close()
			t.Fatal("bound over a regular file")
		}
		b, err := os.ReadFile(path)
		if err != nil || string(b) != "someone's work" {
			t.Fatalf("a mistyped socket path deleted a real file: %v %q", err, b)
		}
	})

	t.Run("live socket refused", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "tis.sock")
		l, err := listenMint(path)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go http.Serve(l, http.NotFoundHandler())
		if l2, err := listenMint(path); err == nil {
			l2.Close()
			t.Fatal("a second proxy took over a live socket — two keys, one deployment")
		}
	})

	t.Run("parent directory is owner-only", func(t *testing.T) {
		dir := shortDir(t)
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		l, err := listenMint(filepath.Join(dir, "tis.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		fi, _ := os.Stat(dir)
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Fatalf("state dir mode %o — it holds signing keys and gates the socket", perm)
		}
	})
}

// A token with no subject verifies as valid and attributes nobody: it would
// produce assertion_status=valid with an empty asserted_principal, and an
// empty lineage element hides a hop in a chain that still looks complete.
func TestMintRejectsEmptyAgent(t *testing.T) {
	h := newHarness(t)
	c, _ := mintClient(t, h)

	if code, _ := post(t, c, "/mint", `{"agent":"  "}`); code != http.StatusBadRequest {
		t.Errorf("whitespace agent minted: %d", code)
	}
	_, parent := post(t, c, "/mint", `{"agent":"orchestrator","scope":{"compartments":["*"],"resource_types":["*"],"actions":["*"],"purpose":"*"}}`)
	for _, agent := range []string{`""`, `"   "`} {
		code, out := post(t, c, "/derive",
			`{"parent":"`+parent["txn"]+`","agent":`+agent+`,"scope":{"compartments":["*"],"resource_types":["*"],"actions":["*"],"purpose":"*"}}`)
		if code == http.StatusOK {
			t.Errorf("derived an anonymous child (agent=%s): %v", agent, out)
		}
	}
}

// Everything above exercises listenMint/mintMux directly, so the wiring in
// main() — the default path, the flag, the off switch, cleanup on exit — could
// be deleted with every test still green. This one runs the real binary.
func TestMintSocketWiredIntoTheBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	dir, err := os.MkdirTemp("", "gs") // socket paths cap at ~104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "gurdy-proxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	run := func(t *testing.T, extra ...string) (state string, stop func()) {
		t.Helper()
		state, err := os.MkdirTemp(dir, "st")
		if err != nil {
			t.Fatal(err)
		}
		args := append([]string{"-stdio", "-ledger-dir", filepath.Join(state, "l"),
			"-state-dir", state}, extra...)
		cmd := exec.Command(bin, append(args, "--", "cat")...)
		// Stdin must stay open: the shim treats EOF as "the task is over" and
		// shuts down — correctly removing its socket on the way out, which is
		// indistinguishable from never having created one.
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return state, func() { in.Close(); cmd.Process.Kill(); cmd.Wait() }
	}

	// Default: the socket appears at <state-dir>/tis.sock and mints.
	state, stop := run(t)
	sock := filepath.Join(state, "tis.sock")
	var appeared bool
	for i := 0; i < 100 && !appeared; i++ {
		_, err := os.Stat(sock)
		appeared = err == nil
		time.Sleep(50 * time.Millisecond)
	}
	if !appeared {
		stop()
		t.Fatal("no socket at the documented default path")
	}
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	if code, out := post(t, c, "/mint", `{"agent":"sdk"}`); code != http.StatusOK || out["txn"] == "" {
		stop()
		t.Fatalf("mint over the real binary's socket: %d %v", code, out)
	}
	stop()

	// -tis-socket off: no socket at all. An operator who turns it off and gets
	// one anyway has been told something false about their attack surface.
	state, stop = run(t, "-tis-socket", "off")
	time.Sleep(500 * time.Millisecond)
	stop()
	if _, err := os.Stat(filepath.Join(state, "tis.sock")); err == nil {
		t.Fatal("-tis-socket off still opened a socket")
	}
}
