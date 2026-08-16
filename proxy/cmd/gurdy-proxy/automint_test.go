package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// autoMint is on the path of every call that arrives without a Gurdy-Txn — the
// no-SDK path, and therefore the common one (D12). These pin the three
// properties that make caching the expiry safe rather than merely fast.

func newAutoGateway(t testing.TB) *gateway {
	t.Helper()
	h := newHarness(t)
	return newGateway(h.store, h.tis, h.led, "test", slogTo(&syncBuffer{}))
}

// A cached token is handed back unchanged. If this fails the proxy is minting
// a fresh transaction per call, which is not just slow: §4.3 auto-mints per
// *task*, so a token per call would make every call its own transaction and
// destroy the grouping the ledger's provenance depends on.
func TestAutoMintReusesCachedToken(t *testing.T) {
	g := newAutoGateway(t)
	first := g.autoMint("host:127.0.0.1")
	if first == "" {
		t.Fatal("autoMint returned empty on first call")
	}
	if second := g.autoMint("host:127.0.0.1"); second != first {
		t.Errorf("token not reused:\n first=%s\nsecond=%s", first, second)
	}
	if _, err := g.tis.VerifyTxn(first); err != nil {
		t.Errorf("cached token does not verify: %v", err)
	}
	if other := g.autoMint("host:10.0.0.1"); other == first {
		t.Error("two different principals share one token — the cache is not keyed by principal")
	}
}

// The cached expiry is held strictly *earlier* than the token's real expiry.
// This is the property that protects evidence rather than latency: a token
// handed out microseconds before it dies makes DeriveCall fail, and that call
// is recorded with empty txn fields plus an identity gap (§5.5). Without the
// margin the failure is a race nobody can reproduce on demand.
func TestAutoMintRenewsBeforeRealExpiry(t *testing.T) {
	g := newAutoGateway(t)
	tok := g.autoMint("host:127.0.0.1")

	claims, err := g.tis.VerifyTxn(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	g.mu.RLock()
	ent := g.autoTxn["host:127.0.0.1"]
	g.mu.RUnlock()

	real := claims.ExpiresAt.Time
	if !ent.exp.Before(real) {
		t.Errorf("cached expiry %v is not before the token's own %v — no renewal margin", ent.exp, real)
	}
	if got := real.Sub(ent.exp); got != autoRenew {
		t.Errorf("renewal margin = %v, want %v", got, autoRenew)
	}
}

// Past the cached expiry the token is replaced rather than handed out again.
func TestAutoMintReplacesExpiredToken(t *testing.T) {
	g := newAutoGateway(t)
	first := g.autoMint("host:127.0.0.1")

	g.mu.Lock()
	ent := g.autoTxn["host:127.0.0.1"]
	ent.exp = time.Now().Add(-time.Second)
	g.autoTxn["host:127.0.0.1"] = ent
	g.mu.Unlock()

	if second := g.autoMint("host:127.0.0.1"); second == first {
		t.Error("expired token handed out again")
	}
}

// Minting sweeps principals whose tokens have expired, so the map is bounded
// by principals currently active rather than by every client IP ever seen —
// half of D6, taken because minting is the one place an O(n) pass is affordable.
func TestAutoMintEvictsExpiredPrincipals(t *testing.T) {
	g := newAutoGateway(t)
	g.mu.Lock()
	for _, k := range []string{"host:1.1.1.1", "host:2.2.2.2", "host:3.3.3.3"} {
		g.autoTxn[k] = autoTok{tok: "stale", exp: time.Now().Add(-time.Hour)}
	}
	g.autoTxn["host:live"] = autoTok{tok: "live", exp: time.Now().Add(time.Hour)}
	g.mu.Unlock()

	g.autoMint("host:new") // any mint triggers the sweep

	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, k := range []string{"host:1.1.1.1", "host:2.2.2.2", "host:3.3.3.3"} {
		if _, ok := g.autoTxn[k]; ok {
			t.Errorf("%s survived the sweep", k)
		}
	}
	if _, ok := g.autoTxn["host:live"]; !ok {
		t.Error("unexpired principal was swept — the sweep is evicting live entries")
	}
}

// Concurrent first-sight callers on one principal converge on one token.
// Without the re-check under the write lock they each mint their own, and the
// losers walk away holding a token the map no longer names — so two calls in
// the same task land in the ledger under two transactions.
//
// Rounds, and a fresh principal per round, because one round does not reliably
// race: the first goroutine can finish minting before the rest are scheduled,
// after which they all hit the fast path and agree for the wrong reason. Each
// round is an independent first-sight collision, and the mutation that removes
// the re-check has to survive every one of them to go unnoticed. Verified by
// doing exactly that — at one round it passed, across these it does not.
func TestAutoMintConcurrentSinglePrincipal(t *testing.T) {
	g := newAutoGateway(t)
	const rounds, n = 64, 32

	for r := range rounds {
		principal := fmt.Sprintf("host:10.0.0.%d", r)
		var wg sync.WaitGroup
		toks := make([]string, n)
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // release together, onto an empty cache entry
				toks[i] = g.autoMint(principal)
			}()
		}
		close(start)
		wg.Wait()

		for i, tok := range toks {
			if tok == "" {
				t.Fatalf("round %d goroutine %d: empty token", r, i)
			}
			if tok != toks[0] {
				t.Fatalf("round %d goroutine %d minted a second token for one principal", r, i)
			}
		}
		g.mu.RLock()
		ent := g.autoTxn[principal]
		g.mu.RUnlock()
		if ent.tok != toks[0] {
			t.Fatalf("round %d: the cached token is not the one callers were given", r)
		}
	}
}
