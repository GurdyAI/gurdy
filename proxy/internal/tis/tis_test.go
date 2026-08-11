package tis

import (
	"errors"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTIS(t *testing.T) *TIS {
	t.Helper()
	ts, err := New("deploy-test", filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

var rootScope = Scope{
	Compartments:  []string{"proj-a", "proj-b"},
	ResourceTypes: []string{"file", "http"},
	Actions:       []string{"read", "write"},
	Purpose:       "ticket-123",
}

func TestMintVerifyRoundTrip(t *testing.T) {
	ts := newTIS(t)
	tok, err := ts.MintTxn("agent-root", "alice@example.com", rootScope, "starter-v0", 0)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ts.VerifyTxn(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "agent-root" || claims.Act != "alice@example.com" ||
		claims.TxnID == "" || claims.PolVer != "starter-v0" {
		t.Fatalf("claims mangled: %+v", claims)
	}
	if len(claims.Lineage) != 1 || claims.Lineage[0] != "agent-root" {
		t.Fatalf("root lineage: %v", claims.Lineage)
	}
}

func TestThreeDeepLineage(t *testing.T) {
	ts := newTIS(t)
	root, _ := ts.MintTxn("orchestrator", "alice", rootScope, "v0", 0)

	mid, err := ts.DeriveChildTxn(root, "researcher", Scope{
		Compartments: []string{"proj-a"}, ResourceTypes: []string{"file", "http"},
		Actions: []string{"read"}, Purpose: "ticket-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ts.DeriveChildTxn(mid, "fetcher", Scope{
		Compartments: []string{"proj-a"}, ResourceTypes: []string{"http"},
		Actions: []string{"read"}, Purpose: "ticket-123",
	})
	if err != nil {
		t.Fatal(err)
	}

	call, err := ts.DeriveCall(leaf, "http_get")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ts.VerifyCall(call)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"orchestrator", "researcher", "fetcher"}
	if len(claims.Lineage) != 3 {
		t.Fatalf("lineage depth: %v", claims.Lineage)
	}
	for i, w := range want {
		if claims.Lineage[i] != w {
			t.Fatalf("lineage[%d]=%s want %s", i, claims.Lineage[i], w)
		}
	}
	root2, _ := ts.VerifyTxn(root)
	if claims.ParentTxn != root2.TxnID {
		t.Fatal("call assertion lost txn identity across derivation chain")
	}
}

func TestScopeWideningRejected(t *testing.T) {
	ts := newTIS(t)
	root, _ := ts.MintTxn("orchestrator", "alice", rootScope, "v0", 0)
	cases := []Scope{
		{Compartments: []string{"proj-c"}, ResourceTypes: []string{"file"}, Actions: []string{"read"}, Purpose: "ticket-123"},   // new compartment
		{Compartments: []string{"proj-a"}, ResourceTypes: []string{"db"}, Actions: []string{"read"}, Purpose: "ticket-123"},     // new resource type
		{Compartments: []string{"proj-a"}, ResourceTypes: []string{"file"}, Actions: []string{"delete"}, Purpose: "ticket-123"}, // new action
		{Compartments: []string{"proj-a"}, ResourceTypes: []string{"file"}, Actions: []string{"read"}, Purpose: "other"},        // incomparable purpose
		{Compartments: []string{"*"}, ResourceTypes: []string{"file"}, Actions: []string{"read"}, Purpose: "ticket-123"},        // wildcard escalation
	}
	for i, c := range cases {
		if _, err := ts.DeriveChildTxn(root, "evil-child", c); !errors.Is(err, ErrScopeWidens) {
			t.Fatalf("case %d: widening accepted (err=%v)", i, err)
		}
	}
}

// Property: any child Derive accepts is subset-contained in the parent on
// every dimension; any child containing an element outside a non-top parent
// dimension is rejected (§8.2 "generated scope pairs must never widen").
func TestNarrowOnlyProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "b", "c", "d"}
	pick := func() []string {
		var out []string
		for _, s := range alphabet {
			if rng.Intn(2) == 0 {
				out = append(out, s)
			}
		}
		return out
	}
	contained := func(child, parent []string) bool {
		for _, c := range child {
			ok := false
			for _, p := range parent {
				if c == p {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	for i := 0; i < 5000; i++ {
		parent := Scope{Compartments: pick(), ResourceTypes: pick(), Actions: pick(), Purpose: "p"}
		child := Scope{Compartments: pick(), ResourceTypes: pick(), Actions: pick(), Purpose: "p"}
		got := Narrows(child, parent)
		want := contained(child.Compartments, parent.Compartments) &&
			contained(child.ResourceTypes, parent.ResourceTypes) &&
			contained(child.Actions, parent.Actions)
		if got != want {
			t.Fatalf("iter %d: Narrows=%v want %v\nchild=%+v\nparent=%+v", i, got, want, child, parent)
		}
	}
}

func TestReplayRejected(t *testing.T) {
	ts := newTIS(t)
	txn, _ := ts.MintTxn("agent", "alice", rootScope, "v0", 0)
	call, _ := ts.DeriveCall(txn, "read_file")
	if _, err := ts.VerifyCall(call); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := ts.VerifyCall(call); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay accepted (err=%v)", err)
	}
}

// Cross-replica binding (§5.2): an assertion minted on replica A fails on
// replica B via audience mismatch alone — no shared replay state needed.
//
// Both instances share one deployment and one persisted key here, which is the
// real cluster shape and the case that matters: with the key now durable, a
// signature check can no longer tell the replicas apart, so the audience is
// the only thing left doing this job. The same construction is a restart —
// B is what comes back up — so this covers cross-restart replay too.
func TestCrossReplicaReplayRejected(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	a, err := New("deploy-test", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("deploy-test", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	txn, _ := a.MintTxn("agent", "alice", rootScope, "v0", 0)
	call, _ := a.DeriveCall(txn, "read_file")
	if _, err := b.VerifyCall(call); !errors.Is(err, ErrAudience) {
		t.Fatalf("cross-replica assertion accepted (err=%v)", err)
	}
	// The txn token, which carries no audience, must still verify on B —
	// that portability is the whole reason the key persists (D2).
	if _, err := b.VerifyTxn(txn); err != nil {
		t.Fatalf("txn token does not survive to the other instance: %v", err)
	}
}

func TestExpiredTxnRejected(t *testing.T) {
	ts := newTIS(t)
	expired := TxnClaims{
		TxnID: "01OLD", Scope: rootScope, Lineage: []string{"agent"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, expired).SignedString(ts.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.VerifyTxn(tok); err == nil {
		t.Fatal("expired txn accepted")
	}
	if _, err := ts.DeriveCall(tok, "read_file"); err == nil {
		t.Fatal("derive from expired txn accepted")
	}
}

// BenchmarkDeriveVerifyCall is the per-call identity hot path (§8.2 microbench
// gate: derive <1ms; mint is per-task and amortized, excluded from this budget).
func BenchmarkDeriveVerifyCall(b *testing.B) {
	ts, err := New("deploy-bench", filepath.Join(b.TempDir(), "key.pem"))
	if err != nil {
		b.Fatal(err)
	}
	txn, err := ts.MintTxn("agent", "alice", rootScope, "v0", MaxTxnTTL)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		call, err := ts.DeriveCall(txn, "read_file")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ts.VerifyCall(call); err != nil {
			b.Fatal(err)
		}
	}
}

func TestChildNeverOutlivesParent(t *testing.T) {
	ts := newTIS(t)
	root, _ := ts.MintTxn("orchestrator", "alice", rootScope, "v0", time.Minute)
	child, err := ts.DeriveChildTxn(root, "sub", rootScope)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := ts.VerifyTxn(root)
	cc, _ := ts.VerifyTxn(child)
	if cc.ExpiresAt.After(rc.ExpiresAt.Time) {
		t.Fatal("child txn outlives parent")
	}
}

// The deployment key must survive a restart (D2, §5.2). An ephemeral key
// invalidates every outstanding txn token on a bounce and leaves replicas of
// one deployment unable to verify each other's assertions.
func TestKeyPersistsAcrossRestart(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	first, err := New("deploy-test", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := first.MintTxn("agent", "human", Scope{Compartments: []string{"c1"}}, "v0", 0)
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := New("deploy-test", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.VerifyTxn(tok); err != nil {
		t.Fatalf("token minted before restart no longer verifies: %v", err)
	}

	// Guard the other direction: a token really is key-bound, so the test
	// above cannot pass by the signature going unchecked.
	stranger, err := New("deploy-test", filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.VerifyTxn(tok); err == nil {
		t.Fatal("token verified under a different deployment key")
	}
}
