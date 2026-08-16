package tis

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mintOne(t *testing.T, ts *TIS) string {
	t.Helper()
	tok, err := ts.MintTxn("agent", "", rootScope, "v0", 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The point of a 2-key overlap: a token minted a moment before a rotation must
// keep verifying for its whole life. Without this, every rotation is an outage
// for outstanding transactions — recorded, under NFR-3, as a run of `invalid`
// assertions indistinguishable from forgeries rather than as a visible failure.
func TestRotationKeepsOutstandingTokensValid(t *testing.T) {
	ts := newTIS(t)
	before := mintOne(t, ts)
	oldKid := ts.CurrentKid()

	if err := ts.Rotate(); err != nil {
		t.Fatal(err)
	}
	if ts.CurrentKid() == oldKid {
		t.Fatal("rotation did not change the signing key")
	}
	if _, err := ts.VerifyTxn(before); err != nil {
		t.Errorf("token minted before rotation no longer verifies: %v", err)
	}
	if _, err := ts.VerifyTxn(mintOne(t, ts)); err != nil {
		t.Errorf("token minted after rotation does not verify: %v", err)
	}
	// And derivation, which is the operation the proxy actually performs on a
	// token it received — verifying but failing to derive would still blank the
	// assertion out of the record.
	if _, err := ts.DeriveCall(before, "read_file"); err != nil {
		t.Errorf("derive from a pre-rotation token failed: %v", err)
	}
}

// Two keys, not a growing keyring. The overlap has to end, or a compromised key
// stays able to mint credentials the deployment accepts for as long as the
// process lives — which is the failure rotation exists to bound.
func TestSecondRotationRetiresTheOldestKey(t *testing.T) {
	ts := newTIS(t)
	oldest := mintOne(t, ts)

	if err := ts.Rotate(); err != nil { // oldest -> previous, still valid
		t.Fatal(err)
	}
	if _, err := ts.VerifyTxn(oldest); err != nil {
		t.Fatalf("first rotation should keep the token valid: %v", err)
	}
	if err := ts.Rotate(); err != nil { // oldest -> retired
		t.Fatal(err)
	}
	if _, err := ts.VerifyTxn(oldest); err == nil {
		t.Error("a token signed by a key retired two rotations ago still verifies — the overlap is unbounded")
	}
	if n := len(ts.JWKS()); n != 2 {
		t.Errorf("JWKS publishes %d keys, want exactly 2 (current + previous)", n)
	}
}

// The overlap window must outlive the longest token anyone can mint, or a
// token can be born already doomed: valid when issued, unverifiable before its
// own expiry. This is a relationship between two constants, and the test is
// here so narrowing either one fails loudly rather than in a deployment.
func TestOverlapOutlivesToken(t *testing.T) {
	if RotateEvery <= MaxTxnTTL {
		t.Fatalf("rotation interval %v does not exceed the maximum token TTL %v: a token minted "+
			"just before a rotation would outlive the key that signed it", RotateEvery, MaxTxnTTL)
	}
	if RotateEvery > 24*time.Hour {
		t.Fatalf("rotation interval %v exceeds NFR-5's ≤24h", RotateEvery)
	}
}

// kid is a hint about which key to try; the signature is what decides. A token
// naming a key this deployment does not have is refused rather than tried
// against the keyring, so a proxy pointed at the wrong state directory fails
// visibly instead of appearing to work.
func TestUnknownKidIsRefused(t *testing.T) {
	ts := newTIS(t)
	claims := TxnClaims{
		TxnID: "01TEST", Scope: rootScope, Lineage: []string{"agent"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = "deadbeefdeadbeef"
	ts.mu.Lock()
	signed, err := tok.SignedString(ts.ring.current) // OUR key, someone else's kid
	ts.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.VerifyTxn(signed); err == nil {
		t.Error("a token naming an unknown key was accepted")
	}
}

// The adversarial case the kid-less fallback must not open: trying both keys
// is a convenience for tokens from an older build, never a way in. A foreign
// signature fails whether or not it names a key.
func TestForeignKeyRejectedWithAndWithoutKid(t *testing.T) {
	ts := newTIS(t)
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := TxnClaims{
		TxnID: "01EVIL", Scope: rootScope, Lineage: []string{"agent"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	for _, tc := range []struct {
		name string
		kid  any
	}{
		{"no kid at all", nil},
		{"our current kid", ts.CurrentKid()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			if tc.kid != nil {
				tok.Header["kid"] = tc.kid
			}
			signed, err := tok.SignedString(attacker)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ts.VerifyTxn(signed); err == nil {
				t.Error("a token signed by a foreign key was accepted")
			}
		})
	}
	// Same again after a rotation, when there are two keys to try rather than one.
	if err := ts.Rotate(); err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, _ := tok.SignedString(attacker)
	if _, err := ts.VerifyTxn(signed); err == nil {
		t.Error("a foreign token was accepted once the keyring held two keys")
	}
}

// The previous key must survive a restart. Without persistence, a bounce inside
// the overlap window fails every token minted before the rotation — the same
// hazard D2 fixed for the current key, reintroduced one key over.
func TestPreviousKeySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	ts, err := New("deploy-test", path)
	if err != nil {
		t.Fatal(err)
	}
	before := mintOne(t, ts)
	if err := ts.Rotate(); err != nil {
		t.Fatal(err)
	}
	afterRotate := mintOne(t, ts)

	restarted, err := New("deploy-test", path) // same state dir, new process
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.VerifyTxn(before); err != nil {
		t.Errorf("pre-rotation token lost across restart: %v", err)
	}
	if _, err := restarted.VerifyTxn(afterRotate); err != nil {
		t.Errorf("post-rotation token lost across restart: %v", err)
	}
	if n := len(restarted.JWKS()); n != 2 {
		t.Errorf("restarted keyring publishes %d keys, want 2", n)
	}
}

// JWKS is served to third parties (§5.2), so what it must never contain is as
// load-bearing as what it must.
func TestJWKSIsPublicAndWellFormed(t *testing.T) {
	ts := newTIS(t)
	if err := ts.Rotate(); err != nil {
		t.Fatal(err)
	}
	keys := ts.JWKS()
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if keys[0].Kid != ts.CurrentKid() {
		t.Errorf("current key is not first: got %s, want %s", keys[0].Kid, ts.CurrentKid())
	}
	if keys[0].Kid == keys[1].Kid {
		t.Error("both entries name the same key")
	}
	for _, k := range keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
			t.Errorf("malformed JWK: %+v", k)
		}
		// Fixed 32-byte coordinates. big.Int.Bytes() would trim a leading zero
		// on roughly one key in 256 and produce a 31-byte value that strict
		// consumers reject — a defect that never shows up in a test generating
		// one key, so it is asserted rather than hoped for.
		for name, v := range map[string]string{"x": k.X, "y": k.Y} {
			raw, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				t.Errorf("%s is not base64url: %v", name, err)
				continue
			}
			if len(raw) != 32 {
				t.Errorf("%s is %d bytes, want exactly 32", name, len(raw))
			}
		}
	}
}

// Nothing on the private side may reach the key files' neighbours or the JWKS
// payload. The keyring writes 0600 and publishes coordinates only.
func TestRotationPersistsPrivateKeysUnreadableByOthers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	ts, err := New("deploy-test", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Rotate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, prevPath(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is mode %o — readable beyond its owner", p, perm)
		}
	}
	if got := prevPath("/state/tis-key.pem"); got != "/state/tis-key.prev.pem" {
		t.Errorf("prevPath = %s", got)
	}
}

// jwkOf must left-pad, and the case that proves it cannot be waited for: a
// P-256 coordinate has a leading zero byte about once in 256 keys, so a test
// generating one key passes ~99.6% of the time whether or not the padding is
// there. Random runs are not a gate at that rate — 20 of them still miss it a
// quarter of the time — so the key is searched for instead.
func TestJWKCoordinatesArePaddedNotTrimmed(t *testing.T) {
	var short *ecdsa.PrivateKey
	for i := 0; i < 4000 && short == nil; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// A coordinate needing ≤248 bits is one big.Int.Bytes() would return
		// in fewer than 32 bytes.
		if k.PublicKey.X.BitLen() <= 248 || k.PublicKey.Y.BitLen() <= 248 {
			short = k
		}
	}
	if short == nil {
		t.Skip("no short-coordinate key found in 4000 tries — vanishingly unlikely, not a failure")
	}
	jwk := jwkOf(&short.PublicKey, "test")
	for name, v := range map[string]string{"x": jwk.X, "y": jwk.Y} {
		raw, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(raw) != 32 {
			t.Errorf("%s is %d bytes for a key with a short coordinate — the encoder trims "+
				"instead of left-padding, and strict JWK consumers reject that", name, len(raw))
		}
	}
}
