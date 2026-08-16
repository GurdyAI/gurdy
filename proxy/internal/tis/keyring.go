package tis

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/keyfile"
	"github.com/golang-jwt/jwt/v5"
)

// RotateEvery is the deployment key's rotation interval. NFR-5 states ≤24h;
// this is that bound, not a tuning knob, so it is a constant.
//
// The overlap window is one full interval — the previous key is retired only
// when the next rotation displaces it. That makes "2-key overlap" (§5.2)
// literal: exactly two keys are ever live. It also has to exceed MaxTxnTTL,
// because a transaction token minted a moment before a rotation must still
// verify for its whole life; 24h against a 4h ceiling leaves six times the
// margin, and a build that narrows either is caught by TestOverlapOutlivesToken.
const RotateEvery = 24 * time.Hour

// keyring holds the signing key and its predecessor. Sign with current, verify
// with either — that is the entire mechanism (§5.2, NFR-5).
//
// Retiring the previous key at the *next* rotation rather than on a second
// timer is deliberate: two independent clocks deciding when a key dies is how
// a deployment ends up verifying a token with a key it has already forgotten,
// and the failure is silent — an assertion recorded `invalid` looks exactly
// like a forged one.
type keyring struct {
	current  *ecdsa.PrivateKey
	previous *ecdsa.PrivateKey // nil until the first rotation
	curKid   string
	prevKid  string
	rotated  time.Time
}

// KeyID names a public key: the first 8 bytes of the SHA-256 of its PKIX
// encoding, hex. Deliberately the identical construction the ledger has
// stamped on every header and batchsig since v0.8.5 — changing it would
// re-label keys that existing evidence already names, which is a migration,
// not a rename.
func KeyID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:8])
}

// prevPath is where the retiring key is kept. It must persist for the same
// reason the current key does (D2): a restart inside the overlap window that
// forgot the previous key would fail every outstanding token minted before the
// rotation, and NFR-3 turns that into a run of `invalid` assertions rather
// than an outage — evidence quietly degrading, which is worse than a stop.
func prevPath(keyPath string) string {
	ext := filepath.Ext(keyPath)
	return keyPath[:len(keyPath)-len(ext)] + ".prev" + ext
}

func loadKeyring(keyPath string) (*keyring, error) {
	cur, err := keyfile.LoadOrCreate(keyPath)
	if err != nil {
		return nil, err
	}
	kr := &keyring{current: cur, curKid: KeyID(&cur.PublicKey), rotated: time.Now()}
	prev, err := keyfile.Load(prevPath(keyPath))
	switch {
	case err == nil:
		kr.previous, kr.prevKid = prev, KeyID(&prev.PublicKey)
	case errors.Is(err, fs.ErrNotExist):
		// Never rotated. Not an error, and not something to fabricate a key for.
	default:
		return nil, fmt.Errorf("tis: previous key: %w", err)
	}
	return kr, nil
}

// byKid returns the key a token names. An unknown kid is refused rather than
// tried against every key: kid is a *hint* about which key to use, and the
// signature is what actually decides, so falling back on an unknown one buys
// nothing and hides a deployment that is verifying against the wrong keyring.
func (k *keyring) byKid(kid string) (*ecdsa.PublicKey, bool) {
	switch kid {
	case k.curKid:
		return &k.current.PublicKey, true
	case k.prevKid:
		if k.previous == nil {
			return nil, false
		}
		return &k.previous.PublicKey, true
	}
	return nil, false
}

// Rotate generates a new signing key, demotes the current one, and retires
// whatever was previous. Callable on a timer and from the admin API; both go
// through here so there is one implementation of the ordering below.
//
// Ordering is chosen for what a crash leaves behind. The new key is generated
// and written to a temp file before anything on disk moves, then the current
// key is renamed to .prev, then the new key is renamed into place. A crash
// between those two renames leaves no current key at all — and that is the
// benign outcome, because the next start generates a fresh current while .prev
// still holds the key every outstanding token was signed with. The alternative
// ordering loses the old key instead, which fails those tokens.
//
// In-memory state is updated only after both renames succeed. A keyring that
// has moved on from a key the disk still names is the same class of defect
// this repo keeps finding: state that outlives its own proof.
func (t *TIS) Rotate() error {
	next, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.keyPath != "" {
		if err := keyfile.Replace(prevPath(t.keyPath), t.ring.current); err != nil {
			return fmt.Errorf("tis: persist previous key: %w", err)
		}
		if err := keyfile.Replace(t.keyPath, next); err != nil {
			return fmt.Errorf("tis: persist new key: %w", err)
		}
	}
	t.ring.previous, t.ring.prevKid = t.ring.current, t.ring.curKid
	t.ring.current, t.ring.curKid = next, KeyID(&next.PublicKey)
	t.ring.rotated = time.Now()
	// Published so holders of derived state can notice. The gateway's
	// auto-minted token cache reads it: those tokens stay *valid* across a
	// rotation (the previous key still verifies them), but they would outlive
	// the key at the following one, and a cache keyed on expiry alone cannot
	// see that coming.
	t.keyGen.Add(1)
	return nil
}

// KeyGen counts rotations. It exists so a cache of minted tokens can tell that
// the signing key has moved without reaching into the keyring or being called
// back — one atomic load on a hot path, against a lock and a callback.
func (t *TIS) KeyGen() uint64 { return t.keyGen.Load() }

// JWK is one public key in JWKS form (RFC 7517/7518), which is what §5.2 means
// by "JWKS served on admin API for third-party verification".
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the public half of the keyring, current key first.
//
// Both keys are published throughout the overlap, and that is the point rather
// than an oversight: a verifier handed a token signed a minute before a
// rotation must still find its key, and a key that disappears the instant it
// stops signing makes every in-flight assertion unverifiable. It is retired
// from here when it is retired from the keyring, and not before.
func (t *TIS) JWKS() []JWK {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []JWK{jwkOf(&t.ring.current.PublicKey, t.ring.curKid)}
	if t.ring.previous != nil {
		out = append(out, jwkOf(&t.ring.previous.PublicKey, t.ring.prevKid))
	}
	return out
}

func jwkOf(pub *ecdsa.PublicKey, kid string) JWK {
	// Fixed-width, left-padded coordinates. FillBytes rather than Bytes():
	// Bytes() drops leading zero bytes, so roughly one key in 256 would publish
	// a 31-byte coordinate that strict JWK consumers reject — a bug that shows
	// up in well under 1% of deployments and never in a test that generates one
	// key.
	xb, yb := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return JWK{
		Kty: "EC", Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xb),
		Y:   base64.RawURLEncoding.EncodeToString(yb),
		Kid: kid, Use: "sig", Alg: "ES256",
	}
}

// RotateDue reports whether the interval has elapsed. The caller drives the
// clock so nothing here starts a goroutine a test would have to wait on.
func (t *TIS) RotateDue(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return now.Sub(t.ring.rotated) >= RotateEvery
}

// CurrentKid names the key signing right now — for the admin API's status and
// for tests that need to see a rotation happen.
func (t *TIS) CurrentKid() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ring.curKid
}

// candidates is the keyset for a token that names no key. Current first, so
// the common case verifies on the first try.
func (k *keyring) candidates() jwt.VerificationKeySet {
	keys := []jwt.VerificationKey{&k.current.PublicKey}
	if k.previous != nil {
		keys = append(keys, &k.previous.PublicKey)
	}
	return jwt.VerificationKeySet{Keys: keys}
}

// sign stamps every token with the kid of the key that signed it, in one place.
// Three call sites mint tokens and a kid missing from any one of them is
// invisible until that token outlives a rotation, so the header is not left to
// each of them to remember.
func (t *TIS) sign(claims jwt.Claims) (string, error) {
	t.mu.Lock()
	key, kid := t.ring.current, t.ring.curKid
	t.mu.Unlock()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	return tok.SignedString(key)
}
