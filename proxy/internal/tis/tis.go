// Package tis is the Transaction Identity Service (§5.2): ephemeral,
// transaction-scoped ES256 credentials with a narrow-only provenance chain.
// No network calls on the mint path (NFR-5).
package tis

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
)

const (
	DefaultTxnTTL = 15 * time.Minute
	MaxTxnTTL     = 4 * time.Hour
	CallTTL       = 60 * time.Second
)

var (
	ErrScopeWidens = errors.New("tis: child scope is not a provable narrowing of parent scope")
	ErrReplay      = errors.New("tis: call assertion replayed")
	ErrAudience    = errors.New("tis: call assertion bound to a different target")
	ErrNoAgent     = errors.New("tis: agent is required — a token with no subject attributes nothing")
)

// TxnClaims is the transaction token payload.
type TxnClaims struct {
	TxnID   string   `json:"txn_id"`
	Act     string   `json:"act,omitempty"` // initiating human principal
	Scope   Scope    `json:"scope"`
	Lineage []string `json:"lineage"` // ordered agent chain, root first
	PolVer  string   `json:"pol_ver"`
	jwt.RegisteredClaims
}

// CallClaims is the per-call derived assertion payload.
type CallClaims struct {
	ParentTxn string   `json:"parent_txn"`
	Act       string   `json:"act,omitempty"`
	Scope     Scope    `json:"scope"`
	Lineage   []string `json:"lineage"`
	Tool      string   `json:"tool"`
	jwt.RegisteredClaims
}

// TIS mints and validates credentials for one deployment.
type TIS struct {
	aud     string // audience for call assertions (cross-replica/restart binding)
	keyPath string // "" for an in-memory keyring (tests); rotation then persists nothing
	keyGen  atomic.Uint64

	mu         sync.Mutex
	ring       *keyring             // current + previous signing keys (NFR-5 2-key overlap)
	replay     map[string]time.Time // jti -> expiry; same-instance replay defense
	sinceSweep int
}

// New loads the deployment's ES256 keypair from keyPath, creating it on first
// use. It must persist: an ephemeral key invalidates every outstanding txn
// token on restart and leaves replicas unable to verify each other (§5.2
// install-time per-deployment key; NFR-5 KMS-wrap and rotation come later).
//
// The call-assertion audience is deployID plus a per-instance nonce. The jti
// replay cache is in-memory and same-instance, so an assertion replayed at
// another replica — or here after a restart — was previously stopped by the
// key being ephemeral. Persisting the key removes that, and the audience has
// to carry the instance or the replay defense goes with it. Txn tokens carry
// no audience and still verify deployment-wide, which is the point of D2.
func New(deployID, keyPath string) (*TIS, error) {
	ring, err := loadKeyring(keyPath)
	if err != nil {
		return nil, err
	}
	return &TIS{
		ring:    ring,
		keyPath: keyPath,
		aud:     deployID + "#" + ulid.Make().String(),
		replay:  map[string]time.Time{},
	}, nil
}

// Instance identifies this process: the deployment ID plus the per-instance
// nonce that binds call assertions. The ledger header carries it (§5.5
// v0.8.5) so a record and an assertion can be traced to the same process —
// which is what makes a cross-replica replay visible in the evidence rather
// than only at verification time.
func (t *TIS) Instance() string { return t.aud }

// MintTxn mints a root transaction token at task initiation (FR-3).
// An empty agent is refused: the subject becomes asserted_principal, and a
// token with no subject verifies as valid while naming nobody — an assertion
// that passes every check and attributes nothing is worse than none.
func (t *TIS) MintTxn(agent, humanActor string, scope Scope, polVer string, ttl time.Duration) (string, error) {
	if strings.TrimSpace(agent) == "" {
		return "", ErrNoAgent
	}
	if ttl <= 0 {
		ttl = DefaultTxnTTL
	}
	if ttl > MaxTxnTTL {
		ttl = MaxTxnTTL
	}
	now := time.Now()
	claims := TxnClaims{
		TxnID:   ulid.Make().String(),
		Act:     humanActor,
		Scope:   scope,
		Lineage: []string{agent},
		PolVer:  polVer,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   agent,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return t.sign(claims)
}

// DeriveChildTxn mints a sub-agent transaction from a live parent token.
// Lineage extends; scope may only narrow — incomparable pairs are REJECTED,
// never silently allowed (§5.2 normative).
func (t *TIS) DeriveChildTxn(parentToken, childAgent string, childScope Scope) (string, error) {
	if strings.TrimSpace(childAgent) == "" {
		// Same reason as MintTxn, plus one: an empty lineage element would
		// leave a chain that looks complete and hides a hop.
		return "", ErrNoAgent
	}
	parent, err := t.VerifyTxn(parentToken)
	if err != nil {
		return "", fmt.Errorf("verify parent: %w", err)
	}
	if !Narrows(childScope, parent.Scope) {
		return "", ErrScopeWidens
	}
	now := time.Now()
	claims := TxnClaims{
		TxnID:   parent.TxnID, // same transaction, deeper lineage
		Act:     parent.Act,
		Scope:   childScope,
		Lineage: append(append([]string{}, parent.Lineage...), childAgent),
		PolVer:  parent.PolVer,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   childAgent,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: parent.ExpiresAt, // child never outlives parent
		},
	}
	return t.sign(claims)
}

// DeriveCall derives a single-use per-call assertion from a live txn token (FR-3).
func (t *TIS) DeriveCall(txnToken, tool string) (string, error) {
	txn, err := t.VerifyTxn(txnToken)
	if err != nil {
		return "", fmt.Errorf("verify txn: %w", err)
	}
	now := time.Now()
	exp := now.Add(CallTTL)
	if txn.ExpiresAt.Before(exp) {
		exp = txn.ExpiresAt.Time
	}
	claims := CallClaims{
		ParentTxn: txn.TxnID,
		Act:       txn.Act,
		Scope:     txn.Scope,
		Lineage:   txn.Lineage,
		Tool:      tool,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        ulid.Make().String(),
			Subject:   txn.Subject,
			Audience:  jwt.ClaimStrings{t.aud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	return t.sign(claims)
}

// VerifyTxn validates signature and expiry of a transaction token.
func (t *TIS) VerifyTxn(token string) (*TxnClaims, error) {
	var claims TxnClaims
	if err := t.parse(token, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// VerifyCall validates a call assertion: signature, expiry, audience binding
// (a replayed assertion against a different replica fails here with no shared
// state — §5.2), and single-use jti (same-instance replay cache).
func (t *TIS) VerifyCall(token string) (*CallClaims, error) {
	var claims CallClaims
	if err := t.parse(token, &claims); err != nil {
		return nil, err
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != t.aud {
		return nil, ErrAudience
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if _, seen := t.replay[claims.ID]; seen {
		return nil, ErrReplay
	}
	t.replay[claims.ID] = claims.ExpiresAt.Time
	// Amortized sweep: expired jtis linger ≤1024 inserts, bounding both map
	// growth and per-verify cost (NFR-2).
	t.sinceSweep++
	if t.sinceSweep >= 1024 {
		t.sinceSweep = 0
		for jti, exp := range t.replay {
			if exp.Before(now) {
				delete(t.replay, jti)
			}
		}
	}
	return &claims, nil
}

// parse selects the verifying key by the token's `kid` (NFR-5: a signature
// that cannot say which key made it makes rotation unbuildable — §5.5 landed
// the same field on the ledger for this reason).
//
// A token with no kid is tried against both keys rather than refused. It is
// not a weakening: an attacker gains nothing by omitting the hint, because the
// signature still has to be one of ours. What it buys is the upgrade — tokens
// minted by a pre-rotation build stay verifiable for their remaining life
// (≤MaxTxnTTL), instead of a fleet-wide run of `invalid` assertions after a
// deploy. NFR-3 means those would degrade the evidence silently rather than
// break traffic, which is the worse failure of the two.
func (t *TIS) parse(token string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(token, claims,
		func(tok *jwt.Token) (any, error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			kid, _ := tok.Header["kid"].(string)
			if kid == "" {
				return t.ring.candidates(), nil
			}
			pub, ok := t.ring.byKid(kid)
			if !ok {
				return nil, fmt.Errorf("tis: unknown key %q", kid)
			}
			return pub, nil
		},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithExpirationRequired(),
	)
	return err
}
