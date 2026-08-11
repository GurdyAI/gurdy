// Package policy wraps the embedded Cedar engine (ADR-1).
// No network I/O during evaluation; all context arrives in the request (§5.3).
package policy

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
)

// Starter is the bundled free-tier flight-recorder policy set (BR-11).
//
//go:embed starter.cedar
var Starter []byte

// Decision is what the *policy* concluded for one intercepted call (FR-5).
// It is not what happened to the traffic: the actuator's action_applied and
// the policy's policy_mode are separate ledger fields (§4.2), and this build
// forwards everything (ADR-3).
type Decision string

const (
	Allow Decision = "allow"
	Flag  Decision = "flag"
	// Block is a conclusion, never an effect here — a forbid whose author set
	// enforce_action=block. Paired with policy_mode=monitor and
	// action_applied=forwarded it is exactly the shadow record of §8.3:
	// "would have blocked". The actuator that makes it an effect is Phase 2.
	Block         Decision = "block"
	Indeterminate Decision = "indeterminate"
)

// Per-policy fail/enforce metadata (§5.3: every policy declares on_error and
// enforce_action; FR-11). A stated value is validated at load, so a typo in a
// *value* fails when the pack is published rather than the first time it
// matters.
//
// ponytail: a typo in the *key* (@enfroce_action) is still invisible — Cedar
// annotations are free-form, so absence and misspelling look identical, and
// both take the default. Harmless in Phase 1: the defaults are exactly what a
// monitor build does anyway, so a missed annotation cannot make the proxy more
// permissive than it already is. It arms with the actuator, where "declaration
// required on every forbid" belongs (Phase 2: enforce_action/on_error honored)
// — enforcing it here would only add boilerplate to every test bundle a phase
// early, and would not cover the pack-registry lint that has to exist anyway.
const (
	EnforceFlag  = "flag" // default: record the conclusion, nothing more
	EnforceBlock = "block"

	OnErrorOpen   = "open" // default (FR-11: fail-open on single-instance installs)
	OnErrorClosed = "closed"
)

// Input is the policy-relevant view of one tool call (governance loop: Classify).
type Input struct {
	// Principal is the proxy-*observed* principal (§5.5), never the agent's
	// claim: an agent that could pick this string would pick the identity it
	// is authorized as. The claim is available to policies as reserved
	// context instead, so trusting it is an explicit line in a pack — which
	// is what §5.9's "policies may require attestation" means in practice.
	Principal         string
	AssertedPrincipal string            // agent-side claim; "" unless the assertion verified
	AssertionStatus   string            // absent | valid | invalid
	Tool              string            // MCP tool name, e.g. "read_file"
	Action            string            // normalized action, e.g. "mcp/tools_call"
	Resource          string            // extracted resource identifier (path, host, ...)
	Context           map[string]string // extra extracted attributes
}

// reservedContextKeys are owned by the proxy: an extracted attribute using one
// of these names is dropped, not merged. Dropping rather than overwriting is
// the point — an optional key like asserted_principal is not written at all
// when no claim verified, which is exactly when a forged one does the most
// damage. Shadowing `tool` would restore the name-matching dodge that
// lowercasing it exists to prevent (§7 aliasing). Today's extractors emit two
// fixed keys; the pluggable per-domain registry (FR-6) is what puts these
// names within an attacker's reach, and this has to be right before it lands.
var reservedContextKeys = []string{"tool", "asserted_principal", "assertion_status"}

// Result carries the aggregate decision plus what *each* determining policy
// concluded (FR-7). Per-policy rather than a flat ID list because staged
// graduation puts policies with different rollout states on the same call, and
// one record-level mode cannot say which was enforcing and which was shadowing
// (§5.5 v0.8.5).
type Result struct {
	Decision Decision
	Effects  []Effect
}

// Effect is one determining policy's contribution.
type Effect struct {
	PolicyID      string
	Decision      Decision
	Mode          string // rollout state; monitor everywhere until the actuator lands
	EnforceAction string
	OnError       string
}

// IDs is the flat list, for the places that only need "which policies fired".
func (r Result) IDs() []string {
	out := make([]string, 0, len(r.Effects))
	for _, e := range r.Effects {
		out = append(out, e.PolicyID)
	}
	return out
}

// Evaluator holds a loaded, versioned policy bundle.
type Evaluator struct {
	ps   *cedar.PolicySet
	meta map[cedar.PolicyID]policyMeta
	// Version is the bundle version recorded with every decision (FR-10).
	Version string
}

// policyMeta is a policy's declared behavior (§5.3, FR-11). on_error is
// retained now — v0.8.5 puts it in the record, because a reader cannot
// otherwise tell what a policy *would* have done when evaluation failed.
type policyMeta struct{ enforce, onError string }

// Load parses a Cedar policy document. Monitor-mode semantics: Cedar "forbid"
// means flag, never block (ADR-3). The local enforce actuator (ADR-14) is
// Phase 2 work; until it lands this build is monitor-only in every tier.
func Load(version string, document []byte) (*Evaluator, error) {
	parsed, err := cedar.NewPolicySetFromBytes(version+".cedar", document)
	if err != nil {
		return nil, err
	}
	// Re-key policies by their @id annotation so ledger records carry stable,
	// author-chosen policy IDs (FR-7) instead of positional policyN names.
	ps := cedar.NewPolicySet()
	meta := map[cedar.PolicyID]policyMeta{}
	for id, p := range parsed.All() {
		ann := p.Annotations()
		if named, ok := ann["id"]; ok {
			id = cedar.PolicyID(named)
		}
		act, err := oneOf("enforce_action", ann["enforce_action"], EnforceFlag, EnforceBlock)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", id, err)
		}
		onErr, err := oneOf("on_error", ann["on_error"], OnErrorOpen, OnErrorClosed)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", id, err)
		}
		// Two policies re-keyed to the same @id would leave only the last one in
		// the set: a control silently absent from a pack that appears to contain
		// it, and a policy_ids entry that no longer identifies which rule fired.
		if !ps.Add(id, p) {
			return nil, fmt.Errorf("policy %s: duplicate @id — one rule would silently replace the other", id)
		}
		meta[id] = policyMeta{enforce: act, onError: onErr}
	}
	return &Evaluator{ps: ps, meta: meta, Version: version}, nil
}

// oneOf constrains an optional annotation to a fixed vocabulary, defaulting to
// the first value when it is absent (an absent annotation and an empty one are
// the same thing; no legal value is empty).
func oneOf(name string, v cedar.String, allowed ...string) (string, error) {
	if v == "" {
		return allowed[0], nil
	}
	if !slices.Contains(allowed, string(v)) {
		return "", fmt.Errorf("@%s(%q) must be one of %v", name, string(v), allowed)
	}
	return string(v), nil
}

// Evaluate runs one call through Cedar. Deterministic, local, sub-ms (§5.3).
//
// **Every string a policy matches on is lowercased for evaluation; the ledger
// keeps the raw value.** This began as `context.tool` only — so `DeleteFile`
// could not dodge a rule written for `delete_file` — and adversarial corpus
// trace 05 showed the same dodge worked one field over: the credential rule
// matches `resource_path like "*/.ssh/*"`, and `/home/u/.SSH/id_rsa` is the same
// file on macOS and Windows and a different string everywhere. A one-line bypass
// of the flagship BR-11 control.
//
// Normalising the whole set rather than adding a second special case is the
// point: the bug was not that `resource_path` was forgotten, it was that
// case-folding was a property of one field instead of a property of matching.
// A new extractor attribute now gets the safe behaviour by default.
//
// The cost is a false positive where case is genuinely significant — a Linux
// `.SSH` directory that really is distinct from `.ssh` now flags. That is the
// right direction to be wrong in: a spurious flag is noise in a monitor, and a
// missed credential read is a bypass.
//
// ponytail: this would corrupt an attribute whose value is case-significant, a
// base64 signature being the obvious one. No extractor emits such a value today.
// If one ever does, the fix is an explicit exact-match set here — not reverting
// to per-field folding, which is how this got missed the first time.
//
// Binding to tool *signature* rather than name is still the §7 aliasing control
// (roadmap §3.D); this closes the case dimension of it, not the naming one.
func (e *Evaluator) Evaluate(in Input) Result {
	ctx := cedar.RecordMap{}
	for k, v := range in.Context {
		if slices.Contains(reservedContextKeys, k) {
			continue // see reservedContextKeys
		}
		ctx[cedar.String(k)] = cedar.String(strings.ToLower(v))
	}
	ctx["tool"] = cedar.String(strings.ToLower(in.Tool))
	ctx["assertion_status"] = cedar.String(in.AssertionStatus)
	// Left absent rather than empty when there is no verified claim, so
	// `context has asserted_principal` is a real test for one. Lowercased like
	// everything else: the agent chooses this string, so a pack rule naming a
	// quarantined agent must not be dodgeable by capitalising it.
	if in.AssertedPrincipal != "" {
		ctx["asserted_principal"] = cedar.String(strings.ToLower(in.AssertedPrincipal))
	}
	req := cedar.Request{
		// The resource UID gets the same treatment as the attribute: a policy
		// written as `resource == Resource::"/etc/shadow"` would otherwise carry
		// the bypass the context attribute no longer has.
		Principal: cedar.NewEntityUID("Agent", cedar.String(strings.ToLower(in.Principal))),
		Action:    cedar.NewEntityUID("Action", cedar.String(in.Action)),
		Resource:  cedar.NewEntityUID("Resource", cedar.String(strings.ToLower(in.Resource))),
		Context:   cedar.NewRecord(ctx),
	}
	decision, diag := cedar.Authorize(e.ps, cedar.EntityMap{}, req)
	ids := policyIDs(diag)

	// Each determining policy's own conclusion, then the aggregate. A permit
	// concludes allow; a forbid concludes what its author declared it would do.
	agg := Allow
	if len(diag.Errors) > 0 {
		agg = Indeterminate
	} else if decision != cedar.Allow {
		agg = Flag
	}
	effects := make([]Effect, 0, len(ids))
	for _, id := range ids {
		m := e.meta[cedar.PolicyID(id)]
		d := agg
		if agg == Flag {
			// Most-restrictive wins for the aggregate: if any matching forbid
			// would have blocked, the call would have been blocked.
			d = Flag
			if m.enforce == EnforceBlock {
				d = Block
			}
		}
		effects = append(effects, Effect{PolicyID: id, Decision: d, Mode: ModeMonitor,
			EnforceAction: m.enforce, OnError: m.onError})
	}
	if agg == Flag {
		for _, e := range effects {
			if e.Decision == Block {
				agg = Block
				break
			}
		}
	}
	return Result{Decision: agg, Effects: effects}
}

// ModeMonitor is every policy's rollout state until the Phase 2 actuator
// exists. It lives here rather than being read from an annotation because a
// build that cannot enforce must not let a pack claim it is enforcing.
const ModeMonitor = "monitor"

func policyIDs(diag cedar.Diagnostic) []string {
	ids := make([]string, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		ids = append(ids, string(r.PolicyID))
	}
	return ids
}
