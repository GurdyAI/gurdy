package main

import (
	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
	"github.com/GurdyAI/gurdy/proxy/internal/policy"
)

// The Act stage of the governance loop (§4.2), as an interface with exactly one
// implementation today — deliberately, and against the usual rule about
// single-implementation abstractions.
//
// The reason is that the *second* implementation is a Phase 2 requirement
// (ADR-14's local enforce actuator) and every transport has to consult it. As
// the code stood, `ServeHTTP` forwarded unconditionally and the shim's relay
// always wrote the line to the child, so adding blocking meant editing both
// transports and the decision path at once — a refactor with no intermediate
// state where the tree is both correct and half-done. With this seam, Phase 2
// adds an implementation and changes the call sites' *data*, not their shape.
//
// It also names the thing Phase 2 must not get wrong: an actuator returns a
// Plan, and §5.5 requires the record to be durable *before* a plan that is not
// Forward takes effect. That ordering is a property of the seam, not of the
// actuator, so it can be enforced here once rather than in each transport.
type Actuator interface {
	// Plan decides what happens to the traffic. It is given the policy's
	// conclusion, never the payload: an actuator that could read the body
	// would be a second place where content affects a decision (ADR-7).
	Plan(policy.Decision) Plan
}

// Plan is what the transport must do with the call.
type Plan struct {
	// Forward is false only when something actively stops the traffic. Monitor
	// mode never sets it false — ADR-3 is a property of this build, and the
	// field exists so that fact is *stated* in the evidence rather than
	// implied by the absence of code that could do otherwise.
	Forward bool
	// Applied is the §5.5 action_applied value the record must carry.
	Applied string
	// FailMode records which way an undecidable call went (FR-11), empty when
	// nothing failed.
	FailMode string
	// Durable requires the record to be written and flushed before the plan
	// takes effect (§5.5: "any record whose action_applied ≠ forwarded ... is
	// written synchronously before the actuator's effect is released"). Always
	// false in monitor mode; the enforce actuator sets it, and the call site
	// honours it via ledger.AppendSync.
	Durable bool
}

// monitorActuator forwards everything, always (ADR-3). It is the whole of the
// Act stage in Phase 1, and it exists as a type rather than as an `if` so that
// "this build cannot block" is one object anyone can find, rather than an
// absence spread across two transports.
type monitorActuator struct{}

func (monitorActuator) Plan(d policy.Decision) Plan {
	if d == policy.Indeterminate {
		// Forwarding because we could not decide is a fail-open, and the
		// reporter counts those apart from clean forwards (§5.6, NFR-3).
		return Plan{Forward: true, Applied: ledger.ActionFailedOpen, FailMode: ledger.FailOpen}
	}
	return Plan{Forward: true, Applied: ledger.ActionForwarded}
}
