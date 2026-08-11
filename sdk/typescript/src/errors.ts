/** Failures the SDK must never resolve on the developer's behalf. */

export class GurdyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * A sub-agent asked for a scope that is not provably a narrowing (§5.2).
 *
 * Thrown at the spawn site, before the child is given a binding. Deliberately
 * not recoverable inside the SDK: clamping the scope would hand back a
 * credential nobody asked for, and falling back to the parent's token would
 * attribute the child's actions to the parent — a false lineage, which is the
 * failure this whole product exists to prevent.
 *
 * The server owns the algebra (`internal/tis/scope.go`); this is only the
 * report of its refusal.
 */
export class ScopeNarrowingRefused extends GurdyError {}

/**
 * The local TIS could not be reached, or answered with something unusable.
 *
 * Where this surfaces depends on which form you used, and the split is
 * deliberate:
 *
 * - `startTask` and `derive` **reject** with it. Their whole job is to return a
 *   credential and there is no degraded value to return.
 * - `task()` and `spawn()` **do not**. They log once and run the callback with
 *   no binding, so the calls inside go out unenriched.
 *
 * The second is the important one. This SDK enriches; it does not gate. A
 * transient outage of a local socket must not stop an agent from working: the
 * proxy still observes the traffic and still records an attested-coarse
 * principal (§5.2), so degrading costs a claim while throwing costs the
 * request. An on-ramp that makes the agent *less* reliable than not installing
 * it gets uninstalled, and takes the evidence with it (NFR-3's posture, applied
 * on this side of the wire).
 */
export class TISUnavailable extends GurdyError {}

/**
 * No TIS socket is configured, so no credential can be obtained.
 *
 * Distinct from {@link TISUnavailable}: nothing was even attempted, it fails
 * identically on every run, and it fails the first time anyone tries it rather
 * than at 3am. Throwing rather than silently no-op'ing is the point — a task
 * wrapper that quietly enriched nothing would let a developer believe a whole
 * service is instrumented when it is not.
 */
export class NotConfigured extends GurdyError {}
