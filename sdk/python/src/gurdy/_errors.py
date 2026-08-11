"""Failures the SDK must never resolve on the developer's behalf."""


class GurdyError(Exception):
    """Base for every error this package raises."""


class ScopeNarrowingRefused(GurdyError):
    """A sub-agent asked for a scope that is not provably a narrowing (§5.2).

    Raised at the spawn site, synchronously, before the child is given a
    binding. It is deliberately not recoverable inside the SDK: clamping the
    scope would hand back a credential nobody asked for, and falling back to
    the parent's token would attribute the child's actions to the parent —
    a false lineage, which is the failure this whole product exists to prevent.

    The server owns the algebra (``internal/tis/scope.go``); this is only the
    report of its refusal.
    """


class TISUnavailable(GurdyError):
    """The local TIS could not be reached, or answered with something unusable.

    Where this surfaces depends on which form you used, and the split is
    deliberate:

    - ``start_task`` and ``derive`` **raise** it. Their whole job is to return a
      credential and there is no degraded value to return.
    - ``task()`` and ``spawn()`` — the decorator and context-manager forms —
      **do not**. They log once and run the block with no binding, so the calls
      inside go out unenriched.

    The second is the important one. This SDK enriches; it does not gate. A
    transient outage of a local socket must not stop an agent from working: the
    proxy still observes the traffic and still records an attested-coarse
    principal (§5.2), so degrading costs a claim while raising costs the
    request. An on-ramp that makes the agent *less* reliable than not
    installing it gets uninstalled, and takes the evidence with it (NFR-3's
    posture, applied on this side of the wire).
    """


class NotConfigured(GurdyError):
    """No TIS socket is configured, so no credential can be obtained.

    Distinct from :class:`TISUnavailable`: nothing was even attempted. Raising
    rather than silently no-op'ing is the point — a task decorator that
    quietly enriched nothing would let a developer believe a whole service is
    instrumented when it is not.
    """
