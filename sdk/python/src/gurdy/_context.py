"""The execution-context binding, and the rules for how far it travels.

One ``ContextVar`` holds the credential for the task currently running. That
choice is what makes asyncio work for free — ``asyncio.create_task`` copies the
context at creation — and it is also what makes a *worker thread start empty*,
which is the behaviour we want: a pooled thread that inherited whatever the
pool's creator was doing would stamp one task's identity onto another task's
calls, and misattributed provenance is the failure mode this product exists to
eliminate. An unenriched call is a visible gap; a wrongly-attributed one is not.

So propagation past a context boundary is always explicit, and where it is not
requested the call goes out bare.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

TXN_HEADER = "Gurdy-Txn"


@dataclass(frozen=True)
class Binding:
    """A credential and the claim it carries.

    Everything here is *asserted* — the agent's own account of itself (§5.2).
    The proxy records its own observed principal alongside, and that is what
    policy evaluates on, which is why the SDK accepting these values from the
    caller unchecked is sound: an agent cannot select the identity it is
    authorized as.

    ``lineage`` is not a field. The chain lives inside the token, the proxy
    reads it from there, and a copy held on this side could only ever disagree
    with the signed one.
    """

    txn: str
    agent: str
    human_actor: str = ""

    def headers(self, url: str) -> dict[str, str]:
        """Headers for a call to ``url``; empty when it is not the proxy."""
        from . import _config

        if not _config.is_governed(url):
            return {}
        return {TXN_HEADER: self.txn}


_binding: contextvars.ContextVar[Binding | None] = contextvars.ContextVar(
    "gurdy_binding", default=None
)


def current() -> Binding | None:
    """The binding in effect here, or ``None`` outside any task context."""
    return _binding.get()


@contextmanager
def using(binding: Binding) -> Iterator[Binding]:
    """Run a block under ``binding``.

    The counterpart to obtaining a credential without activating it: a spawn
    helper hands back a binding, and the code that actually runs as that
    sub-agent enters it here. Restores the previous binding on exit, including
    on exception, so a failing sub-agent cannot leak its identity onto the
    parent's subsequent calls.
    """
    token = _binding.set(binding)
    try:
        yield binding
    finally:
        _binding.reset(token)


@contextmanager
def detached() -> Iterator[None]:
    """Run a block with no task context, so calls inside it go out unenriched.

    Not a workaround — a real need. Work that is genuinely not part of the task
    (a health check, a metrics push) should not be recorded as though the task
    performed it, and the honest way to say so is to say so.
    """
    token = _binding.set(None)
    try:
        yield
    finally:
        _binding.reset(token)


def headers(url: str) -> dict[str, str]:
    """Headers to attach to a call to ``url``.

    Empty when there is no task context. That is the whole of the
    "does not fabricate" rule (§5.9): outside a task there is no claim to
    make, and inventing one would put an assertion nobody made into evidence
    that a third party is meant to be able to trust.
    """
    binding = current()
    return binding.headers(url) if binding is not None else {}


# --- crossing a boundary a ContextVar cannot ---------------------------------


def carrier() -> dict[str, Any] | None:
    """A serialisable snapshot of the current binding, or ``None``.

    For process pools and any other boundary that shares no memory. Explicit by
    design: auto-pickling a context across a fork is exactly the magic that
    fails silently, and a worker that receives nothing runs unenriched, which
    the export shows as an attested-coarse principal rather than as somebody
    else's identity.

    The token inside is a live bearer credential for the whole transaction —
    treat a carrier as the secret it is, and do not log it.
    """
    binding = current()
    if binding is None:
        return None
    return {
        "txn": binding.txn,
        "agent": binding.agent,
        "human_actor": binding.human_actor,
    }


@contextmanager
def adopt(carried: dict[str, Any] | None) -> Iterator[Binding | None]:
    """Re-enter the context described by :func:`carrier` on the other side.

    A ``None`` carrier is not an error: it means the parent had no task context
    either, and the correct result is an unenriched worker rather than a
    fabricated one.
    """
    if not carried:
        with detached():
            yield None
        return
    binding = Binding(
        txn=carried["txn"],
        agent=carried.get("agent", ""),
        human_actor=carried.get("human_actor", ""),
    )
    with using(binding) as b:
        yield b
