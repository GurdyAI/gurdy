"""Marking the task boundary, and spawning sub-agents under it."""

from __future__ import annotations

import contextvars
import functools
import inspect
import logging
from typing import Any, Callable

from . import _config
from ._context import Binding, current, detached, using
from ._errors import NotConfigured, TISUnavailable
from ._tis import Scope, TISClient

_log = logging.getLogger("gurdy")
_warned = False


def _warn_degraded(exc: Exception) -> None:
    """Say once, loudly, that provenance is being lost — and keep going.

    Once rather than per call: a TIS outage affects every task, and a warning
    per call would bury the log of the very application we are asking people to
    trust us inside. The authoritative signal is in the export anyway — the
    proxy records these calls as attested-coarse, and a run with no asserted
    identity is visible to the reporter.
    """
    global _warned
    if not _warned:
        _warned = True
        _log.warning(
            "gurdy: TIS unavailable (%s) — calls will be recorded with the "
            "principal the proxy observes, without asserted identity. "
            "Traffic is unaffected.",
            exc,
        )


def _client() -> TISClient:
    socket_path = _config.current().tis_socket
    if not socket_path:
        raise NotConfigured(
            f"no TIS socket configured — set {_config.ENV_TIS_SOCKET} or call "
            f"gurdy.configure(tis_socket=...). Refusing to run a task that "
            f"cannot obtain a credential, because silently enriching nothing "
            f"looks identical to being instrumented."
        )
    return TISClient(socket_path)


def start_task(
    agent: str,
    human_actor: str = "",
    scope: Scope | dict[str, Any] | None = None,
    ttl_seconds: int = 0,
) -> Binding:
    """Obtain a root transaction credential *without* activating it.

    The handle form. Use it when the code that runs as this task is somewhere
    other than the enclosing block — a worker, a callback, a framework's
    executor. :func:`task` is this plus :func:`~gurdy.using`.
    """
    token = _client().mint(
        agent=agent, human_actor=human_actor, scope=scope, ttl_seconds=ttl_seconds
    )
    return Binding(txn=token, agent=agent, human_actor=human_actor)


def derive(
    parent: Binding, agent: str, scope: Scope | dict[str, Any] | None = None
) -> Binding:
    """Obtain a sub-agent credential from ``parent``, eagerly.

    Eagerly, and not at the child's first governed call, because the refusal
    has to land on the line that asked for too much scope. A lazy derive
    surfaces a 422 somewhere in the middle of the child's work, where agent
    frameworks routinely retry and then continue with a different tool — and a
    child that continues after a refused derive is a child running with no
    credential of its own.

    Raises :class:`~gurdy.ScopeNarrowingRefused` when the requested scope is
    not provably a narrowing of the parent's. Never clamps, and never falls
    back to the parent's token: the child's calls would then be recorded under
    the parent's identity, which is a false lineage rather than a missing one.
    """
    token = _client().derive(parent=parent.txn, agent=agent, scope=scope)
    # human_actor is inherited: the person on whose authority the whole
    # transaction runs does not change because a sub-agent was spawned, and the
    # proxy reads it from the token chain regardless.
    return Binding(txn=token, agent=agent, human_actor=parent.human_actor)


class _Bound:
    """Shared decorator/context-manager plumbing for :func:`task` and :func:`spawn`."""

    def __init__(self, acquire: Callable[[], Binding]) -> None:
        self._acquire = acquire
        # A ContextVar, not an attribute. One `_Bound` can legitimately be
        # entered more than once — nested, or reused, or from two threads — and
        # a single slot on the instance means the inner exit restores the outer
        # entry's state, or worse, one thread resets a token another thread's
        # context created (which raises, and leaves the binding installed after
        # the `with` block has visibly ended). Per-context, and a stack.
        self._entered: contextvars.ContextVar[list[Any]] = contextvars.ContextVar(
            "gurdy_bound_stack"
        )

    def _enter(self) -> Any:
        """Activate a fresh credential, degrading to unenriched if TIS is down."""
        try:
            return using(self._acquire())
        except TISUnavailable as exc:
            # The SDK enriches; it does not gate. A transient TIS outage must
            # not stop the developer's work — the proxy still sees the traffic
            # and still records an attested-coarse principal, so degrading
            # costs a claim and breaking costs the request (NFR-3's posture,
            # applied on this side of the wire).
            #
            # Degrading to *detached* and never to the parent's binding: for a
            # spawn, running the child under its parent's credential would
            # record the child's actions as the parent's, and a false lineage
            # is worse than a missing one.
            _warn_degraded(exc)
            return detached()

    def __enter__(self) -> Binding | None:
        cm = self._enter()
        stack = self._entered.get(None)
        if stack is None:
            stack = []
            self._entered.set(stack)
        stack.append(cm)
        return cm.__enter__()

    def __exit__(self, *exc: Any) -> bool | None:
        stack = self._entered.get(None) or []
        if not stack:
            return None
        return stack.pop().__exit__(*exc)

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        # A fresh credential per invocation, never one captured at decoration
        # time: the decorator runs once at import, the function runs per task,
        # and a token minted at import would put every task in one transaction.
        if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
            # Refused at decoration time — loudly, on import, rather than
            # silently at 3am. A generator does not get its own context: the
            # wrapper would acquire a credential, return the generator object
            # and exit before a single line of the body ran, so the task would
            # be unenriched. Driving it step-by-step instead would leak the
            # binding into the caller between yields, where an unrelated task's
            # calls would pick it up. Neither is a thing to do quietly.
            raise TypeError(
                f"gurdy.task/spawn cannot decorate the generator function "
                f"{fn.__qualname__!r}: the credential would be acquired and "
                f"released before the body runs. Use the context manager "
                f"inside the function instead, around the work rather than "
                f"around the yields."
            )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                with self._enter():
                    return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self._enter():
                return fn(*args, **kwargs)

        return wrapper


def task(
    agent: str,
    human_actor: str = "",
    scope: Scope | dict[str, Any] | None = None,
    ttl_seconds: int = 0,
) -> _Bound:
    """Mark the task boundary: obtain a credential and bind it to this context.

    Usable as a decorator or a context manager::

        @gurdy.task(agent="orchestrator", human_actor="alice@example.com")
        def handle(ticket): ...

        with gurdy.task(agent="orchestrator") as binding:
            ...

    Marked once, at the entry point. Calls inside inherit it with no further
    developer code, and so do asyncio tasks created inside it (§5.9).
    """
    return _Bound(
        lambda: start_task(
            agent=agent, human_actor=human_actor, scope=scope, ttl_seconds=ttl_seconds
        )
    )


def spawn(agent: str, scope: Scope | dict[str, Any] | None = None) -> _Bound:
    """Run a block as a sub-agent of the current task.

    Derives at entry, so a scope that is not a narrowing raises *before* the
    block runs — the body of a refused spawn never executes, which is why the
    SDK needs no further defence against a caller that swallows the exception.
    """

    def acquire() -> Binding:
        parent = current()
        if parent is None:
            raise NotConfigured(
                "gurdy.spawn() outside a task context: there is no parent "
                "credential to derive from. Mark the task boundary with "
                "gurdy.task() first, or make the call unenriched on purpose."
            )
        return derive(parent, agent=agent, scope=scope)

    return _Bound(acquire)
