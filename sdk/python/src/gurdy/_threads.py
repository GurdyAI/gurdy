"""Carrying the task context across boundaries a ContextVar does not cross.

asyncio needs nothing here: ``asyncio.create_task`` copies the context, so a
coroutine started inside a task inherits the binding and a coroutine started
outside one does not — both correct, for free.

Threads are the opposite. ``threading.Thread`` and ``ThreadPoolExecutor`` start
workers with an empty context, so lineage stops at the boundary unless it is
carried deliberately. That default is safe (an unenriched call is a visible
gap) but incomplete, so this module provides the carrying — always capturing in
the *submitting* thread, never in the worker, because capturing in the worker
is how a pooled thread ends up stamping the previous task's identity onto this
one's calls.
"""

from __future__ import annotations

import concurrent.futures as _cf
import functools
import logging
import threading
from typing import Any, Callable, TypeVar

from ._context import Binding, current, detached, using

_R = TypeVar("_R")
_log = logging.getLogger("gurdy")


def bound(fn: Callable[..., _R]) -> Callable[..., _R]:
    """Wrap ``fn`` so it runs under the binding in effect *now*.

    Capture happens when ``bound`` is called, which for
    ``executor.submit(bound(f))`` is the submitting thread — the whole point.

    Only the Gurdy binding travels, not the whole ``contextvars.Context``.
    Re-entrancy is why: one copied ``Context`` cannot be entered by two threads
    at once, so a wrapped callable submitted twice concurrently would raise.
    Carrying one value also keeps the blast radius to this library, rather than
    silently teleporting some other package's context variables into a worker.
    """
    if getattr(fn, "__gurdy_bound__", False):
        # Already wrapped, in this same thread and moment — the three thread
        # mechanisms overlap (the executor subclass calls submit, which
        # instrument_threading may also have patched), and wrapping twice would
        # capture the same binding twice for no reason.
        return fn
    binding: Binding | None = current()

    @functools.wraps(fn)
    def run(*args: Any, **kwargs: Any) -> _R:
        if binding is None:
            # Explicitly *clear* rather than leave whatever this worker last
            # held. Pool threads are reused, and inheriting a previous task's
            # binding would attribute this call to an unrelated agent.
            with detached():
                return fn(*args, **kwargs)
        with using(binding):
            return fn(*args, **kwargs)

    run.__gurdy_bound__ = True  # type: ignore[attr-defined]
    return run


class ThreadPoolExecutor(_cf.ThreadPoolExecutor):
    """A ``ThreadPoolExecutor`` whose workers inherit the submitter's task context."""

    def submit(self, fn: Callable[..., _R], /, *args: Any, **kwargs: Any) -> "_cf.Future[_R]":
        return super().submit(bound(fn), *args, **kwargs)


_patch_lock = threading.Lock()
_patched = False


def instrument_threading() -> bool:
    """Make stock ``threading.Thread`` and ``ThreadPoolExecutor`` carry the context.

    Opt-in, and never on by default. Agent frameworks fan tools out across
    thread pools the caller never constructed, so without this the lineage a
    developer believes is automatic stops at somebody else's executor. With it,
    this package is patching classes it does not own — which breaks gevent and
    eventlet, and interacts badly with anything that has already subclassed
    them.

    Neither default is safe enough to pick for someone, so the choice is theirs
    and the failure it prevents is documented next to the one it causes.
    Idempotent; returns True if this call installed the patches.
    """
    global _patched
    with _patch_lock:
        if _patched:
            return False

        original_start = threading.Thread.start

        def start(self: threading.Thread) -> None:
            # Wrap `run`, not `target`: a Thread subclass that overrides run()
            # has no target at all, and it is exactly the shape frameworks use.
            # Bound here, in the thread calling start().
            try:
                self.run = bound(self.run)  # type: ignore[method-assign]
            except AttributeError:
                # A subclass with a read-only `run` (a property, or __slots__)
                # cannot be wrapped this way. Started unwrapped and said so,
                # rather than raising: this patch is opt-in ergonomics, and it
                # must not turn a thread that worked into one that does not.
                _log.warning("gurdy: cannot carry context into %r; its run() is not assignable", self)
            original_start(self)

        original_submit = _cf.ThreadPoolExecutor.submit

        @functools.wraps(original_submit)
        def submit(self: _cf.ThreadPoolExecutor, fn: Callable[..., Any], /, *a: Any, **kw: Any) -> Any:
            return original_submit(self, bound(fn), *a, **kw)

        threading.Thread.start = start  # type: ignore[method-assign]
        _cf.ThreadPoolExecutor.submit = submit  # type: ignore[method-assign]
        _patched = True
        return True
