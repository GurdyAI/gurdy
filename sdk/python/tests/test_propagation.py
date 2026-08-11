"""The properties a conformance case cannot pin, because they need concurrency.

Everything here is about one question: can a call end up recorded under an
agent that did not make it? A lost binding is a visible gap in the export — the
proxy still records an attested-coarse principal. A *wrong* binding is
misattributed evidence, and no reader can detect it.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import gurdy
import pytest

PROXY = "http://proxy.local"


@pytest.fixture(autouse=True)
def _configured():
    gurdy.configure(proxy_url=PROXY, tis_socket="/nonexistent.sock")
    yield
    from gurdy import _config

    _config.reset()


def binding(name: str) -> gurdy.Binding:
    """A binding built directly, so these tests need no live TIS."""
    return gurdy.Binding(txn=f"token-{name}", agent=name)


def seen() -> str:
    """The token a call made right here would carry, or "" for none."""
    return gurdy.headers(PROXY + "/").get(gurdy.TXN_HEADER, "")


# --- the one a thread-local would pass sequentially and fail here ------------


def test_interleaved_async_tasks_do_not_clobber_each_other():
    """Two tasks, one thread, different bindings, forced to interleave.

    This is the test that separates a ContextVar from a ``threading.local``.
    Sequentially they behave identically — each sets and clears before the next
    begins — so every conformance case passes with either. Interleaved, a
    thread-local holds exactly one value for the whole thread and the second
    task's binding overwrites the first, which then reports the wrong identity
    for the rest of its life.

    The interleaving is forced rather than hoped for, and the ordering is the
    whole test: alpha must read *while* beta's binding is installed. Merely
    alternating is not enough — a thread-local restores on exit like anything
    else, so a task that enters and leaves inside another's ``await`` still
    looks correct. The two bindings have to be live at the same moment.
    """
    a_entered, b_entered, a_read = (asyncio.Event() for _ in range(3))
    observed: dict[str, str] = {}

    async def first():
        with gurdy.using(binding("alpha")):
            a_entered.set()
            await b_entered.wait()  # beta is now installed, and stays installed
            observed["alpha"] = seen()
            a_read.set()

    async def second():
        await a_entered.wait()
        with gurdy.using(binding("beta")):
            b_entered.set()
            await a_read.wait()  # hold beta live across alpha's read
            observed["beta"] = seen()

    async def main():
        await asyncio.wait_for(asyncio.gather(first(), second()), timeout=5)

    asyncio.run(main())
    assert observed == {"alpha": "token-alpha", "beta": "token-beta"}


def test_concurrent_threads_do_not_clobber_each_other():
    """The same claim across real threads, running at the same time."""
    started = threading.Barrier(3, timeout=5)
    observed: dict[str, str] = {}
    lock = threading.Lock()

    def work(name: str) -> None:
        with gurdy.using(binding(name)):
            started.wait()  # all three hold a different binding simultaneously
            with lock:
                observed[name] = seen()

    threads = [threading.Thread(target=work, args=(n,)) for n in ("a", "b", "c")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)

    assert observed == {"a": "token-a", "b": "token-b", "c": "token-c"}


# --- worker reuse ------------------------------------------------------------


def test_pooled_worker_does_not_leak_a_binding_left_behind():
    """A worker that somehow retains a binding must not lend it to the next job.

    ``using`` always restores, so the SDK's own API cannot produce this state —
    which is exactly why it is worth a test: the guard in ``bound`` is
    unreachable through the public surface and would otherwise look like dead
    code to the next person reading it. Here the state is created deliberately,
    the way a third-party ``ctx.run`` or a future carrier bug would.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        # Contaminate the single worker: set without restoring.
        from gurdy import _context

        pool.submit(lambda: _context._binding.set(binding("ghost"))).result()

        # A submit from a context with no binding must arrive clean.
        assert gurdy.current() is None
        assert pool.submit(gurdy.bound(seen)).result() == ""
    finally:
        pool.shutdown(wait=True)


def test_bound_captures_at_submit_not_at_execution():
    """The capture must happen in the submitting thread, while the task is live.

    An SDK that reads the context inside the worker reads whatever that worker
    happens to hold, which is either nothing or the previous task's identity.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with gurdy.using(binding("submitter")):
            job = gurdy.bound(seen)
        # Submitted *after* leaving the block: the binding is already gone from
        # this thread, so only a capture made at bound() time can still be right.
        assert gurdy.current() is None
        assert pool.submit(job).result() == "token-submitter"
    finally:
        pool.shutdown(wait=True)


def test_gurdy_executor_carries_the_submitters_context():
    with gurdy.ThreadPoolExecutor(max_workers=2) as pool:
        with gurdy.using(binding("alpha")):
            alpha = pool.submit(seen)
        beta = pool.submit(seen)  # submitted outside any task
    assert alpha.result() == "token-alpha"
    assert beta.result() == ""


def test_stock_executor_loses_the_context_and_says_nothing():
    """The documented gap, asserted so it cannot change by accident.

    A stock pool drops the binding, and the call goes out unenriched. That is
    the safe failure — the proxy still attributes an attested-coarse principal
    — but it is a failure, and the README promises exactly this behaviour.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        with gurdy.using(binding("alpha")):
            assert pool.submit(seen).result() == ""


# --- asyncio inheritance -----------------------------------------------------


def test_asyncio_task_inherits_and_a_later_one_does_not():
    async def main():
        with gurdy.using(binding("alpha")):
            inside = await asyncio.create_task(_seen())
        outside = await asyncio.create_task(_seen())
        return inside, outside

    async def _seen():
        return seen()

    inside, outside = asyncio.run(main())
    assert inside == "token-alpha"
    assert outside == ""


# --- processes ---------------------------------------------------------------


def test_carrier_round_trips_and_none_stays_none():
    with gurdy.using(binding("alpha")):
        carried = gurdy.carrier()
    assert carried["txn"] == "token-alpha"

    with gurdy.adopt(carried):
        assert seen() == "token-alpha"

    # A parent with no task context produces no carrier, and the worker that
    # receives it runs unenriched rather than inheriting whatever is around.
    assert gurdy.carrier() is None
    with gurdy.using(binding("alpha")):
        with gurdy.adopt(None):
            assert seen() == ""
