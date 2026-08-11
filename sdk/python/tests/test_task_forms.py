"""How the decorator and context-manager forms behave at their edges.

Three properties, each of which was wrong in the first version: a `_Bound`
object can be entered more than once, a generator function cannot be decorated
at all, and a TIS outage must not stop the developer's work.
"""

from __future__ import annotations

import asyncio
import logging
import threading

import pytest

import gurdy

PROXY = "http://proxy.local:8080"
DEAD_SOCKET = "/tmp/gurdy-no-such-socket.sock"


@pytest.fixture(autouse=True)
def _configured():
    gurdy.configure(proxy_url=PROXY, tis_socket=DEAD_SOCKET)
    from gurdy import _task

    _task._warned = False  # the warn-once latch is process-global
    yield
    from gurdy import _config

    _config.reset()


def seen() -> str:
    return gurdy.headers(PROXY + "/").get(gurdy.TXN_HEADER, "")


# --- a _Bound is not single-use ----------------------------------------------


def test_the_same_task_object_can_be_entered_twice_and_nested():
    """Entry state belongs to the context, not to the object.

    A single slot on the instance means an inner `__exit__` restores the outer
    entry's state — so after the inner block ends, the outer block is silently
    running with the wrong binding, and every call it makes is misattributed.
    """
    binding = gurdy.Binding(txn="tok", agent="a")
    reusable = gurdy._task._Bound(lambda: binding)

    with reusable:
        with reusable:
            assert seen() == "tok"
        # The outer block is still live: leaving the inner one must not have
        # unwound it.
        assert seen() == "tok"
    assert seen() == ""

    with reusable:  # and the object still works afterwards
        assert seen() == "tok"


def test_two_threads_may_share_one_task_object():
    """One thread's exit must not touch another thread's binding.

    With entry state on the instance this raises ``ValueError: Token was
    created in a different Context`` — or worse, silently leaves a binding
    installed after the `with` has visibly ended.
    """
    reusable = gurdy._task._Bound(lambda: gurdy.Binding(txn="tok", agent="a"))
    both_inside = threading.Barrier(2, timeout=5)
    errors: list[BaseException] = []
    after: list[str] = []

    def work() -> None:
        try:
            with reusable:
                both_inside.wait()
                assert seen() == "tok"
            after.append(seen())
        except BaseException as exc:  # noqa: BLE001 - the point is to see it
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)

    assert errors == []
    assert after == ["", ""], "a binding outlived its with-block"


# --- generator functions are refused, not silently broken --------------------


def test_decorating_a_generator_function_is_refused_at_decoration_time():
    """Loud on import beats silent at 3am.

    A generator does not get its own context: the wrapper would acquire the
    credential, return the generator object and exit before one line of the
    body ran, so the task would be unenriched while looking instrumented.
    """
    with pytest.raises(TypeError, match="generator function"):

        @gurdy.task(agent="a")
        def streaming():
            yield 1


def test_decorating_an_async_generator_function_is_refused_too():
    with pytest.raises(TypeError, match="generator function"):

        @gurdy.task(agent="a")
        async def streaming():
            yield 1


# --- a TIS outage degrades, it does not break traffic ------------------------


def test_task_runs_the_body_unenriched_when_tis_is_down(caplog):
    """The SDK enriches; it does not gate.

    The socket does not exist, so no credential is obtainable. The developer's
    function must still run — the proxy sees the traffic either way and records
    an attested-coarse principal. An on-ramp that makes the agent less reliable
    than not installing it gets uninstalled, and takes the evidence with it.
    """
    ran = []

    @gurdy.task(agent="orchestrator")
    def work():
        ran.append(seen())
        return "done"

    with caplog.at_level(logging.WARNING, logger="gurdy"):
        assert work() == "done"

    assert ran == [""], "degraded run must be unenriched, not fabricated"
    assert any("TIS unavailable" in r.message for r in caplog.records), (
        "silently losing provenance is not a degrade, it is a disappearance"
    )


def test_async_task_degrades_the_same_way():
    @gurdy.task(agent="orchestrator")
    async def work():
        return seen()

    assert asyncio.run(work()) == ""


def test_spawn_degrades_to_no_binding_never_to_the_parents():
    """The child must not inherit the parent's credential when derive fails.

    Running the child under the parent's token would record the child's actions
    as the parent's. That is a *false* lineage, which no reader can detect,
    where an absent one is a visible gap.
    """
    parent = gurdy.Binding(txn="parent-tok", agent="orchestrator")
    with gurdy.using(parent):
        assert seen() == "parent-tok"
        with gurdy.spawn(agent="fetcher"):
            assert seen() == "", "the child ran as its parent"
        assert seen() == "parent-tok", "the parent binding was not restored"


def test_the_handle_forms_still_raise():
    """``start_task``/``derive`` return a credential or nothing at all.

    They have no degraded value to hand back, so they raise where the context
    managers degrade — and a caller who wanted the lenient behaviour has it,
    by using the form that wraps execution.
    """
    with pytest.raises(gurdy.TISUnavailable):
        gurdy.start_task(agent="a")
    with pytest.raises(gurdy.TISUnavailable):
        gurdy.derive(gurdy.Binding(txn="t", agent="a"), agent="b")


def test_no_socket_configured_raises_rather_than_doing_nothing():
    """A missing env var is a deployment error, and a deterministic one.

    Distinct from an outage: nothing was even attempted, it fails identically
    on every run, and it fails the first time anyone tries it rather than at
    3am. Quietly enriching nothing would let a whole service look instrumented.
    """
    gurdy.configure(tis_socket="")
    with pytest.raises(gurdy.NotConfigured):
        with gurdy.task(agent="a"):
            pass
