#!/usr/bin/env python3
"""Conformance driver for the Python SDK.

Reads a case on stdin, executes its steps through the SDK's *public surface*,
writes a transcript to stdout. See ``conformance/README.md`` for the contract.

The rule that shapes this file: it must not re-implement the wire protocol. A
driver that posts to ``/mint`` itself and sets ``Gurdy-Txn`` by hand would prove
the protocol works — which the built-in reference driver already proves — and
would say nothing about the SDK. So every step here goes through the surface a
developer would use, and the only thing this file contributes is the mapping
from a declarative case to those calls.

Run it via the suite, not directly::

    gurdy-conform -cases ../../conformance/cases -proxy ./gurdy-proxy \\
        -driver ../../sdk/python/conformance_driver.py
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import sys

import gurdy


def _body(step: dict) -> str:
    """The request body for a call step.

    Absent *or* empty: the runner hands the driver a re-marshalled case, so
    unset string fields arrive as "" rather than missing. Testing for None
    sends an empty body, which the proxy correctly declines to record as a tool
    call — a silent pass-through that looks exactly like a broken SDK.
    """
    return step.get("body") or json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": step.get("tool", ""),
                "arguments": step.get("args") or {},
            },
        }
    )


def _call(client, step: dict) -> None:
    """One governed call, through an SDK-instrumented client.

    The client carries the SDK's request hook, so whether the credential lands
    on this request is decided by the SDK's own context rules — which is the
    thing under test. Nothing here inspects or sets a header.
    """
    response = client.post(
        step.get("path") or "/",
        content=_body(step),
        headers={"Content-Type": "application/json"},
    )
    response.read()
    response.close()


def _in_process(carried: dict | None, step: dict) -> None:
    """Make one call in a fresh process, re-entering the carried context.

    Module level because it has to be importable by name in the child. The
    client is built here rather than passed: a connection pool does not cross a
    process boundary, and the SDK's configuration comes from the environment
    the child inherits.
    """
    with gurdy.adopt(carried):
        client = gurdy.httpx_client()
        try:
            _call(client, step)
        finally:
            client.close()


async def _acall(step: dict) -> None:
    """One governed call over an async client, exercising the async request hook."""
    client = gurdy.httpx_async_client()
    try:
        response = await client.post(
            step.get("path") or "/",
            content=_body(step),
            headers={"Content-Type": "application/json"},
        )
        await response.aread()
        await response.aclose()
    finally:
        await client.aclose()


async def _in_task(step: dict) -> None:
    """Make one call from a distinct asyncio Task.

    ``create_task`` is where the context is copied, and a genuinely async
    client keeps the whole thing on the event loop. Deliberately not
    ``asyncio.to_thread``: that copies the context itself, so the call would
    cross a *thread* boundary under asyncio's own machinery and pass whatever
    the SDK did.
    """
    await asyncio.create_task(_acall(step))


def _dispatch(client, pool, step: dict) -> None:
    """Run one call from the execution context the case demands.

    Called with the binding already active, so whether it survives the boundary
    is the SDK's problem — which is the whole point of the ``in`` field.
    """
    where = step.get("in") or ""
    if where == "thread":
        # gurdy.ThreadPoolExecutor captures the binding at submit, in this
        # thread. One shared single-worker pool for the whole case, on purpose:
        # it guarantees the same OS thread serves every threaded call, which is
        # the arrangement that exposes a worker retaining the previous task's
        # identity (case 11). A fresh pool per call would hide it.
        pool.submit(_call, client, step).result()
    elif where == "async":
        asyncio.run(_in_task(step))
    elif where == "process":
        carried = gurdy.carrier()
        # spawn, not fork: this driver holds a live thread pool, and forking a
        # process that has threads is a documented way to deadlock the child.
        ctx = multiprocessing.get_context("spawn")
        proc = ctx.Process(target=_in_process, args=(carried, step))
        proc.start()
        proc.join(30)
        if proc.exitcode != 0:
            raise RuntimeError(f"process worker exited {proc.exitcode}")
    else:
        _call(client, step)


def main() -> int:
    case = json.load(sys.stdin)
    client = gurdy.httpx_client()
    pool = gurdy.ThreadPoolExecutor(max_workers=1)
    bindings: dict[str, gurdy.Binding] = {}
    steps: list[dict] = []

    for index, step in enumerate(case.get("steps") or []):
        if mint := step.get("mint"):
            # start_task rather than the @gurdy.task decorator: a case names its
            # credentials and calls under them in an order the case chooses, so
            # the driver holds handles and activates one per call. Same code
            # path — task() is start_task() plus using().
            bindings[mint["as"]] = gurdy.start_task(
                agent=mint.get("agent", ""),
                human_actor=mint.get("human_actor", ""),
                scope=mint.get("scope"),
            )
            steps.append({"index": index})

        elif spawn := step.get("derive"):
            try:
                bindings[spawn["as"]] = gurdy.derive(
                    bindings[spawn["from"]],
                    agent=spawn.get("agent", ""),
                    scope=spawn.get("scope"),
                )
            except gurdy.ScopeNarrowingRefused as exc:
                # Reported as a refusal *of this step*, which is what stops a
                # driver from claiming a refusal it never attempted. Note what
                # does not happen: no retry with a smaller scope, and no
                # falling back to the parent's binding.
                steps.append({"index": index, "refused": True, "reason": str(exc)})
                continue
            steps.append({"index": index})

        elif call := step.get("call"):
            name = call.get("txn") or "none"
            if name == "none":
                # Outside any task context. detached() is explicit because this
                # driver holds live bindings that are not lexically scoped; in
                # ordinary code the call would simply sit outside the with-block.
                # Either way the SDK must send nothing rather than invent one.
                with gurdy.detached():
                    _dispatch(client, pool, call)
            else:
                with gurdy.using(bindings[name]):
                    _dispatch(client, pool, call)
            steps.append({"index": index})

    pool.shutdown(wait=True)
    client.close()
    json.dump({"steps": steps}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
