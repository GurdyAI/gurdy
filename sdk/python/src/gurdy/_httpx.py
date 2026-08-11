"""httpx integration: stamp the credential on governed calls, and nothing else.

httpx is an optional extra. It is imported here and nowhere else in the
package, so an agent that uses a different client pays nothing for this file
existing.
"""

from __future__ import annotations

from typing import Any

from . import _config
from ._context import TXN_HEADER, headers


def _stamp(request: Any) -> None:
    """Set the transaction credential on this request, or make sure it is absent.

    Removing matters as much as adding, because of redirects. httpx carries
    headers onto the redirected request and runs this hook again for it — so a
    hook that only ever *added* would leave the credential in place when a
    governed URL redirects somewhere else, handing a live bearer token for the
    whole transaction to whoever controls the ``Location``. Following redirects
    is off by default in httpx, which is why this is a trap rather than an
    outage: it arms the first time an application sets ``follow_redirects``.

    So the hook is authoritative for this header on every request it sees:
    present when the target is the proxy and there is a task context, absent
    otherwise.
    """
    stamped = headers(str(request.url))
    if TXN_HEADER in stamped:
        request.headers[TXN_HEADER] = stamped[TXN_HEADER]
    else:
        request.headers.pop(TXN_HEADER, None)


def hooks() -> dict[str, list[Any]]:
    """Event hooks for an existing client::

        client = httpx.Client(event_hooks=gurdy.httpx_hooks())

    For an app that builds its own client and does not want it replaced. The
    hook is a no-op outside a task context and on any URL that is not the
    configured proxy, so it is safe on a client that talks to other hosts.
    """
    return {"request": [_stamp]}


async def _astamp(request: Any) -> None:
    _stamp(request)


def async_hooks() -> dict[str, list[Any]]:
    """The same, for ``httpx.AsyncClient``, whose hooks must be awaitable."""
    return {"request": [_astamp]}


def _merge_hooks(caller: Any, ours: dict[str, list[Any]]) -> dict[str, list[Any]]:
    """Add our request hook to the caller's hooks instead of replacing them.

    ``setdefault`` looked equivalent and was not: a caller who passes
    ``event_hooks={"response": [log]}`` — a different event entirely — would
    have dropped the request hook and silently lost every assertion, with the
    traffic still flowing and the ledger quietly recording attested-coarse.
    """
    merged: dict[str, list[Any]] = {k: list(v) for k, v in (caller or {}).items()}
    for event, fns in ours.items():
        merged.setdefault(event, [])
        # Ours first: a caller hook that raises should not decide whether the
        # request was attributable.
        merged[event] = list(fns) + merged[event]
    return merged


def client(**kwargs: Any) -> Any:
    """An ``httpx.Client`` pointed at the proxy with the hook already attached."""
    import httpx

    kwargs.setdefault("base_url", _config.current().proxy_url)
    kwargs["event_hooks"] = _merge_hooks(kwargs.get("event_hooks"), hooks())
    return httpx.Client(**kwargs)


def async_client(**kwargs: Any) -> Any:
    """An ``httpx.AsyncClient`` pointed at the proxy with the hook attached."""
    import httpx

    kwargs.setdefault("base_url", _config.current().proxy_url)
    kwargs["event_hooks"] = _merge_hooks(kwargs.get("event_hooks"), async_hooks())
    return httpx.AsyncClient(**kwargs)
