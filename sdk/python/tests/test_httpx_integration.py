"""The client integration, driven through httpx's real machinery.

``MockTransport`` rather than a live server: the interesting behaviour is
httpx's — redirect handling, header carry-over, hook ordering — and a mock
transport exercises all of it without a socket.
"""

from __future__ import annotations

import httpx
import pytest

import gurdy

PROXY = "http://proxy.local:8080"


@pytest.fixture(autouse=True)
def _configured():
    gurdy.configure(proxy_url=PROXY, tis_socket="/nonexistent.sock")
    yield
    from gurdy import _config

    _config.reset()


def _recorder(handler):
    seen: list[httpx.Request] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return seen, httpx.MockTransport(transport_handler)


def test_governed_call_is_stamped_and_an_unrelated_host_is_not():
    seen, transport = _recorder(lambda r: httpx.Response(200))
    client = gurdy.httpx_client(transport=transport)
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        client.post("/")
        client.post("http://elsewhere.example/")
    client.close()
    assert seen[0].headers.get("Gurdy-Txn") == "tok"
    assert "Gurdy-Txn" not in seen[1].headers


def test_a_redirect_off_the_proxy_does_not_carry_the_credential():
    """The trap that arms the day someone sets ``follow_redirects=True``.

    httpx copies headers onto the redirected request, so a hook that only ever
    *added* the token would leave it in place when the proxy redirects
    elsewhere — handing a live bearer credential for the whole transaction to
    whoever controls the Location header. The hook has to be authoritative:
    set when the target is the proxy, removed when it is not.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "proxy.local":
            return httpx.Response(302, headers={"Location": "http://evil.example/steal"})
        return httpx.Response(200)

    seen, transport = _recorder(handler)
    client = gurdy.httpx_client(transport=transport, follow_redirects=True)
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        client.post("/")
    client.close()

    assert len(seen) == 2, "the redirect was not followed; the test proves nothing"
    assert seen[0].headers.get("Gurdy-Txn") == "tok"
    assert seen[1].url.host == "evil.example"
    assert "Gurdy-Txn" not in seen[1].headers


def test_a_callers_own_event_hooks_do_not_disable_stamping():
    """``setdefault`` looked equivalent to merging, and silently was not.

    A caller registering a hook for a *different* event would have replaced the
    whole mapping, dropping the request hook — every call then unenriched, with
    the traffic still flowing and nothing to notice.
    """
    logged: list[int] = []
    seen, transport = _recorder(lambda r: httpx.Response(200))
    client = gurdy.httpx_client(
        transport=transport,
        event_hooks={"response": [lambda resp: logged.append(resp.status_code)]},
    )
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        client.post("/")
    client.close()
    assert seen[0].headers.get("Gurdy-Txn") == "tok"
    assert logged == [200], "the caller's own hook was dropped instead of kept"


def test_async_client_stamps_too():
    import asyncio

    async def main():
        seen, transport = _recorder(lambda r: httpx.Response(200))
        client = gurdy.httpx_async_client(transport=transport)
        with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
            await client.post("/")
        await client.aclose()
        return seen

    seen = asyncio.run(main())
    assert seen[0].headers.get("Gurdy-Txn") == "tok"
