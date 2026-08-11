"""The two refusals: never invent a claim, never send the token to the wrong hop."""

from __future__ import annotations

import gurdy
import pytest

PROXY = "http://proxy.local:8080"


@pytest.fixture(autouse=True)
def _configured():
    gurdy.configure(proxy_url=PROXY, tis_socket="/nonexistent.sock")
    yield
    from gurdy import _config

    _config.reset()


def test_no_task_context_means_no_header():
    """§5.9: a call outside a task passes through unenriched.

    The record then says attested-coarse, which is a true statement about what
    the proxy observed. A fabricated assertion would be a false one, and the
    ledger is meant to be worth trusting.
    """
    assert gurdy.current() is None
    assert gurdy.headers(PROXY + "/") == {}


def test_leaving_a_task_stops_the_enrichment():
    b = gurdy.Binding(txn="tok", agent="a")
    with gurdy.using(b):
        assert gurdy.headers(PROXY + "/") == {gurdy.TXN_HEADER: "tok"}
    assert gurdy.headers(PROXY + "/") == {}


def test_a_failing_task_does_not_leak_its_identity_onward():
    outer = gurdy.Binding(txn="outer", agent="o")
    inner = gurdy.Binding(txn="inner", agent="i")
    with gurdy.using(outer):
        with pytest.raises(RuntimeError):
            with gurdy.using(inner):
                raise RuntimeError("sub-agent blew up")
        # The parent's identity is restored, not the child's left in place.
        assert gurdy.headers(PROXY + "/") == {gurdy.TXN_HEADER: "outer"}


def test_detached_suppresses_enrichment_inside_a_task():
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        with gurdy.detached():
            assert gurdy.headers(PROXY + "/") == {}
        assert gurdy.headers(PROXY + "/") == {gurdy.TXN_HEADER: "tok"}


# --- the credential goes to exactly one hop ----------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example/",  # somewhere else entirely
        "http://proxy.local:9999/",  # right host, wrong port
        "https://proxy.local:8080/",  # right authority, wrong scheme
        "http://proxy.local/",  # right host, no port
        "http://proxy.local.evil.example/",  # prefix of the *host*, not the URL
    ],
)
def test_the_token_never_goes_to_a_hop_that_is_not_the_proxy(url):
    """Gurdy-Txn is a live bearer credential for the whole transaction.

    The proxy consumes it and never forwards it upstream — but that only
    protects the hop the proxy is on. An upstream tool server that receives one
    directly can mint call assertions in the agent's name, so a mis-aimed call
    must carry nothing. The check is a literal prefix match against one
    configured base URL for exactly this reason: a host list or a pattern is
    how the last case above starts passing.
    """
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        assert gurdy.headers(url) == {}


def test_the_token_does_go_to_the_proxy():
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        for url in (PROXY, PROXY + "/", PROXY + "/v1/messages"):
            assert gurdy.headers(url) == {gurdy.TXN_HEADER: "tok"}


@pytest.mark.parametrize(
    "url",
    [
        "http://gurdy.internal.attacker.example/collect",  # the prefix is the *host*
        "http://gurdy.internalXY/",
        "http://gurdy.internal:9999/",  # a port appended to a port-less base
        "http://gurdy.internal@attacker.example/",  # base becomes userinfo
    ],
)
def test_a_port_less_proxy_url_does_not_match_lookalike_hosts(url):
    """The bug a bare ``startswith`` has, and the reason the boundary check exists.

    Configuring ``GURDY_PROXY_URL`` with no port is the ordinary case, and it
    makes the configured string a prefix of every host that merely *starts*
    with it. Whoever owns that host then receives a live bearer credential for
    the whole transaction.

    The first version of this suite missed it by testing only a base URL with a
    port, where the port happens to terminate the authority — a test written
    from the fix rather than from the bug.
    """
    gurdy.configure(proxy_url="http://gurdy.internal")
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        assert gurdy.headers(url) == {}


def test_a_port_less_proxy_url_still_matches_itself():
    gurdy.configure(proxy_url="http://gurdy.internal")
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        for url in (
            "http://gurdy.internal",
            "http://gurdy.internal/",
            "http://gurdy.internal/v1/messages",
            "http://gurdy.internal?x=1",
        ):
            assert gurdy.headers(url) == {gurdy.TXN_HEADER: "tok"}, url


def test_nothing_is_sent_when_no_proxy_is_configured():
    """An unset proxy URL must not mean "match everything"."""
    gurdy.configure(proxy_url="")
    with gurdy.using(gurdy.Binding(txn="tok", agent="a")):
        assert gurdy.headers("http://anywhere/") == {}
