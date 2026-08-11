"""Where the proxy and the local TIS are, and nothing else.

Both default from the environment, because §5.9's production mode is meant to
be "install + env var": the task boundary is marked in code, but *where the
governed traffic goes* is a deployment fact and does not belong in a source
file.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, replace
from urllib.parse import SplitResult, urlsplit

ENV_PROXY_URL = "GURDY_PROXY_URL"
ENV_TIS_SOCKET = "GURDY_TIS_SOCKET"


@dataclass(frozen=True)
class Config:
    proxy_url: str = ""
    tis_socket: str = ""


_lock = threading.Lock()
_config: Config | None = None


def _from_env() -> Config:
    return Config(
        proxy_url=os.environ.get(ENV_PROXY_URL, "").rstrip("/"),
        tis_socket=os.environ.get(ENV_TIS_SOCKET, ""),
    )


def current() -> Config:
    global _config
    with _lock:
        if _config is None:
            _config = _from_env()
        return _config


def configure(*, proxy_url: str | None = None, tis_socket: str | None = None) -> Config:
    """Override the environment. Returns the resulting configuration."""
    global _config
    with _lock:
        base = _config if _config is not None else _from_env()
        if proxy_url is not None:
            base = replace(base, proxy_url=proxy_url.rstrip("/"))
        if tis_socket is not None:
            base = replace(base, tis_socket=tis_socket)
        _config = base
        return base


def reset() -> None:
    """Forget the cached configuration; the next read re-reads the environment."""
    global _config
    with _lock:
        _config = None


def is_governed(url: str) -> bool:
    """Whether ``url`` is the configured proxy, and may therefore carry the token.

    One configured base URL, matched literally — deliberately not a pattern, a
    wildcard, or a host list. ``Gurdy-Txn`` is a live bearer credential for the
    whole transaction and the proxy is the only hop meant to consume it, so a
    permissive rule here is how a mis-aimed call hands a credential to an
    upstream tool server that can then mint assertions in the agent's name. A
    wrong answer in the strict direction costs one unenriched record.

    Matched by parsing, not by string prefix, because a string prefix is wrong
    in both directions and the false-positive direction hands out a credential:

    - ``http://gurdy.internal`` is a prefix of
      ``http://gurdy.internal.attacker.example/collect``. Configuring the proxy
      with no port is the ordinary case, so this is not an exotic misuse.
    - ``http://gurdy.internal@attacker.example/`` has the configured value as a
      prefix and ``attacker.example`` as its actual host — userinfo is part of
      the authority and a string comparison cannot see that.
    - ``.../api`` is a prefix of ``.../apiary``.

    And in the harmless direction, a host that differs only in case, or an
    explicit ``:80`` against a client that normalises it away, would silently
    stop enriching anything.

    So: compare scheme, host and effective port, then require the configured
    path to end at a path segment boundary. The comparison is deliberately
    exact — one origin, no wildcards, no host list. This is the only place a
    live bearer credential can be attached to an outbound request.
    """
    base = current().proxy_url
    if not base:
        return False
    try:
        want, got = urlsplit(base), urlsplit(url)
    except ValueError:
        return False  # unparseable: not provably the proxy, so no credential
    if want.scheme.lower() != got.scheme.lower():
        return False
    if (want.hostname or "").lower() != (got.hostname or "").lower():
        return False
    if _port(want) != _port(got):
        return False
    if not got.path.startswith(want.path):
        return False
    rest = got.path[len(want.path) :]
    return rest == "" or want.path.endswith("/") or rest.startswith("/")


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _port(parts: SplitResult) -> int | None:
    try:
        return parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
    except ValueError:  # a malformed port is not the proxy's
        return None
