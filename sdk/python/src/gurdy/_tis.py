"""The whole wire contract this SDK speaks to the local TIS: mint and derive.

Two endpoints over a Unix socket, and nothing else. There is deliberately no
``/derive-call``: per-call assertions are derived by the proxy from the
transaction token it is already handed, so an agent never gets to choose the
``tool`` its own assertion names.

Written against ``http.client`` rather than a dependency because the payload is
two JSON objects over a local socket, and a governance SDK that drags a
transport stack into someone else's agent process has to justify it (§5.9: a
thin shim, no governance logic).
"""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass
from typing import Any

from ._errors import ScopeNarrowingRefused, TISUnavailable

# The kernel refuses longer socket paths (~104 bytes on macOS, 108 on Linux)
# with EINVAL, which says nothing about length; the proxy reports the same
# limit from the other side.
_TIMEOUT_S = 5.0


class _UnixConnection(http.client.HTTPConnection):
    """HTTPConnection over an AF_UNIX socket."""

    def __init__(self, path: str, timeout: float = _TIMEOUT_S) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:  # noqa: D102 - http.client protocol
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


@dataclass(frozen=True)
class Scope:
    """The dimensioned task-scope descriptor (§5.2).

    Mirrored here only so a caller can name the dimensions; the *algebra* lives
    in the Go TIS and is never reimplemented on this side. A Python copy of
    ``Narrows`` would be a second implementation of a security rule, and the
    two would drift — so the SDK asks and reports the answer.
    """

    compartments: tuple[str, ...] = ("*",)
    resource_types: tuple[str, ...] = ("*",)
    actions: tuple[str, ...] = ("*",)
    purpose: str = "*"

    def as_json(self) -> dict[str, Any]:
        return {
            "compartments": list(self.compartments),
            "resource_types": list(self.resource_types),
            "actions": list(self.actions),
            "purpose": self.purpose,
        }

    @staticmethod
    def coerce(scope: "Scope | dict[str, Any] | None") -> dict[str, Any]:
        """Normalise a caller's scope for the wire.

        A ``dict`` is sent **verbatim**, including its missing keys, and that is
        deliberate. An absent dimension decodes server-side to an empty list,
        which the narrow-only algebra treats as the *bottom* of that dimension:
        a partial scope narrows a wildcard one, and a wildcard one does not
        narrow it. So a dict that omits ``actions`` grants nothing there.

        Filling the gaps with ``"*"`` would be the opposite — it would silently
        widen what the developer wrote, and turn a typo into a grant. Pass
        ``Scope()`` when wildcards are what you mean; that spells them out.
        """
        if scope is None:
            return Scope().as_json()
        if isinstance(scope, Scope):
            return scope.as_json()
        return dict(scope)


class TISClient:
    """Mint and derive against the local TIS socket."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path

    def mint(
        self,
        agent: str,
        human_actor: str = "",
        scope: Scope | dict[str, Any] | None = None,
        ttl_seconds: int = 0,
    ) -> str:
        return self._post(
            "/mint",
            {
                "agent": agent,
                "human_actor": human_actor,
                "scope": Scope.coerce(scope),
                "ttl_seconds": ttl_seconds,
            },
        )

    def derive(
        self, parent: str, agent: str, scope: Scope | dict[str, Any] | None = None
    ) -> str:
        return self._post(
            "/derive",
            {"parent": parent, "agent": agent, "scope": Scope.coerce(scope)},
        )

    def _post(self, path: str, payload: dict[str, Any]) -> str:
        body = json.dumps(payload).encode()
        conn = _UnixConnection(self.socket_path)
        try:
            conn.request(
                "POST", path, body=body, headers={"Content-Type": "application/json"}
            )
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        except (OSError, http.client.HTTPException) as exc:
            raise TISUnavailable(
                f"TIS socket {self.socket_path!r} unreachable: {exc}"
            ) from exc
        finally:
            conn.close()

        try:
            decoded = json.loads(raw)
        except ValueError:
            raise TISUnavailable(
                f"TIS returned {status} with an undecodable body: {raw[:200]!r}"
            ) from None
        if not isinstance(decoded, dict):
            # A JSON list or a bare null would otherwise reach .get() and raise
            # AttributeError out of a governance SDK, which is neither a useful
            # diagnosis nor a type any caller is prepared to catch.
            raise TISUnavailable(
                f"TIS returned {status} with a non-object body: {raw[:200]!r}"
            )

        if status == 200:
            token = decoded.get("txn", "")
            # Type-checked, not just truth-checked. {"txn": true} is truthy and
            # would install a binding whose header value blows up inside the
            # user's HTTP client, at the call site, having passed through the
            # part of the system that was supposed to validate it.
            if not isinstance(token, str) or not token:
                raise TISUnavailable(
                    f"TIS returned 200 with an unusable txn: {token!r}"
                )
            return token

        error = decoded.get("error", f"HTTP {status}")
        # 422 is the narrow-only refusal specifically (the proxy distinguishes it
        # from a malformed request precisely so this side can). Reported as its
        # own type because it is the one failure a developer is meant to fix in
        # their code rather than in their deployment.
        if status == 422:
            raise ScopeNarrowingRefused(error)
        raise TISUnavailable(f"TIS refused {path}: {error}")
