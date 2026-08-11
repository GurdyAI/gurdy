"""Gurdy — provenance enrichment for governed agent traffic.

What this package is (§5.9, ADR-9): the on-ramp. It marks the task boundary,
obtains a transaction credential from the *local* TIS, and stamps it on calls
that go to the proxy. That is all.

What it is not, and cannot become:

- **Not an enforcement point.** The proxy is the authority. Nothing here
  decides, blocks, or delays anything.
- **Not a holder of signing keys.** It asks the local TIS for tokens; it cannot
  make one, and it cannot write a ledger entry.
- **Not a second implementation of anything.** The scope algebra, the policy
  engine and the ledger live in the Go core. Where this package needs an
  answer it asks and reports; a Python copy of a security rule is a Python copy
  that will drift.

Everything it supplies is recorded as **asserted** identity — the agent's own
claim about itself. The proxy records what it *observed* separately, and that
is what policy evaluates on, so an agent cannot pick the identity it is
authorized as. The one thing this package must therefore never do is fabricate
a claim nobody made: outside a task context, a call goes out unenriched, and
the record says attested-coarse instead of naming an agent that was not there.
"""

from ._config import configure
from ._context import (
    TXN_HEADER,
    Binding,
    adopt,
    carrier,
    current,
    detached,
    headers,
    using,
)
from ._errors import (
    GurdyError,
    NotConfigured,
    ScopeNarrowingRefused,
    TISUnavailable,
)
# Safe to import eagerly: _httpx imports httpx inside client()/async_client(),
# so nothing here touches the optional extra until someone asks for a client.
from ._httpx import async_client as httpx_async_client
from ._httpx import async_hooks as httpx_async_hooks
from ._httpx import client as httpx_client
from ._httpx import hooks as httpx_hooks
from ._task import derive, spawn, start_task, task
from ._threads import ThreadPoolExecutor, bound, instrument_threading
from ._tis import Scope

__all__ = [
    "TXN_HEADER",
    "Binding",
    "GurdyError",
    "NotConfigured",
    "Scope",
    "ScopeNarrowingRefused",
    "ThreadPoolExecutor",
    "TISUnavailable",
    "adopt",
    "bound",
    "carrier",
    "configure",
    "current",
    "derive",
    "detached",
    "headers",
    "httpx_async_client",
    "httpx_async_hooks",
    "httpx_client",
    "httpx_hooks",
    "instrument_threading",
    "spawn",
    "start_task",
    "task",
    "using",
]

__version__ = "0.1.0"

