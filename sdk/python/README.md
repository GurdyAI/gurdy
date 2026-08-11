# gurdy — Python SDK

The on-ramp. It marks the task boundary, obtains a transaction credential from
the local TIS, and stamps it on calls that go to the proxy.

It is **not** an enforcement point, it **never holds signing keys**, and it
contains **no governance logic** (§5.9, ADR-9). The proxy is the authority.

```python
import gurdy

@gurdy.task(agent="orchestrator", human_actor="alice@example.com")
def handle(ticket):
    client.post("/", content=tool_call)          # enriched automatically

    with gurdy.spawn(agent="fetcher", scope=narrower):
        client.post("/", content=tool_call)      # lineage: orchestrator > fetcher
```

Configuration is environment-first: `GURDY_PROXY_URL` and `GURDY_TIS_SOCKET`,
or `gurdy.configure(proxy_url=..., tis_socket=...)`.

## What it records, and what it cannot

Everything this SDK supplies is **asserted** identity — the agent's own claim
about itself. The proxy separately records what it *observed*, and that is what
policy evaluates on, so an agent cannot pick the identity it is authorized as.

The consequence worth internalising: **the SDK never fabricates a claim.**
Outside a task context a call goes out unenriched and the ledger records an
attested-coarse principal. That is a visible, readable gap. The alternative —
inventing a credential so the record looks complete — would put an assertion
nobody made into evidence a third party is meant to be able to trust.

## Propagation: what is automatic, and what is not

This table is the honest part of this README. A silently lost lineage is worse
than a documented gap, because the record would then attribute a sub-agent's
action to nobody while the developer believes instrumentation is on.

| Boundary | Carries the context? | How |
|---|---|---|
| Ordinary calls inside a task | **Yes** | `ContextVar` |
| `asyncio.create_task`, `gather`, `TaskGroup` | **Yes** | asyncio copies the context at task creation |
| `threading.Thread` | No, by default | `gurdy.bound(fn)`, or `gurdy.instrument_threading()` |
| `ThreadPoolExecutor` | No, by default | `gurdy.ThreadPoolExecutor`, or `gurdy.instrument_threading()` |
| `loop.run_in_executor` | No, by default | `gurdy.bound(fn)`, or `gurdy.instrument_threading()` |
| `ProcessPoolExecutor`, `multiprocessing`, subprocesses | **No — explicit only** | `gurdy.carrier()` → send → `gurdy.adopt()` |
| A new process (gunicorn/uvicorn worker) | **No** | mark the task boundary again at the request entry point |
| A generator that `yield`s inside a `with gurdy.task(...)` | **Leaks** — see below | put the `with` around the work, not around the yields |

**Generators are the one sharp edge.** Python does not give a generator its own
context, so a binding set inside one stays visible to the caller *between*
yields — where an unrelated task's calls would pick it up. Decorating a
generator function is therefore refused outright, at decoration time:

```python
@gurdy.task(agent="streamer")     # raises TypeError on import
def stream(): yield ...
```

The decorator would otherwise acquire the credential, return the generator
object and exit before a single line of the body ran, leaving the task
unenriched while looking instrumented. Wrap the work instead of the yields.

Two of those deserve their reasoning stated.

**Worker threads start empty on purpose.** A pool thread that inherited
whatever its creator was doing would stamp one task's identity onto another
task's calls. `gurdy.bound` captures in the *submitting* thread, never in the
worker, and clears the binding when there is nothing to carry — so a reused
worker cannot leak the previous task's identity into this one's evidence.

**Process pools are explicit and will stay that way.** Auto-pickling a context
across a fork is the kind of magic that fails silently. A worker that receives
no carrier runs unenriched, which the export shows as attested-coarse rather
than as somebody else's identity.

```python
carried = gurdy.carrier()                    # in the parent
...
with gurdy.adopt(carried):                   # in the worker
    do_work()
```

A carrier holds a live bearer credential for the whole transaction. Treat it as
the secret it is; do not log it.

### `instrument_threading()`

Agent frameworks fan tools out across thread pools you never constructed, so
without patching, lineage stops inside somebody else's executor. With patching,
this package is modifying classes it does not own — which breaks gevent and
eventlet and interacts badly with anything that has already subclassed them.

Neither default is safe enough to choose on your behalf, so it is opt-in:

```python
gurdy.instrument_threading()   # patches threading.Thread and ThreadPoolExecutor
```

## Sub-agents and scope

`gurdy.spawn()` derives a child credential **eagerly**, at the spawn site,
before the block runs. A scope that is not provably a narrowing of the parent's
raises `gurdy.ScopeNarrowingRefused` there and then.

It is never clamped and never falls back to the parent's token. Clamping would
hand back a credential nobody asked for; falling back would record the child's
actions under the parent's identity, which is a *false* lineage rather than a
missing one. The algebra itself lives in the Go TIS — this SDK asks and reports
the answer rather than keeping a second copy of a security rule that would
drift.

## Which calls get the credential

Exactly those whose scheme, host and port match the configured
`GURDY_PROXY_URL`, and whose path sits under its path. One origin, no patterns,
no host list.

`Gurdy-Txn` is a live bearer credential for the whole transaction and the proxy
is the only hop meant to consume it, so a permissive rule here is how a
mis-aimed call hands a credential to an upstream tool server that can then mint
assertions in the agent's name. The matching is done by parsing rather than by
string prefix, because a prefix is wrong in the dangerous direction:
`http://gurdy.internal` is a prefix of `http://gurdy.internal.attacker.example/`,
and configuring the proxy without a port is the ordinary case.

The hook is also *authoritative*, not additive: it removes the header on a
request that should not carry it. That matters on redirects, where httpx copies
headers onto the redirected request — an additive hook would follow a redirect
off the proxy with the credential still attached.

## When the TIS is down

The SDK enriches; it does not gate.

- `gurdy.task()` and `gurdy.spawn()` log once and run the block **unenriched**.
  Your traffic is unaffected; the proxy still observes it and still records an
  attested-coarse principal. An on-ramp that makes an agent less reliable than
  not installing it gets uninstalled, and takes the evidence with it.
- `gurdy.start_task()` and `gurdy.derive()` **raise** `TISUnavailable`. Their
  job is to return a credential and there is no degraded value to return.
- A missing `GURDY_TIS_SOCKET` raises `NotConfigured` either way. That is a
  deployment error, it fails identically every run, and it fails the first time
  anyone tries it — unlike quietly enriching nothing, which lets a whole
  service look instrumented when it is not.

A `spawn()` that cannot derive degrades to **no** binding, never to the
parent's. Running a child under its parent's credential would record the
child's actions as the parent's, and a false lineage is worse than a missing
one.

## Conformance

`conformance_driver.py` runs the shared corpus against this SDK. New behavior
lands in the corpus first, then here — that ordering is what keeps the Python
and TypeScript SDKs from drifting.

```bash
cd proxy && go build -o /tmp/gurdy-proxy ./cmd/gurdy-proxy && go build -o /tmp/gurdy-conform ./cmd/gurdy-conform
/tmp/gurdy-conform -cases ../conformance/cases -proxy /tmp/gurdy-proxy \
    -driver ../sdk/python/run-driver.sh
```

## Not built yet

- **`gurdy.annotate(...)`** (§5.9). Deliberately absent rather than shipped as
  a no-op: `/mint` takes `agent`, `human_actor`, `scope` and `ttl` and there is
  nowhere on the wire for a task description or a ticket ref to go. A function
  that accepted annotations and dropped them would be worse than its absence —
  the developer would believe the ledger had them. Needs a wire change first.
- Framework hooks (LangChain, Claude agent SDK).
- Dev mode: the wheel does not yet bundle the Go core.
