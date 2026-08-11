# @gurdy/sdk — TypeScript SDK

The on-ramp. It marks the task boundary, obtains a transaction credential from
the local TIS, and stamps it on calls that go to the proxy.

It is **not** an enforcement point, it **never holds signing keys**, and it
contains **no governance logic** (§5.9, ADR-9). The proxy is the authority.

Node-only (`node:async_hooks` and an AF_UNIX socket), ESM-only, no runtime
dependencies.

```ts
import * as gurdy from '@gurdy/sdk';

await gurdy.task({ agent: 'orchestrator', humanActor: 'alice@example.com' }, async () => {
  await gurdy.fetch(`${proxy}/`, { method: 'POST', body: toolCall });   // enriched

  await gurdy.spawn({ agent: 'fetcher', scope: narrower }, async () => {
    await gurdy.fetch(`${proxy}/`, { method: 'POST', body: toolCall }); // orchestrator > fetcher
  });
});
```

Configuration is environment-first: `GURDY_PROXY_URL` and `GURDY_TIS_SOCKET`, or
`gurdy.configure({ proxyUrl, tisSocket })`.

## What it records, and what it cannot

Everything this SDK supplies is **asserted** identity — the agent's own claim
about itself. The proxy separately records what it *observed*, and that is what
policy evaluates on, so an agent cannot pick the identity it is authorized as.

The consequence worth internalising: **the SDK never fabricates a claim.**
Outside a task context a call goes out unenriched and the ledger records an
attested-coarse principal. That is a visible, readable gap. The alternative —
inventing a credential so the record looks complete — would put an assertion
nobody made into evidence a third party is meant to be able to trust.

## Read this section first: the callback that runs somewhere else

This is the Node-specific failure mode, and it is the dangerous kind. A callback
registered inside a task but *invoked* from elsewhere runs in the context of
whoever called it — so it does not lose the binding, it acquires **someone
else's**:

```ts
await gurdy.task({ agent: 'alpha' }, async () => {
  emitter.on('tool', handler);           // registered as alpha
});
await gurdy.task({ agent: 'beta' }, async () => {
  emitter.emit('tool');                  // handler runs as BETA
});
```

`AsyncLocalStorage` has no way to know the handler was written for alpha. Bind it
at registration:

```ts
emitter.on('tool', gurdy.bind(handler));  // runs as alpha, wherever it is fired
```

The same applies to stream handlers (`data`, `end`, `error`), and to any callback
you hand to a library that stores it and calls it later. `gurdy.bind` also
*clears* the binding when there is none to carry, so a callback written outside
any task cannot pick up the identity of the code that ends up invoking it.

## Propagation: what is automatic, and what is not

| Boundary | Carries the context? | How |
|---|---|---|
| `await`, `.then`, promise combinators | **Yes** | `AsyncLocalStorage` |
| `setTimeout`, `setImmediate`, `queueMicrotask`, `process.nextTick` scheduled inside the task | **Yes** | same |
| `EventEmitter` / stream callbacks | **No — runs in the emitter's context** | `gurdy.bind(handler)` at registration |
| A callback stored by a library and invoked later | **No — same reason** | `gurdy.bind(handler)` |
| `worker_threads` | **No — explicit only** | `gurdy.carrier()` → `postMessage` → `gurdy.adopt()` |
| `child_process`, `cluster` | **No — explicit only** | same |
| A new process (a server worker) | **No** | mark the task boundary again at the request entry point |

**A worker thread is not a Python thread.** It is a separate isolate with its own
`AsyncLocalStorage`, so it is closer to a *process*: nothing propagates
implicitly and nothing should pretend to.

```ts
worker.postMessage({ job, gurdy: gurdy.carrier() });      // parent, per message

parentPort.on('message', (m) =>                            // worker
  gurdy.adopt(m.gurdy, () => handle(m.job)));
```

**Per message, not `workerData`.** Passing the carrier once at construction pins
the *first* task's identity to every later job a long-lived worker serves, which
is misattribution rather than loss. `adopt` scopes the binding to one callback,
so a worker cannot leak the identity of the job before.

A carrier holds a live bearer credential for the whole transaction. Treat it as
the secret it is; do not log it.

## Which calls get the credential

Exactly those whose **origin** matches the configured `GURDY_PROXY_URL`, with the
path under its path. One origin, no patterns, no host list.

`Gurdy-Txn` is a live bearer credential for the whole transaction and the proxy
is the only hop meant to consume it, so a permissive rule is how a mis-aimed call
hands a credential to an upstream tool server that can then mint assertions in
the agent's name. `URL.origin` is the comparison because a string prefix — which
the Python SDK shipped first, and which leaked — is wrong in the dangerous
direction: `http://gurdy.internal` is a prefix of
`http://gurdy.internal.attacker.example/`, and `http://gurdy.internal@attacker.example/`
has the configured value as a prefix and someone else's host.

`gurdy.fetch` is **authoritative** about the header: it sets it on a governed
request and *removes* it from any other, including one a caller attached by hand.

**A governed request will not follow a redirect.** `Gurdy-Txn` is a custom
header, so the Fetch standard does not strip it on a cross-origin redirect the
way it strips `Authorization` — undici re-sends it to whatever `Location` names.
`fetch` offers no per-hop hook to re-check the origin, so a request carrying the
credential is issued with `redirect: "manual"` and the 3xx is handed back to you.
A caller who explicitly asked to follow redirects is overruled: there is no
setting that turns a credential leak into a supported feature.

`gurdy.instrumentGlobalFetch()` replaces `globalThis.fetch` so code this SDK
never sees — the MCP transport, an agent framework — is enriched too. Opt-in, and
never on by default: it is a process-wide change to a function the SDK does not
own.

## When the TIS is down

The SDK enriches; it does not gate.

- `gurdy.task()` and `gurdy.spawn()` log once and run the callback
  **unenriched**. Your traffic is unaffected; the proxy still observes it and
  still records an attested-coarse principal. An on-ramp that makes an agent less
  reliable than not installing it gets uninstalled, and takes the evidence with
  it.
- `gurdy.startTask()` and `gurdy.derive()` **reject**. Their job is to return a
  credential and there is no degraded value to return.
- A missing `GURDY_TIS_SOCKET` rejects with `NotConfigured` either way — a
  deployment error, deterministic, and it surfaces the first time anyone tries it
  rather than at 3am.

A `spawn()` that cannot derive degrades to **no** binding, never to the parent's.
Running a child under its parent's credential would record the child's actions as
the parent's, and a false lineage is worse than a missing one.

## Sub-agents and scope

`gurdy.spawn()` derives **eagerly**, before the callback runs. A scope that is
not provably a narrowing of the parent's rejects with `ScopeNarrowingRefused`
there and then — never clamped, never falling back to the parent's token. The
algebra itself lives in the Go TIS; this SDK asks and reports the answer rather
than keeping a second copy of a security rule that would drift.

A partial `scope` object is sent **verbatim**, missing keys and all. An absent
dimension is the *bottom* of that dimension server-side, so a partial scope
narrows a wildcard one. Filling the gaps with `"*"` would silently widen what you
wrote; use `gurdy.WILDCARD_SCOPE` when wildcards are what you mean.

## Why a callback, and not a decorator or `await using`

`AsyncLocalStorage` is callback-scoped, so `task(opts, fn)` is the only shape
with no way to leave a store installed after the block it belongs to. Both
alternatives have one: a decorator evaluates at definition time rather than call
time, and an `await using` resource that is never disposed — a bare
`taskResource()` without the `await using` — leaves the binding in the caller.
Both failures are misattribution, which is the one outcome this design will not
trade for ergonomics.

## Development

```bash
npm install && npm test          # builds, then runs node:test

# the shared conformance corpus
cd ../../proxy
go build -o /tmp/gp ./cmd/gurdy-proxy && go build -o /tmp/gc ./cmd/gurdy-conform
/tmp/gc -cases ../conformance/cases -proxy /tmp/gp -driver ../sdk/typescript/run-driver.sh
```

New behavior lands in the corpus first, then here — that ordering is what keeps
this SDK and the Python one from drifting.

## Not built yet

- Framework hooks (the MCP TypeScript SDK transport, LangChain.js).
- `gurdy.annotate()`: `/mint` takes agent, humanActor, scope and ttl, and there
  is nowhere on the wire for a task description or ticket ref to go. Shipped as a
  no-op it would be worse than absent, because you would believe the ledger had
  it. Needs a wire change first.
- Dev mode: the package does not yet bundle the Go core.
- An undici interceptor applying the header rules on every hop of a redirect
  chain, which is the complete version of what `redirect: "manual"` currently
  refuses.
