# Gurdy SDK conformance suite

The parity mechanism for the Python and TypeScript SDKs (§5.9). **New behavior
lands here first, then in each SDK** — that ordering is the point. Two SDKs with
two test suites drift; two SDKs judged by one corpus cannot.

## What a case asserts

The **evidence**, never the API. A case says what an SDK must cause to appear in
the ledger — asserted identity, lineage, degrade behavior — and says nothing
about how the SDK spells it. That is what lets one corpus judge Python,
TypeScript and the raw wire protocol, and it is why this suite exists before
either SDK does: the built-in reference driver speaks the wire contract
directly, so every expectation is provably satisfiable by *something*.

A case that over-specifies fails on unrelated changes and gets deleted, so each
one pins the property it is about and leaves the rest unasserted.

## Running it

```bash
cd proxy
go build -o /tmp/gurdy-proxy ./cmd/gurdy-proxy && go build -o /tmp/gurdy-conform ./cmd/gurdy-conform
/tmp/gurdy-conform -cases ../conformance/cases -proxy /tmp/gurdy-proxy            # reference driver
/tmp/gurdy-conform -cases ../conformance/cases -proxy /tmp/gurdy-proxy -driver ../sdk/python/run-driver.sh
/tmp/gurdy-conform -cases ../conformance/cases -proxy /tmp/gurdy-proxy -driver ../sdk/typescript/run-driver.sh
```

Both SDK drivers are invoked through a `run-driver.sh` rather than directly: the
suite runs a driver as a plain executable and gives it no way to say "activate
this virtualenv first" or "build the TypeScript first", so the indirection lives
on each SDK's side and the contract stays "any executable". The TypeScript one
needs `npm install && npm run build` first, and says so rather than building
twelve times.

Each case gets its own proxy, its own ledger and its own upstream: a suite where
one case can see another's evidence cannot tell a leak from a pass. The runner
stops the proxy with SIGTERM so the export is *closed* — signed final batch,
shutdown record — because that is what an auditor is handed, and it verifies the
chain before reading it. Evidence that does not survive `gurdy-verify` is not
evidence, whatever it says.

## The driver contract

A driver is any executable. It receives:

- **stdin** — the case as JSON (`steps` is the part it must execute)
- **`GURDY_PROXY_URL`** — where governed calls go
- **`GURDY_TIS_SOCKET`** — the Unix socket for `POST /mint` and `POST /derive`

It performs the steps in order, writes a **transcript** to stdout, and exits
**0**. A non-zero exit, or no finish within 60s, fails the case.

```json
{"steps": [{"index": 0}, {"index": 1, "refused": true, "reason": "…not a provable narrowing…"}]}
```

One entry per step actually executed. The transcript is structured rather than
free text on purpose: a case whose only evidence is a printed word can be
satisfied by printing that word, and the narrow-only case would then pass
without the driver ever calling derive. The runner checks that each step the
case marks `expect_refused` appears in the transcript, as a refusal, *of that
step*.

The three step kinds:

| Step | Meaning |
|---|---|
| `mint` | Obtain a task credential. `as` names it for later steps. |
| `derive` | Obtain a sub-agent credential from a named parent. `expect_refused: true` means the SDK must surface the refusal — not retry with less scope, not proceed uncredentialed. |
| `call` | Make one governed call. `txn` names a credential from an earlier step, or `none` — no task context. `in` says which execution context to make it from. |

`in` is `thread`, `async`, `process`, or absent for inline. It exists because
§5.9 requires lineage to survive those boundaries and a language runtime is
exactly where it silently does not. The mapping is per language, and the point of
the corpus is that the *evidence* is not:

| `in` | Python | TypeScript |
|---|---|---|
| `thread` | a `ThreadPoolExecutor` worker (no `ContextVar` copy) | a `worker_thread` (a separate isolate; no `AsyncLocalStorage` at all) |
| `async` | an `asyncio` task | an `AsyncLocalStorage` hop through a timer |
| `process` | a `multiprocessing` child | a forked child process |

`thread` is the case where the two languages differ most: Python's threads share
memory and need the context carried, while a TypeScript worker shares nothing and
needs a serialised carrier. Same case, same expected record, different mechanism —
which is exactly what a corpus that asserts evidence rather than API buys. A driver must
genuinely cross the boundary — the reference driver uses a goroutine, which
proves the expectation is satisfiable from the wire contract and nothing more,
since it holds tokens explicitly and no execution context can lose one.

An unknown `in` value fails the case at load rather than being ignored, because
a silently-skipped one would let a propagation case pass while testing nothing.

An SDK driver should exercise the SDK's *public surface* (`@gurdy.task`, the
spawn helper, the instrumented client) rather than re-implementing the wire
protocol. A driver that reimplements the protocol proves the protocol works,
which the reference driver already does; it proves nothing about the SDK.

## Two kinds of case, and why the split is not cosmetic

`"kind": "sdk"` (the default) means the driver runs it. `"kind": "wire"` means
the **runner** runs it, always, whatever `-driver` says — and the output labels
every line `[sdk ]` or `[wire]` so `8 passed` can never be read as *the SDK
passed 8*.

Wire cases pin proxy behavior that no SDK can produce:

- **`forged`** — forging a credential needs a signing key, and §5.9 is explicit
  that the SDK never holds one. An SDK driver could only satisfy it by
  hand-rolling a bypass, at which point every driver runs identical code and
  the "pass" says nothing about the SDK. The runner rejects a case that uses
  `forged` outside `kind: "wire"`, so this cannot creep back.
- **no SDK at all** (case 04) — the claim is about what the proxy records for an
  agent that never installed one. There is nothing for a driver to do.

`none` is the interesting one: it appears in **both** kinds and means something
different in each.

| Case | Kind | What `none` means | What is being tested |
|---|---|---|---|
| 04 | wire | no SDK is installed | the proxy still attributes an attested-coarse principal, and writes no asserted field |
| 08 | sdk | the SDK is installed; this call is outside any task context | the SDK lets the call through unenriched and **does not fabricate** a credential to fill the hole |

Identical evidence, entirely different claim. A fabricated assertion would put a
claim nobody made into the ledger, and only an SDK driver can prove its SDK
doesn't do that — which is exactly why case 08 is not a wire case.

## Adding a case

1. Write the fixture, including `why` — the requirement it pins, in the author's
   words. A case whose reason nobody can restate is a case nobody can safely
   change.
2. Confirm the reference driver passes it. If it cannot, the expectation is not
   satisfiable from the wire contract and the case is wrong, not the SDK.
3. **Break the implementation and confirm the case fails.** Every mutation
   tried against this corpus is caught: on the proxy side, forwarding
   `Gurdy-Txn` upstream (1 case), recording an unverified claim as asserted
   (5), dropping response records (4), and ignoring the SDK's transaction so
   each call gets a fresh one (5); on the SDK side — checked against *both* SDKs — a context that does not
   cross a thread (2), an executor that captures at construction instead of at
   submit (2), a carrier that returns nothing (3), an `adopt` that ignores the
   carrier it was given (3), and a header function that falls back to the last
   binding it saw (2). An assertion nothing can break is
   decoration.

   Write the mutation **from the bug, not from the fix**. Two of the four
   propagation cases passed against the very defect they were named for on the
   first attempt: case 11's first version asserted on the id that overflowed
   rather than one tracked cleanly before it, and case 10 still cannot catch a
   thread-local standing in for a context-local — it says so in its own `why`
   rather than implying coverage it does not have.
