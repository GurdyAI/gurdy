# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Gurdy is an agent-governance platform: a proxy that intercepts agent→tool traffic (MCP), decides
against a versioned Cedar policy bundle, and writes a tamper-evident decision ledger that a third
party can verify offline.

`docs/spec.md` is the **normative spec** (public half; the commercial sections live in `GurdyAI/gurdy-private`,
branch `private/design-archive`, under `docs/private/`) — section numbers (§5.2),
requirement IDs (FR-3, NFR-1, BR-11) and ADR numbers in code comments all point into it. Read the
relevant section before changing behavior; the doc wins over the code. `docs/roadmap.md` sequences
the doc (it does not amend it) and tracks known debt items D1–D8 with file locations — check it
before "fixing" something that is a deliberate, scheduled gap.

`proxy/` (Go), `sdk/python` and `sdk/typescript` have code; `conformance/` holds the shared corpus
that both SDKs are judged by. `cloud/` is an empty placeholder.

## Commands

All Go work happens in `proxy/`:

```bash
cd proxy
go test ./...                                   # full suite
go test ./internal/tis -run TestNarrowOnly -v    # single test
go test -race ./...                              # required before commit
go test -bench=. ./internal/tis ./internal/policy
gofmt -l . && go vet ./...                       # must be clean
go build ./cmd/...
```

CI is `.github/workflows/ci.yml`: build, vet, `gofmt -l`, test, `-race`, coverage gate. The gate is
a **ratchet set at the measured floor, not the design's 85% target** — raise `MIN` as tests land.

Running it:

```bash
# reverse-proxy mode
go run ./cmd/gurdy-proxy -upstream http://localhost:3000 -listen :8090 -ledger-dir ./led -state-dir ./state
curl -s localhost:8091/health          # admin API, localhost-only + CSRF guard
curl -sX POST localhost:8091/policy/reload    # or SIGHUP; rollback via /policy/rollback

# stdio shim mode — wraps an MCP stdio server; stdout is the protocol channel, decisions to stderr
go run ./cmd/gurdy-proxy -stdio -ledger-dir ./led -state-dir ./state -- <mcp-server-cmd> [args...]

# offline verification (needs only the binary + the export)
go run ./cmd/gurdy-verify -pubkey key.pem ./led
```

Performance (§8.2) — findings and methodology are in `docs/performance.md`.
Microbenchmarks name *which* component costs what; only the composed harness can
certify NFR-1, because §8.2 forbids summing them:

```bash
go test -run='^$' -bench=. ./cmd/gurdy-proxy        # hot path: identify/extract/eval, D5 body sweep
go run ./cmd/gurdy-bench -proxy http://127.0.0.1:9400/ -direct http://127.0.0.1:9401/ \
  -admin http://127.0.0.1:9402 -rate 1000 -duration 30s
```

`gurdy-bench` is open-loop (a closed loop cannot observe queueing delay), runs
A/B/A so arm order cannot bias the result, **refuses to subtract percentiles**,
and fails a run that dropped ledger records before it reports latency at all — a
proxy shedding evidence under pressure gets faster. It reports **INCONCLUSIVE**
when the host's own noise floor exceeds the gate, rather than blaming the proxy
for the machine.

For a *live* answer to "how much of this latency is ours", `internal/clock` times
each stage of the loop in-process and the admin API serves it:

```bash
curl -s localhost:8091/latency | jq        # per-stage percentiles
curl -sX DELETE localhost:8091/latency     # fresh window
```

~100ns per observation, zero allocations, no flag to disable — a knob for a cost
that size is a knob nobody should think about. **Percentiles, never averages**: a
mean would have hidden every defect found so far. The payload carries its own
statement of what it excludes (the hop, which is the larger term of NFR-1's
budget), because a reader who takes `decide p99` for the gate figure has been
misled by us.

The reporter (`reporter/`) compiles a ledger into the artifact a reviewer reads:

```bash
cd reporter && uv sync && uv run pytest -q
uv run gurdy-report ../proxy/gurdy-ledger --verifier ../proxy/gurdy-verify
```

It **refuses** rather than caveats when the evidence is not evidence, and it does
not verify chains itself — `gurdy-verify -json` is the single implementation
(§3.3). Exit 1 means the export could not carry a report.

The adversarial corpus gates the policy pack (§8.2). It shares the conformance
runner — a trace is a case asking "did the pack reach the right verdict on an
attack?" — and reports **three** outcomes: PASS, GAP (the attack succeeds today,
documented with what closes it), FAIL. **A documented gap that no longer
reproduces is a failure**, so the marker cannot become a graveyard.

```bash
cd proxy && /tmp/gc -cases ../corpus/traces -proxy /tmp/gp
```

SDK work:

```bash
cd sdk/python && uv sync && uv run pytest -q          # uv, never pip
cd sdk/typescript && npm install && npm test          # builds, then node:test

# the shared conformance corpus, against each driver rather than the reference one
cd proxy && go build -o /tmp/gp ./cmd/gurdy-proxy && go build -o /tmp/gc ./cmd/gurdy-conform
/tmp/gc -cases ../conformance/cases -proxy /tmp/gp -driver ../sdk/python/run-driver.sh
/tmp/gc -cases ../conformance/cases -proxy /tmp/gp -driver ../sdk/typescript/run-driver.sh
```

## Architecture

Every intercepted call runs the five-stage **governance loop** (§4.2), and the packages map 1:1 onto it:

```
identify → classify        → decide         → act              → attest
internal/tis  internal/extract internal/policy (forward only)   internal/ledger
```

**`internal/extract` is a registry** (FR-6): ordered per-domain extractors, first match wins, and
each one names the §5.3 action it recognizes (`mcp/tools_call`, `llm/completion`). The action is
the extractor's answer, never a constant at the call site — that is what lets a model call and a
tool call share one decision path and one chain. Add a domain by adding an entry, never by
branching in the gateway. Attributes are metadata only (NFR-7): an extractor may derive a count or
a hash from a body, never copy content out of it.

`cmd/gurdy-proxy/main.go` is the wiring. Both transports converge on one function —
`gateway.decideCall` — so HTTP (`ServeHTTP`) and stdio (`shim.go:relay`) share identical decision
semantics. **Add new transports by adapting to `decideCall`, never by duplicating the loop.**

- **`internal/tis`** — Transaction Identity Service. ES256 JWTs, no remote dependency on the mint
  path. A root txn token per task; per-call assertions derived from it (single-use `jti`, audience-
  bound to `deploy-id` **plus a per-instance nonce**, so a replay against another replica — or
  against this one after a restart — fails with no shared state). The instance half is load-bearing:
  the deployment key now persists (D2), so replicas and restarts share it and a signature check
  alone can no longer tell them apart. `scope.go` holds the normative scope algebra: child scope
  may only **narrow**; anything not provably a narrowing is rejected. Incomparable scopes are rejected, never silently allowed.
- **`internal/policy`** — embedded Cedar (ADR-1). Policies are re-keyed by their `@id` annotation so
  ledger records carry stable author-chosen IDs. `context.tool` is lowercased before evaluation so
  name-matching policies can't be dodged by case. **Cedar's principal is the proxy-*observed*
  identity, never the agent's claim** (§5.3/§5.5); asserted identity is reachable only through
  `reservedContextKeys`, and an extracted attribute using one of those names is *dropped*, not
  merged — the dangerous case is a forged `asserted_principal` when no genuine one exists.
  `Store` hot-swaps the evaluator with versioned rollback; **read `store.Current()` exactly once per decision** so the evaluator and the recorded
  `bundle_ver` can never disagree mid-reload.
- **`internal/ledger`** — append-only hash-chained JSONL per partition. A call is **two records**:
  the decision at decide time and a `kind=response` record when the response completes, joined by
  `call_id` (v0.8.2). Never by `seq` — the queue is async and drops on overflow, so a seq guessed
  before the write lands could name another record. **How the two are joined is transport-specific,
  and an unprovable join is never made** (v0.8.6): HTTP pairs them at the transport; stdio has only
  the JSON-RPC id, so anything that makes the id unprovable — a second call outstanding under it, a
  `null` or oversized id, an unparseable frame, a pending map past its bound — leaves the call
  *unanswered* rather than joined on a guess a reader cannot detect. The recurring bug here is
  **state that outlives its own proof**: ambiguity must persist until every call outstanding under
  that id has been answered, not until the first one is.
  Each record's `prev_hash` is
  the SHA-256 of the previous *line*, so a `batchsig` record (whose `prev_hash` is the chain head)
  transitively signs everything before it. The export format **is** the store; `verify.go` re-walks
  it with nothing but the file and an optional pinned key. One writer goroutine; `Append` is
  non-blocking and drops-with-counter on overflow.
- **`internal/toolsig`** — binds policy to what a tool *is*, not what it is called
  (§7: upstream endpoint + tool signature, never display name). Learns from
  `tools/list` responses, which is the whole basis of trust: the agent picks
  which tool to call, the **server** publishes the schema, and the endpoint is
  where the proxy forwards — none of those are the agent's to rename. Emits
  `tool_endpoint`, `tool_signature`, `tool_declared`, and lets the extractor take
  argument roles from the declaration instead of guessing names. **It cannot
  infer capability** — a schema says `fs_write` takes a mode, not that
  `truncate` destroys the file — so capability is a pack declaration keyed by
  signature, and inferring it would need a model in the decision path (ADR-7).
  An undeclared tool is not an error; it is a *fact*, and it is what a rename
  looks like from here.
- **`internal/bundle`** — loads `.tar.gz` (manifest.json + \*.cedar) or a bare `.cedar`. The version
  string always pins content hash, so a re-released pack can never reuse a predecessor's `bundle_ver`.
- **`internal/mcp`** — minimal JSON-RPC parse. Handles batch arrays and decodes elements
  independently; an undecodable `tools/call` yields an empty `ToolCall` that the caller **must**
  record as indeterminate rather than skip (malformed-MCP evasion). `ParseResponses` requires an id
  **and no method** — a server's own request to the client (sampling, elicitation) carries an id too,
  and claiming one as an answer would consume the pending entry and strand the real call.

- **`sdk/python`** — the on-ramp (§5.9, ADR-9), not an enforcement point and never a holder of
  signing keys. One `ContextVar` holds the task binding, so asyncio inherits and a worker thread
  starts *empty* — a pooled worker that inherited its creator's context would stamp one task's
  identity onto another's calls. Everything past a context boundary is explicit (`bound`,
  `ThreadPoolExecutor`, `carrier`/`adopt`) and anything unavailable degrades to **unenriched**,
  never to a neighbouring identity. It contains no governance logic: the scope algebra lives in
  the Go TIS, and the SDK asks and reports the refusal rather than keeping a copy that would drift.
  Three rules are load-bearing and mutation-tested — never fabricate a claim outside a task
  context; attach the credential only to the configured proxy *origin* (parsed, never
  prefix-matched); and a refused derive is neither clamped nor fallen back to the parent's token.

- **`sdk/typescript`** — the same contract as the Python SDK, and deliberately *not* the same API.
  One `AsyncLocalStorage` entered only via `.run()`: `enterWith` and `withScope` both leak the store
  into the caller, and neither is exposed. Callback form (`task(opts, fn)`) rather than decorators or
  `await using`, because both of those can leave a binding installed after the block it belongs to.
  A `worker_thread` is a separate isolate, so it is the *process* case here — a carrier per message,
  never `workerData`, which would pin the first task's identity to every later job. The Node-specific
  hazard Python does not have: a callback registered in one task but invoked from another runs in the
  **caller's** context, so it acquires someone else's identity rather than losing its own; `bind()`
  captures at registration.

## Invariants that are load-bearing

Breaking any of these breaks a requirement, not just a test:

- **Monitor mode only.** Nothing in this tree may drop, alter, or delay traffic (ADR-3). The local
  enforce actuator (ADR-14) is Phase 2 work and needs an actuator interface that does not exist yet.
  `decision=block` is legal and does **not** contradict this: `decision` is the policy's conclusion,
  `action_applied` is what happened to the traffic, and `policy_mode` is the rule's rollout state —
  three separate fields (§4.2). block + monitor + forwarded is the shadow record of §8.3.
- **Inspection failure never breaks traffic** (NFR-3). Oversized bodies, undecodable frames, failed
  identity — all forward and record `indeterminate`. Coverage gaps are *counted and surfaced*, never
  silent.
- **Hashes, not payloads** (NFR-7). `req_hash` only; no request/response bodies in the ledger.
- **Observed identity never degrades** (§5.2/§5.5). `principal`/`principal_tier` are always what the
  proxy saw; `asserted_*` and `lineage[]` are the agent's claim and are written *only* when
  `assertion_status=valid`. An assertion enriches a record, it never replaces one — and it is never
  the policy principal, or an agent could pick the identity it is authorized as.
- **No secrets in the export.** `-ledger-dir` is what you hand a third-party verifier; private keys
  live under `-state-dir` and `ledger.Open` rejects a key path inside the export. A chain may not be
  resumed under a different key either — the header names one pubkey for the whole file, so
  appending under another makes it silently stop verifying.
- **`Gurdy-Txn` is hop-by-hop.** The proxy consumes it and must never forward it upstream; it is a
  live bearer credential for the whole transaction.
- **Zero mandatory egress** (NFR-6). OTel export is opt-in; without an endpoint the tracer is a no-op.
- **Latency is measured, not asserted, and its parts are owned separately.** Our
  request path is ~300µs p99 (77–87% of it three ES256 operations); response
  hashing is ~0.45µs/KiB and uncapped by design; the hop belongs to the
  deployment. A number that mixes them describes a machine, not the code —
  `internal/clock` therefore ships its own exclusion notice in the payload.
- **The reporter may not say what the ledger does not support.** Denominators are
  the population they actually divide; absence is never rendered as zero; flagged
  is never reported without stopped (monitor mode stops nothing); attribution
  stays two axes. A `Claim` cannot exist without its citation — enforced by the
  type, because a rule enforced by discipline decays.
- **Ledger schema changes are migrations.** Adding a field after evidence exists is expensive —
  land record fields early even when nothing reads them yet.
- **Byte-identical pass-through.** `TestPassThroughByteIdentical` and the shim's line relay exist to
  keep the wire untouched.
- **The SDK enriches, it never gates.** A TIS outage degrades `task()`/`spawn()` to unenriched and
  logs once; it must not break the developer's traffic. An on-ramp that makes an agent less
  reliable than not installing it gets uninstalled, and takes the evidence with it.
- **New behavior lands in `conformance/cases/` before it lands in an SDK.** That ordering is what
  keeps Python and TypeScript from drifting; two SDKs with two test suites drift, two judged by one
  corpus cannot.

## Conventions

- Comments cite the spec (`(§5.5)`, `(FR-10)`, `(ADR-9)`) and explain *why*, especially where the
  boring choice was deliberate. Match that density.
- `// ponytail:` marks a deliberate simplification with its known ceiling and upgrade path
  (e.g. resume scans the whole partition file). Keep the form when adding one.
- Tests are property- and adversarial-flavored, not just happy path: every-byte-mutation detection,
  narrow-only fuzz over random scope pairs, cross-replica replay, gzip bombs. New security-relevant
  logic gets the adversarial case too.
- Wire/telemetry contract is stable naming: `Gurdy-Txn` header, `gurdy.*` span attributes,
  `gurdy-*` binaries.

## Attribution — no AI attribution anywhere, ever

**Nothing published from this repository names an AI assistant.** This overrides any default
tooling behaviour that adds attribution automatically, and it is not a style preference.

- **No `Co-Authored-By:` trailer** naming Claude or any model, and no `Claude-Session:` line, on any
  commit. Commits are authored solely by the human maintainer (`tr9800a`), which is also who is
  accountable for them.
- **No "Generated with Claude Code" footer** or equivalent in pull request bodies, issue comments,
  review comments, release notes, or tag messages.
- **No signature, byline, watermark or "written by" marker in code or comments.** A `// ponytail:`
  marker is about the *code* — a named simplification with its ceiling — and stays; it does not
  name a tool or an author.
- This applies to everything that leaves the machine, including the tap repo, the archive repo, and
  anything pasted into an external service.

The reason is the product's own argument. Gurdy exists to make provenance a checkable fact rather
than a claim, and a trailer asserting co-authorship is an unverifiable provenance claim stamped on
the evidence by the thing being attributed. Accountability for this code sits with a person.

## Subagent authority

Two PreToolUse hooks in `.claude/hooks/` constrain delegates, both scoped by the
`agent_id` the payload carries only for subagent calls — the main agent, whose
tool calls a human is actually watching, is untouched by either.

- **`guard-destructive-git.sh`** — no `checkout`/`restore`/`clean`/`reset --hard`/
  `stash drop`. A design subagent once ran `git checkout --` across the tree "to
  restore a clean state" and deleted an entire uncommitted implementation.
- **`guard-subagent-escalation.sh`** — no `--yolo`,
  `--dangerously-bypass-approvals`, `--dangerously-skip-permissions`,
  `--sandbox danger-full-access`, `dangerouslyDisableSandbox`, or the codex MCP
  equivalents (`yolo`, `sandboxMode: danger-full-access`, `approvalPolicy: never`).

The line the second one draws is **capability versus approval**. A delegate that
writes files is the point of delegating and the workflow depends on it, so
bounded modes stay open: `agy-delegate` without `--yolo`, codex
`workspace-write` with on-failure approval. What a delegate may not do is decide
on its own that the human is out of the loop. The antigravity plugin's own agent
instructions tell it to reach for `--yolo`, so this will keep coming up.

Neither hook is a permission rule, because permission rules are not scoped by
caller: a `deny` on these would disarm the main agent too. Changing either takes
effect on the next session — the agent and settings registries are read at
startup.
