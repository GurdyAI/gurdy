# Gurdy

**A flight recorder for AI agents.** Gurdy sits between your agent and the tools
it calls, decides every call against a policy you can read, and writes a
tamper-evident record that someone who does not trust you can verify offline.

It never blocks anything. Not yet, and not by accident — see
[Monitor mode](#monitor-mode-nothing-here-blocks-traffic).

> **Status: pre-release, Phase 1.** The core works and is tested; packaging,
> release hygiene and the paid layer are not done. There is no `brew install`
> yet — you build it. See [What is not built](#what-is-not-built).

## Five minutes, no infrastructure

You need Go 1.26+ (`proxy/go.mod`). Nothing else — no server, no account, no network.

```bash
git clone https://github.com/GurdyAI/gurdy && cd gurdy/proxy
go build -o /tmp/gurdy-proxy ./cmd/gurdy-proxy
go build -o /tmp/gurdy-verify ./cmd/gurdy-verify
```

Now govern something. `gurdy-proxy -stdio` wraps any MCP server as a subprocess
and relays its protocol untouched — so `cat` stands in as a server that echoes
whatever you send it:

```bash
cd /tmp && mkdir -p demo && cd demo

echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/me/.ssh/id_rsa"}}}' \
  | /tmp/gurdy-proxy -stdio -ledger-dir ./ledger -state-dir ./state -- cat
```

> Keep that JSON on **one line**. MCP stdio framing is newline-delimited, so a
> pretty-printed frame is two incomplete frames: the shim relays them untouched,
> records nothing, and it looks like it worked. (This paragraph exists because
> the first draft of this README got it wrong.)

Two things happen. Your JSON comes back on **stdout**, byte for byte — Gurdy is
in the path and did not touch it. And on **stderr** you get the decision:

```json
{"decision":"flag","policy_ids":["flag-credential-read"],
 "action_applied":"forwarded","principal":"svc:stdio:cat",
 "principal_tier":"attested-coarse","tool":"read_file"}
```

An agent read a private key. That is now written down.

### Check that the record is real

```bash
/tmp/gurdy-verify ./ledger
```

```
OK  ledger/local_stdio_cat-….jsonl: 3 records, 1 decisions, 1 batch signatures
    chain: tenant=local workload=stdio:cat instance=gurdy-local#01KYG… schema=v1
    head: seq 3 hash 83640c4c7c66be52…
```

`gurdy-verify` needs nothing but the binary and the directory — no server, no
key, no network. That is the point: the export **is** the evidence, and anyone
can re-walk its hash chain and check its signatures. Hand someone the folder and
they can check your work without trusting you.

Try breaking it. Change one character inside any record and run `gurdy-verify`
again; it will name the record where the chain stops.

### Read it as a report

```bash
cd gurdy/reporter && uv sync
uv run gurdy-report /tmp/demo/ledger --verifier /tmp/gurdy-verify
```

You get Markdown a person can read, with every claim citing the ledger records
it rests on — and a JSON sibling for tooling (`--json`). It **refuses** to
produce a report from an export that fails verification, because a report over
unverified records looks exactly like a report over sound ones.

## What just happened

Every intercepted call runs five stages (§4.2):

```
identify  →  classify  →  decide   →  act       →  attest
who was    what kind    Cedar       forward      append a
this?      of call?     policy      (always)     signed record
```

- **identify** — a proxy-observed principal, always. If your agent uses a Gurdy
  SDK it also carries an *asserted* identity and a lineage of which sub-agent
  spawned which. The two are recorded separately and the observed one never
  degrades, so an agent cannot choose the identity it is authorised as.
- **classify** — an extractor names the action (`mcp/tools_call`,
  `llm/completion`) and pulls out metadata: which tool, which path, which model.
  Never payload content.
- **decide** — embedded [Cedar](https://www.cedarpolicy.com/). Local,
  deterministic, sub-millisecond. No network call, no model.
- **act** — forwards. Always, today.
- **attest** — appends to a hash-chained, batch-signed JSONL ledger.

## Monitor mode: nothing here blocks traffic

This is a deliberate architectural property, not a missing feature.

A record can say `decision: block` — that means *a policy concluded it would
have blocked*. What actually happened is a separate field, `action_applied`, and
today it is always `forwarded`. A third field, `policy_mode`, says whether the
rule was enforcing or shadowing.

Three fields, because collapsing them is how a monitoring tool starts making
enforcement claims it cannot support. Local blocking is Phase 2 and it is free
and open-source when it lands (ADR-14).

**So a report saying "37 violations" must also say how many were stopped. Ours
does. None were.**

## The two modes

**stdio shim** — wraps a local MCP server, zero infrastructure. What you just
ran. stdout is the protocol channel; decisions go to stderr.

```bash
gurdy-proxy -stdio -ledger-dir ./led -state-dir ./state -- your-mcp-server --flags
```

**Reverse proxy** — sits in front of an HTTP MCP server or a model API.

```bash
gurdy-proxy -upstream http://localhost:3000 -listen :8090 \
            -ledger-dir ./led -state-dir ./state
curl localhost:8091/health     # admin API, localhost-only
curl localhost:8091/latency    # what the proxy itself costs, per stage
```

## Policy

The bundled starter pack (BR-11) is three rules in
[`proxy/internal/policy/starter.cedar`](proxy/internal/policy/starter.cedar):
credential reads, destructive filesystem operations, and model calls to
unlisted hosts. Point `-policy` at your own `.cedar` file or a `.tar.gz` pack to
replace it.

```cedar
@id("flag-credential-read") @enforce_action("flag") @on_error("open")
forbid (principal, action == Action::"mcp/tools_call", resource)
when { context has resource_path && context.resource_path like "*/.ssh/*" };
```

`@enforce_action` is the graduation knob: `"block"` makes the record read *would
have blocked* today, and blocks once the Phase 2 actuator exists.

**We publish what our own pack does not catch.** [`corpus/`](corpus/) holds 27
replayable attack traces, and seven of them are attacks that currently succeed —
each with why, and what would close it. Run them:

```bash
cd proxy && go build -o /tmp/gc ./cmd/gurdy-conform
/tmp/gc -cases ../corpus/traces -proxy /tmp/gurdy-proxy
```

## SDKs

Optional. Without one, Gurdy still records every call against a coarse principal
derived from the environment. With one, you also get the agent's own claim about
who it is and which sub-agent spawned which.

Point them at a running proxy with `GURDY_PROXY_URL` and `GURDY_TIS_SOCKET`
(the proxy prints the socket path at startup), then mark the task boundary once:

```python
import gurdy                                    # sdk/python
with gurdy.task(agent="orchestrator", human_actor="alice@example.com"):
    ...                                          # calls inside carry lineage
```

```ts
import * as gurdy from '@gurdy/sdk';            // sdk/typescript
await gurdy.task({ agent: 'orchestrator' }, async () => { ... });
```

Both are judged by [one shared corpus](conformance/) so they cannot drift.
Neither holds signing keys, neither decides anything, and neither can fabricate
a claim: outside a task context a call goes out unenriched.

## Repository

| | |
|---|---|
| [`proxy/`](proxy/) | the Go core — proxy, identity, policy, ledger, verifier |
| [`sdk/python`](sdk/python/), [`sdk/typescript`](sdk/typescript/) | provenance enrichment |
| [`reporter/`](reporter/) | ledger → readable governance report |
| [`conformance/`](conformance/) | the shared corpus both SDKs must pass |
| [`corpus/`](corpus/) | adversarial traces that gate the policy pack |
| [`docs/`](docs/) | the [normative spec](docs/spec.md), [roadmap](docs/roadmap.md), [performance](docs/performance.md), [activity log](docs/activity-log.md) |

`docs/spec.md` is normative — section numbers in
code comments point into it, and the doc wins over the code.

## What is not built

Stated plainly because a governance tool that overstates itself has picked the
wrong thing to be bad at:

- **No packaging.** No `brew`/`npm`/`pipx` install, no signed binaries, no SBOM.
  You build from source. (§3.J)
- **No blocking.** Monitor only. Phase 2. (ADR-14)
- **No framework hooks.** No LangChain or Claude-agent-SDK integration yet, and
  the SDKs do not bundle the Go core for dev mode. (§3.F)
- **Seven known attack gaps**, published in [`corpus/`](corpus/) rather than
  quietly omitted. Five share one root cause: controls match on strings the
  agent chooses.
- **The paid layer does not exist** — no framework-mapped report, no pack
  registry, no fleet control plane.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
