# Gurdy — Technical Specification

**Normative.** Section numbers (§5.2), requirement IDs (FR-3, NFR-1) and ADR
numbers appearing in code comments point here. Read the relevant section before
changing behavior: the doc wins over the code.

**Section numbering has gaps, and they are deliberate.** This is the public,
technical half of a larger design document. Commercial sections — market
positioning, the business-requirements register, packaging economics, the
open-core boundary's rationale, and the phase-by-phase go-to-market — are
maintained separately and are not published. Numbering is preserved rather than
compacted so that every `§x.y` citation in the code still resolves to the
section it was written against.

The public statements those private sections are cited for are collected in
§0 below, so nothing in this document depends on a reference a reader cannot
follow.

---

## 0. Referenced elsewhere

Code and docs cite a handful of requirements and decisions whose full reasoning
is commercial. Their operative content is stated here in full; only the
rationale is held back.

- **BR-5 — every decision must be independently verifiable.** Signed,
  hash-chained, exportable, and checkable by a third party with nothing but the
  export and `gurdy-verify`. This is the requirement §5.5 exists to satisfy.
- **BR-11 — the free tier must stand alone.** A local flight recorder for agent
  tool calls that is useful to a developer with no compliance obligation at all:
  local ledger, local verification, local report, bundled starter policies, and
  local blocking. No account, no egress.
- **ADR-13 — Apache-2.0 for all open-source components.** The grant boundary is
  drawn at the repository, not argued file-by-file; proprietary artifacts live
  in a separate repository.
- **ADR-14 — local, single-instance enforcement is free and open-source.** The
  paid boundary is *fleet* scale — central ledger, fleet policy distribution,
  fleet-wide rollout and rollback — delivered as the separately-distributed
  `gurdy-fleet`. The capability is free; the coordination is paid. ADR-3's
  monitor-first posture is unchanged and remains the recommendation.

---

## 3. Technical Requirements

### 3.1 Functional requirements

| ID | Requirement |
|---|---|
| FR-1 | Intercept MCP protocol traffic (stdio and HTTP/SSE transports) between agent frameworks and MCP servers without agent-side code changes |
| FR-2 | Wrap arbitrary HTTP tool endpoints via reverse-proxy mode when MCP is not in use |
| FR-3 | Mint a transaction-scoped credential (JWT, ES256) per task initiation; derive per-call child assertions carrying the provenance chain |
| FR-4 | Record provenance: initiating human principal, agent ID, sub-agent lineage, tool, resource identifiers, data classification tags |
| FR-5 | Evaluate every intercepted call against a versioned Cedar policy bundle; produce decision ∈ {allow, flag, block*, rewrite†, escalate†} (*enforcement mode, available in all tiers per ADR-14; †deferred, see §1.2) |
| FR-6 | Resolve policy-relevant attributes from tool calls (tool, action, resource identifiers, arguments) sufficiently to evaluate policy scope, via **pluggable per-domain extractors** — filesystem paths, HTTP hosts, DB tables/queries, cloud-API actions for the general packs; FHIR resource type / patient compartment / search params as the first vertical example |
| FR-7 | Append every decision to a hash-chained, signed ledger; emit an OTel span per decision joining the customer's existing trace |
| FR-8 | Generate monthly (and on-demand) governance/evidence reports mapping decisions to the active pack's control framework (NIST AI RMF / ISO 42001 for general governance; HIPAA Security Rule control IDs in the healthcare vertical), with violation narratives |
| FR-9 | Serve a read-only dashboard: live decision stream, violation summaries, provenance drill-down, policy version in force |
| FR-10 | Support policy bundle hot-reload with versioned rollback; every decision records the bundle version that produced it |
| FR-11 | Fail-mode behavior configurable **per policy** (fail-open with alert vs. fail-closed), not globally. **Default is fail-open on a local single-instance install** — a fail-closed policy plus a crashed proxy breaks a developer's agent, which is an unacceptable free-tier failure mode; fail-closed is opt-in per policy and the expected posture for high-risk classifications in a supervised deployment. Every decision records `fail_mode_applied` |
| FR-12 | Export: full ledger dump (JSONL + chain proofs) and report artifacts (HTML/PDF) via CLI |

### 3.2 Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-1 | Latency | **Now binds the free tier** — since local enforcement is OSS (ADR-14), the enforcement-path budget is a free-tier release gate, not only a paid-deployment one. **Sidecar/tap (guaranteed):** ≤3ms p50 / ≤5ms p99 added per call on the enforcement path; ≤0.5ms tap-mode overhead. **In-cluster reverse proxy (measured, best-effort — not gated):** reported per release; the extra pod-to-pod hop consumes most of the p99 budget. Per-call hot path = hop + derive + extract + eval; **mint is per-task and amortized, not per-call**. Composed p99 is measured under concurrency in the reverse-proxy topology (§8.2), never inferred by summing standalone microbenchmarks |
| NFR-2 | Throughput | Sustain 1,000 decisions/sec per proxy instance (≈10× projected 50-agent fleet load) |
| NFR-3 | Availability | Proxy stateless & horizontally scalable; no central synchronous chokepoint; monitor mode fails open by definition |
| NFR-4 | Integrity | Ledger tamper-evidence verifiable offline by third party from export alone |
| NFR-5 | Key handling | Signing keys minted/held locally (in-memory or customer KMS-wrapped at rest); no per-call network KMS dependency; rotation ≤24h |
| NFR-6 | Deployability | Single Helm chart / Compose file; air-gap-friendly (no mandatory egress); runs on 2 vCPU / 4GB per proxy instance |
| NFR-7 | Data handling | Request/response payloads stored only as hashes + extracted policy-relevant attributes by default; full-payload capture is opt-in per policy |
| NFR-8 | Observability | All components emit OTel traces/metrics/logs; guardrail spans join the upstream agent trace via propagated context |
| NFR-9 | Supply chain | Signed container images, SBOM published, pinned dependencies; reproducible builds for the open-source components |
| NFR-10 | Compatibility | MCP spec version pinned per release with a compatibility matrix; graceful degrade to generic HTTP mode on unknown extensions |

### 3.3 Constraints

- Two-person, part-time founding team → bias every choice toward boring, embedded, operationally quiet components
- No vendor-side data plane → all analytics must run customer-side or on exported, customer-approved artifacts
- Design partner infra is heterogeneous (AKS, EKS, on-prem OpenShift likely) → Kubernetes-first but Compose-capable
- Languages: Go for the governance core (proxy, TIS, policy host, ledger); Python for the reporter and the SDK's developer-facing layer — two languages maximum. **Single-implementation rule:** credential minting, policy evaluation, and ledger logic exist exactly once, in Go; no Python reimplementation ever. The SDK's dev-mode inline shim satisfies this by bundling the Go core as a platform binary inside the wheel, launched as a local subprocess (ruff/esbuild pattern) — the Python layer is transport and ergonomics only

---

## 4. Top-Level Design

### 4.1 Architecture overview

```
CUSTOMER ENVIRONMENT (laptop / VPC / cluster) ─────────────────────────────┐
│                                                                          │
│  ┌─────────────┐        ┌──────────────────────────────────────┐         │
│  │ Human       │ task   │  Agent Runtime (LangChain/Claude/    │         │
│  │ Initiator   ├───────▶│  custom orchestrator, sub-agents)    │         │
│  └─────────────┘        └───────────────┬──────────────────────┘         │
│                                         │ MCP / HTTP tool calls          │
│                                         ▼                                │
│                          ┌──────────────────────────┐                    │
│                          │  INTERCEPTOR PROXY (Go)  │  sidecar or        │
│                          │  ┌────────────────────┐  │  in-cluster        │
│    Policy bundles ──────▶│  │ TIS: txn identity  │  │  reverse proxy;    │
│    (versioned, signed)   │  │ PEP+PDP: Cedar     │  │  tap mode = mirror │
│                          │  └─────────┬──────────┘  │                    │
│                          └───┬────────┼─────────────┘                    │
│              pass-through /  │        │ decision events (async)          │
│              enforce         ▼        ▼                                  │
│                   ┌──────────────┐  ┌──────────────────┐                 │
│                   │ MCP servers/ │  │ DECISION LEDGER  │──▶ OTel spans   │
│                   │ tools / APIs │  │ (hash-chained,   │    to customer  │
│                   └──────────────┘  │  signed, append- │    collector    │
│                                     │  only)           │                 │
│                                     └────────┬─────────┘                 │
│                                              ▼                          │
│                       ┌─────────────────┐  ┌────────────────────┐        │
│                       │ DASHBOARD (RO)  │  │ GOVERNANCE REPORTER│        │
│                       └─────────────────┘  │ (framework ctrl map)│       │
│                                            └────────────────────┘        │
└──────────────────────────────────────────────────────────────────────────┘
   Vendor side (general-market tier): reporting dashboard (Cloudflare), policy pack
   registry, licensing, signed counts-only usage transmissions for metering (opt-in,
   inspectable) — NEVER decision payloads or sensitive data. Air-gapped tranche omits all egress.
```

### 4.2 Framework: the governance loop

Every intercepted call passes through five stages; this loop is the conceptual spine and the vocabulary used throughout:

1. **Identify** — resolve/mint the transaction identity; extend the provenance chain
2. **Classify** — extract policy-relevant attributes (tool, action, resource, arguments, data classification — e.g. file path, host, DB table; patient compartment in the healthcare vertical)
3. **Decide** — evaluate against the versioned policy bundle (deterministic, local, sub-ms)
4. **Act** — pass-through + annotate (monitor) or block (enforce). **Three distinct things must never be conflated, and each is recorded separately (§5.5):** the policy's `decision` (what the rule concluded), the policy's `policy_mode` at the time (monitor / warn / enforce), and the `action_applied` (what the actuator actually did). A `decision=block` under `policy_mode=monitor` yields `action_applied=forwarded` — that combination is the entire content of shadow mode, and an evidence record that cannot express it is ambiguous exactly where it matters most
5. **Attest** — append signed decision to ledger; emit span; feed reporter

### 4.3 Data flow (monitor mode, happy path)

1. Human initiates task → SDK/hook requests transaction credential from TIS (or proxy auto-mints on first unseen task ID)
2. Agent issues MCP `tools/call` → proxy intercepts
3. Proxy derives per-call assertion (child of txn credential), extracts attributes (FR-6)
4. Cedar evaluates → `allow` or `flag` annotation
5. Decision record appended to ledger; OTel span emitted with trace context propagated from the agent's own trace
6. Request forwarded unmodified; the response is hashed as it streams to the caller (never buffered) and a `kind=response` record, joined to the decision by `call_id`, is appended when it completes (§5.5)
7. Reporter aggregates ledger monthly → evidence package

### 4.4 Deployment topologies

| Topology | When | Latency | Notes |
|---|---|---|---|
| **Inline sidecar, monitor mode** | **Default** for partners with any enforcement intent | ~0.1–0.5ms hop | In the request path but pass-through + annotate; 100% capture fidelity. Same observability as tap, but graduating to enforce is a per-policy **config flip** (§8.4), *not* a topology change. Fails open on crash (NFR-3) |
| Inline sidecar, enforce mode | After monitoring earns trust; **no paid component required for a single instance** (ADR-14) | ~0.1–0.5ms hop | Destination posture; per-policy staged rollout. Coordinating that rollout *across a fleet* — staged graduation, fleet-wide rollback, central attestation of what was in force where — is `gurdy-fleet` |
| In-cluster reverse proxy | Simpler estates; shared proxy | 1–2ms hop | Single Deployment; HPA on RPS; the extra hop makes NFR-1 best-effort, not guaranteed (§3.2) |
| Passive tap (traffic mirror) | Path-averse estates; monitor-only / never-enforce buyers | ~0 | A *copy* of traffic — **cannot ever enforce** (physics, not config). Capture is best-effort (≤99.5%, §8.3). **Tap→enforce is a topology migration** (reroute + fresh security review + change window), not a flag flip — budget it as a distinct trust milestone. First-class for the strictest estates |
| stdio shim | Local/desktop MCP servers | ~0 | Wraps MCP server process; dev & demo mode |

---

## 5. Component Specifications

### 5.1 Interceptor Proxy (`gurdy-proxy`) — Go, open-source

**Purpose:** transparent interception of agent→tool traffic; hosts PEP and embedded PDP.

**Interfaces**
- Ingress: MCP over HTTP/SSE; MCP over stdio (shim mode); generic HTTP reverse proxy
- Egress: upstream MCP server / tool endpoint (unmodified)
- Control: gRPC admin API — health, policy bundle load/version, mode (tap/inline/enforce), drain
- Emits: decision events (protobuf) → ledger writer (async, batched, bounded queue)

**Key behaviors**
- Parses MCP frames; extracts `tools/call` name, arguments, resource URIs; **attribute extractors are pluggable per-domain modules** — v1 ships the general extractors (filesystem, HTTP/host, DB, cloud-API) that back the `agent-security` pack, plus FHIR R4 as the first vertical extractor
- Propagates W3C `traceparent` from agent request into decision span (NFR-8)
- Unknown/undecodable traffic: forwarded and logged `decision=indeterminate` with reason (monitor); per-policy fail mode (enforce)
- Bounded decision queue: on overflow, monitor mode drops-with-counter (never blocks traffic); enforce mode applies per-policy fail mode
- Config: single YAML; hot-reload via SIGHUP/admin API
- **Enforcement actuator is a plugin interface (ADR-11, amended by ADR-14):** the PEP calls out to a pluggable actuator. The free OSS base ships **two** actuators: *monitor* (pass-through + annotate, the default) and *local-enforce* (**block only** in v1 — short-circuit the upstream call and return a protocol-level error to the agent). Both are Apache-2.0. Blocking must work on every ingress: the HTTP path short-circuits the reverse proxy, and the **stdio shim synthesizes a JSON-RPC error onto the server's response stream without forwarding to the child**, preserving framing. **Batch semantics are normative:** in a JSON-RPC batch, a blocked call is replaced by an error response element and its siblings are evaluated and forwarded independently — one blocked call never suppresses or silently allows the rest
- **What `gurdy-fleet` adds (paid, separately distributed):** it does not add the ability to block. It adds *fleet coordination* — staged graduation of a policy across many instances, fleet-wide rollback on false-positive spike, central attestation of which bundle was in force on which instance when, and the central ledger those claims are made against. A fork receives the actuator and not the control plane — but see ADR-14: this is an adoption bet, not an unforkable boundary, since fleet coordination is rebuildable work

**Explicit non-goals:** TLS termination beyond standard mesh patterns; content classification; response streaming transformation (v1 passes streams through, evaluates on request + final response metadata)

**Sizing:** 2 vCPU / 512MB baseline; target NFR-1/NFR-2 on that footprint.

### 5.2 Transaction Identity Service (TIS) — Go, embedded in proxy (v1)

**Purpose:** mint and validate ephemeral, transaction-scoped identities; maintain provenance chain.

**Credential model**
- **Transaction token:** ES256 JWT. Claims: `txn_id` (ULID), `sub` (agent principal), `act` (initiating human, OAuth actor-claim style), `scope` (task scope descriptor), `cnf` (optional key binding), `exp` (default 15 min, max 4h), `pol_ver` (bundle version at mint)
- **Call assertion:** derived per tool call, embeds `parent_txn`, `lineage[]` (ordered sub-agent chain), `tool`, `nonce`, `exp` (≤60s). Never reusable: nonce + jti tracked in a short-TTL replay cache
- Keys: per-deployment ES256 keypair, generated at install, private key in-memory / customer-KMS-wrapped at rest; rotation ≤24h with 2-key overlap window; JWKS served on admin API for third-party verification
- **No remote dependency on the mint path** (NFR-5): mint/derive signing is performed by the local TIS from locally available key material; the synchronous signing path must not depend on IdP, KMS, or other remote network services. **SDK-to-local-TIS IPC is allowed** — §4.3 and §5.9 both require the SDK to request a credential at task start, and that request is not what this rule forbids

**Provenance rules**
- Sub-agent spawn requires parent's live txn token; child lineage = parent lineage + child ID; **scope may only narrow, never widen** (confused-deputy control — enforced at derivation, tested adversarially)
- **Scope descriptor algebra (normative):** scope is a dimensioned object (`compartments`, `resource_types`, `actions`, `purpose`) with a defined partial order per dimension. `child ≤ parent` **iff** `child ≤ parent` on *every* dimension; incomparable pairs count as widening and are **rejected**. Derivation must *reject* (never silently allow) any pair it cannot prove is a narrowing. This decidable order is exactly what the property-based "never widens" test (§8.2) checks — spec lands before Stage B (wk 5)
- **Cross-replica replay binding:** each call assertion is bound to its target via `cnf`/audience, so a captured assertion replayed against a *different* proxy replica fails validation with no shared replay-cache state (keeps NFR-3 stateless); the ≤60s jti+nonce cache remains the same-instance defense. The §8.2 replay test fires across two instances
- **Principal attribution answers two independent questions, and one field cannot carry both** (§5.5). *How good is the proxy's own observation* is the **principal tier**; *did an SDK assertion accompany the call, and did it verify* is the separate **assertion status** (`absent` / `valid` / `invalid`). An assertion enriches a record; it never replaces the observation, and the observed principal is recorded on every record.
  - **Asserted** — SDK-supplied agent-side claim: high-fidelity human actor, task scope, purpose. **Not a principal tier** — it is recorded in the `asserted_*` fields alongside the observed principal, never as it
  - **Attested** — proxy-observed infrastructure-side fact: the traffic itself, always captured, *never degrades*
  - **Attested-coarse** — when no SDK credential is present, the proxy derives a *coarse* principal from the runtime environment (authenticated upstream session, K8s service account / workload identity, OS user) and records it at lower confidence — SDK-absent traffic still carries *a* principal, usually a service identity
- Only traffic with **no derivable principal at all** degrades to `principal_tier=orphan` — first-class and prominent in reports, because genuinely unattributable agent activity is itself a finding. Cron/batch/service-triggered agents have no human initiator *by definition*; attributing them to a service principal is **correct, not degraded** — the reporter distinguishes "unattributed" (a finding) from "attributed to a non-human principal" (normal)

**v2 seam:** interface designed so SPIFFE SVIDs / OAuth token-exchange can replace self-minted JWTs without changing the assertion contract.

### 5.3 Policy Engine — embedded Cedar (Rust lib via FFI or cedar-go)

**Purpose:** deterministic, local, versioned authorization decisions.

**Decision request schema (entities & context)**
- Principal: the **proxy-observed** principal (§5.5) — never the SDK's claim, so an agent cannot select the identity it is authorized as. The asserted agent, lineage, human actor and scope reach policy as reserved context keys (`context.asserted_principal`, `context.assertion_status`), which is how "policies may require attestation" (§5.9) is written in practice: a rule that trusts an agent-side claim gates on `context.assertion_status == "valid"` explicitly. Extracted attributes may not occupy reserved key names
- Action: tool + operation (e.g., `fs/read`, `http/request`, `db/query`, `mcp/tools_call`, `llm/completion`; `fhir/search`, `fhir/read` in the healthcare vertical)
  - **`llm/completion` is the model call itself** (v0.8.4). The agent's request to a model is an intercepted action like any other, extracted by a per-domain extractor (FR-6) and governed by a policy family, not by a second subsystem — the taxonomy was always tool+operation, and a model is a tool the agent calls. Resource attributes are the model call's *metadata*: provider, model ID, endpoint, streaming, declared token budget. What it buys is a record that reads "this agent, under this human's authority, sent a payload with this hash and this classification to this model" **in the same provenance chain as its tool calls** — which neither an application-layer LLM log nor a tool-only proxy can produce, because neither sees both halves under one identity
- Resource: extracted attributes (e.g., file path, host, DB table, classification tag, endpoint; resource type + patient compartment ID in the healthcare vertical)
- Context: mode, time, deployment ID, bundle version

**Bundle format:** signed tarball — Cedar policies + schema + data classification map + pack manifest (`pack_id`, `version`, `control_map.yaml` linking each policy to regulatory control IDs + justification doc refs). Verified on load; version recorded per decision (FR-10).

**Hard rules**
- No network I/O during evaluation; all context must arrive in the request or in bundle data. External facts (e.g., consent registries) enter via TTL-cached local snapshots refreshed out-of-band — a documented pack pattern, not an engine feature
- **Snapshot freshness is a policy-declared, classification-scoped property:** each externally-sourced fact carries a `max_ttl` per data classification (sensitive categories → tight or zero staleness tolerance). The ledger record captures the snapshot version and its **age at decision time**, so the evidence report *surfaces* freshness rather than hiding it. If a required snapshot exceeds its `max_ttl`, the policy's `on_error` governs (fail-closed for high-risk classifications, e.g. PHI) — the engine never silently evaluates against stale external data
- Every policy declares `on_error: open|closed` and `enforce_action` (FR-11)
- Sub-ms evaluation budget enforced in CI perf tests

### 5.4 Policy Packs

Packs are maintained, adversarially-tested, reviewed policy sets. Three tiers of pack, all sharing the §5.3 bundle format and the authoring workflow below.

**Free starter policies (OSS, bundled with the base):** shallow filesystem / credential / spend protections — the BR-11 flight recorder's defaults. Each declares `on_error` and `enforce_action` like any other policy, so a free-tier user can graduate any of them from flag to local block (ADR-14). These seed the vocabulary; the depth lives in the paid packs.

**Flagship pack A — `agent-security` v1 (proprietary, deep) — the entry paid pack**
- Cedar policies covering: secret/credential exfiltration (reads of credential paths/env, sends to unlisted hosts), destructive filesystem ops (recursive delete, overwrite outside workspace), unauthorized network egress (host/domain allowlisting), prompt-injection-driven tool abuse (tool-call patterns inconsistent with declared task scope), spend/rate limits per task and per fleet
- `control_map.yaml`: each policy → a plain-language security-control statement + rationale; reviewed by a security expert (BR-4), not counsel
- The deep, maintained extension of the free starter policies — this is what a team upgrades to first

**Flagship pack B — `ai-governance` v1 (proprietary, framework evidence)**
- Maps decisions to named AI-governance framework controls — **NIST AI RMF, ISO/IEC 42001, EU AI Act** readiness — and drives the internal AI-governance evidence report (§5.6). The buyer is an org standing up an AI-governance program, not a compliance officer
- `control_map.yaml`: each policy/decision class → framework control ID + justification; the report is the artifact the org shows its own board/auditor

**Vertical packs (later, per-vertical)**
- `hipaa-min-necessary-fhir` is the **first example** vertical pack (healthcare), no longer the reference launch pack: patient-compartment scoping (agent task scope ↔ FHIR compartment), resource-type allowlists per task category, bulk-export (`$export`) restrictions, `_include`/chained-search widening detection, 42 CFR Part 2-adjacent sensitive-category flags; `control_map.yaml` → HIPAA Security Rule citations (§164.308(a)(4), §164.312(a)(1), §164.312(b)) + counsel review record (reviewer, date, scope of opinion, open questions)
- Fintech/SOC2, legal, and others follow the same regimen as design partners materialize; which vertical goes first is partner-driven (OQ #11), not pre-committed

**Authoring workflow (all packs):** policies as code — PR review, staged rollout (monitor → warn → enforce per policy), regression suite of recorded attack traces. Every pack ships an adversarial test corpus (see §8) and its version gates on corpus pass. Vertical/regulated packs additionally gate on the counsel review record; general packs on security-expert review.

### 5.5 Decision Ledger (`gurdy-ledger`) — Go

**Purpose:** tamper-evident system of record; the metering source (BR-8).

**Record schema (JSONL, protobuf-canonical):**

`header` record — `{seq, ts, kind, schema_version, tenant, workload, instance_id, heartbeat_s, kid, pubkey, prev_hash}`

`decision` record — `{seq, ts, kind, call_id, txn_id, assertion_jti, assertion_status, principal, principal_tier, asserted_principal, lineage[], asserted_human_actor, asserted_scope, tool, action, resource_attrs, declared_classification, decision, policy_mode, action_applied, policy_effects[], bundle_ver, fail_mode_applied, req_hash, prev_hash, sig}`

`response` record — `{seq, ts, kind, call_id, resp_hash, status, bytes, prev_hash, sig}`

`coverage` record — `{seq, ts, kind, reason, window_from, window_to, dropped, write_errors, identity_failed, inherited_unsigned, prev_hash, sig}`

`batchsig` record — `{seq, ts, kind, first_seq, kid, prev_hash, sig}`

`finding` record — `{seq, ts, kind, call_id, source, labels[], confidence, classifier_ver, prev_hash, sig}`

- **Observed and asserted identity are separate fields, and the observed one never degrades** (§5.2). A record carries what the proxy saw *and*, separately, what the agent claimed; an SDK assertion enriches a record, it never overwrites one.
  - `principal` — proxy-observed workload/service principal. **This is the policy principal** (§5.3): never taken from an SDK assertion, so an agent cannot choose the identity it is authorized as
  - `principal_tier` — confidence in `principal`: `attested`, `attested-coarse`, `orphan`. This is observation quality, *not* assertion validity
  - `assertion_status` — the SDK transaction assertion: `absent`, `valid`, `invalid`
  - `asserted_principal`, `asserted_human_actor`, `asserted_scope`, `lineage[]` — agent-side claims, **omitted unless `assertion_status=valid`**. Recording an auto-minted lineage as though an SDK supplied it would launder an inference into an assertion
  - Asserted values reach policy only as reserved Cedar context keys (`context.asserted_principal`, `context.assertion_status`), never as the request principal — this is what §5.9's "policies may require attestation" means operationally: a pack that trusts an agent-side claim does so on an explicit, reviewable line

- **The response is a second, chained record, not a field of the first** (v0.8.2). A decision is knowable the moment the policy evaluates; a response is not, and in a streaming or long-poll call it may be minutes away or never arrive. Holding the decision in memory until then would mean the evidence for a call does not exist while the call is in flight — and does not exist at all if the proxy dies mid-response, which is precisely when someone will want it. So the decision record is appended at decide time and a `kind=response` record follows it in the same partition chain, joined by `call_id`.
  - `call_id` — proxy-minted, unique per intercepted call, carried by both records. **Not the decision's `seq`:** the ledger queue is async and drops-with-counter on overflow (§5.1), so a sequence number chosen before the write lands could name a *different* record. `call_id` survives that — a response record whose `call_id` has no decision record is a visible coverage gap, which is the correct reading (§7)
  - A call with no response record is *unanswered evidence*, not a contradiction: the response never arrived, was never captured, or the proxy stopped first. The reporter must show it as such rather than assume success
  - `resp_hash`, `status`, `bytes` only — hashes, not payloads (NFR-7). Response *content* classification is an explicit non-goal (§4.2); `bytes` is carried because response size is the one exfiltration signal a hash cannot reconstruct
  - **How a response is matched to its call is transport-specific, and a match that cannot be proven must not be made** (v0.8.6). On an HTTP ingress the transport pairs them, and a JSON-RPC batch shares one response envelope, so every call in that batch carries the same `resp_hash` — identical hashes on N records state exactly that. On the stdio shim there is no pairing below the protocol: request and response are two independent byte streams, and the **JSON-RPC id is the only join**, which makes per-element correlation possible and a batched call's `resp_hash` as specific as an unbatched one's. Where the id is ambiguous — a client that reuses an id still in flight, an id a peer re-serialized, a frame too large to parse — the call is left **unanswered**, never joined on a guess. Unanswered is a visible missing half that a reader can act on; a response record on the wrong `call_id` is misattributed evidence that a reader cannot detect at all, which is the failure this ledger exists to prevent

- **Coverage gaps are records, not log lines** (v0.8.3, satisfying §7's "detected and surfaced, never silent"). The ledger's own writer goroutine emits them, never the queue — the queue that dropped a record cannot be the path by which the drop is reported. Reasons:
  - `start` — written to the `_proxy` chain when the process opens the export, signed and flushed immediately. Without it a proxy killed inside its first heartbeat window leaves no lifecycle chain at all, and "no chain" reads identically to "no proxy ever ran": the absence of a shutdown record only means something if a start record promised one
  - `resumed` — written when a process continues a chain whose tail no signature covers, carrying `inherited_unsigned`. A crash leaves such a tail legitimately, so resuming cannot be refused — but anyone with file access can append to it, and this process's next signature would cover their records too. The count marks the boundary between what this writer wrote and what it merely inherited; a forged "clean shutdown" appended after a crash sits inside it
  - `gap` — written into **the partition that lost the records**, so the finding sits in the chain it is missing from: `dropped` (bounded-queue overflow, §5.1), `write_errors`, and `identity_failed`, a TIS derive/verify failure internal to the proxy that otherwise shows only as a decision record with empty txn fields. Counts are a signed **lower bound**: a crash before the next emit takes the open window with it
  - `heartbeat` — written into the `_proxy` chain, covering `[window_from, window_to]`. **Span-coalesced, not per-tick:** an idle proxy writes one record per window, because an append-only chain cannot be compacted afterwards — the saving has to happen before the append. The header declares `heartbeat_s`, so a verifier reading the export alone can call any inter-window gap larger than that an interval in which the proxy was not writing evidence. This is §7's "proxy heartbeat whose *absence* the reporter flags"
  - `shutdown` — the last record of the `_proxy` chain on a clean exit. A `start` that follows one is a restart, not a gap: the proxy was not running and said so, and reporting planned downtime as missing evidence would train readers to ignore the finding. **A chain that ends without one ended abnormally**, which is what makes a crash distinguishable from an idle proxy. It lives only in `_proxy`: written per-partition it would brand every evicted-but-healthy partition as an abnormal end
  - Coverage records are signed like any other evidence. "We lost N records" and "this chain ended cleanly" are precisely the claims worth forging, and an unsigned trailing record is forgeable by anyone
  - Stated rather than implied: traffic that never reached the proxy is invisible to all of this by construction (§7 bypass row). Coverage records bound what the proxy *observed and then lost*, not what it never saw

- **Two kinds of classification, and only one may reach a decision** (v0.8.5, resolving an ambiguity in v0.8.4):
  - **Declared** classification is deterministic and comes from the pack: a data-classification map in the bundle resolving a resource to a label (this path is PHI, this table is PII). It is a lookup, it is reproducible, it is recorded as `declared_classification`, and it **may** drive a decision — §7's "fail-closed on high-risk-classified" means this and nothing else
  - **Inferred** classification is a classifier's opinion about content. It is probabilistic, it arrives after the fact as a `finding` record, and it may **never** reach the decision path
  - The distinction is normative because a pack author cannot otherwise tell which is permitted, and the failure mode is silent: a rule written against an inferred label would look like every other rule while making decisions non-reproducible
- **Inferred classification is an async advisory record, never a decision input** (v0.8.4; ADR-7, **permanently**). A classifier — probabilistic by nature — may attach a `finding` record to a call by `call_id`, after the fact. It may never be consulted on the decision path, and a decision record is never rewritten to absorb one. Three consequences the design accepts deliberately:
  - The decision stays deterministic, local and sub-ms (§5.3). A probabilistic verdict inside the decision path would make two runs over identical traffic disagree, which destroys both the latency budget (NFR-1) and the evidence claim a third party is asked to trust
  - A finding is *evidence about* a call, not a *judgement of* it. `labels[]` and `confidence` are the classifier's opinion, `classifier_ver` is what produced it, and the reporter presents them as such — never as "the platform determined X"
  - Findings can therefore arrive late, be reprocessed with a better classifier, or never arrive at all, without invalidating a single decision record. A call with no finding is unclassified, which is a different statement from "classified benign"

- **`policy_effects[]` replaces `policy_ids[]`** (v0.8.5): each determining policy contributes `{policy_id, decision, mode, enforce_action, on_error}`. A record-level `decision` is an aggregate, and staged graduation means several policies with *different* rollout states can fire on one call — a single mode field cannot say which of them was enforcing and which was still shadowing, and that is unreconstructable once the evidence is written. The record-level `decision` / `policy_mode` / `action_applied` remain, as the aggregate of the effects and what the actuator actually did
- **`decision` / `policy_mode` / `action_applied` are three separate fields** (§4.2). `decision` is the policy's conclusion, `policy_mode` is that policy's rollout state when it fired, `action_applied` ∈ {forwarded, blocked, failed-open, failed-closed} is what the actuator did. Without all three the record cannot distinguish "we blocked this" from "we would have blocked this," which is the difference between an enforcement claim and a shadow-mode observation
- **Enforcement records are durable, not best-effort.** The async, drop-with-counter queue (§5.1) is correct for monitor mode and is a documented design position — a dropped *observation* is a counted coverage gap. It is **not** acceptable for an enforced call: blocking something with no record of it, or failing open with no record of it, produces exactly the unattributable action this product exists to eliminate. Any record whose `action_applied` ≠ `forwarded` — and any record produced under a policy in `enforce` mode — is written **synchronously before the actuator's effect is released to the caller**. If that write cannot complete, the policy's `on_error` governs and `fail_mode_applied` records which way it went. Monitor-mode traffic keeps the fast async path; the two paths coexist and the cost falls only on enforced calls

- **The chain says what it is evidence *of*, inside the signature** (v0.8.5). The header carries `tenant`, `workload`, `instance_id` and `schema_version`, because a partition's identity that lives only in a filename is not evidence: a filename is unsigned, and renaming one would silently re-attribute a whole chain to another tenant. `workload` is additionally present in every record as `principal`; `tenant` had no signed representation at all before this amendment
- **`kid` on the header and on every batchsig.** NFR-5's ≤24h rotation with 2-key overlap is unbuildable if a signature cannot say which key made it, and adding the field after evidence exists is a migration. The field lands now; the keyring and the multi-key verifier land with rotation
- **A chain may continue across files, and the seam is an ordinary chain link** (v0.8.7, D14). A partition's export is one append-only file, and at rated load that file grows by ~65 MB/min, so it has to be able to roll. The header therefore carries `segment`; a continuation segment's first record is legitimately not `seq 1`, and its `prev_hash` is the SHA-256 of the previous segment's **last line** — the same rule every other record follows. No separate "previous segment hash" field exists, because it would be the same value under a second name, and two fields that must agree are one field plus a way to disagree. Absent `segment` means 1: chains written before segments existed are the first and only one by construction.
  - **A segment verifies perfectly while everything before it is missing.** This is the property that matters, and it is why verification *reports* what a segment continues from rather than silently resolving it: a verifier handed one file cannot know whether the predecessor exists, and someone handing over segment 5 alone is indistinguishable at the file level from someone whose chain legitimately starts there. Whoever holds the export checks that the predecessor's head hash equals the successor's declared link; nothing else can
  - A continuation that declares **no** predecessor is rejected outright rather than counted — every other "begins mid-stream" case is at least checkable by someone holding the earlier segments, and that one is not
- **Deleting evidence is itself a record** (v0.8.7, D14). Retention is not a config knob that quietly removes old files. A `kind=retention` record, chained and signed like any other, declares what was removed and how far: `pruned_through_seq` and `pruned_through_hash`, the latter making the claim checkable by anyone who still holds the pruned segments. The consequence is the point: **deleting segments without the record leaves a chain whose head links to a line nobody has, which fails verification and should; deleting them with it leaves a signed statement a reader can weigh.** Silent loss and authorised retention are otherwise identical on disk, and only one of them is operations. Retention counts are reported separately from `dropped` — one is loss the writer regrets, the other is deletion someone authorised, and a reader who conflates them learns nothing from either
- Hash chain: `prev_hash = SHA-256(prev_record_canonical)`; chain **partitioned per (tenant, workload)** from v1 so per-partition sequential writes never serialize the fleet (designed now to avoid a v2 migration)
- Signing: batch signatures (per N records or per T seconds) with ES256; periodic checkpoint records anchor chain heads. The per-record `sig` field is **a reference to the batch signature covering that record**, not an independent per-record signature — records within a batch share one signature over their canonical concatenation, and the hash chain provides per-record ordering integrity between signature points. BR-5 ("every decision signed, independently verifiable") is satisfied because every record is covered by exactly one batch signature that `gurdy-verify` checks offline; no record is ever unsigned once its batch closes. The tunable is the signature-window latency (max time a freshly appended record waits before its batch signs), which is bounded by the per-T setting
- Storage: v1 SQLite-per-partition + object-store snapshots; graduation path Postgres → Kafka + object store at ≥1k sustained decisions/sec
- Verification: `gurdy-verify` CLI (open-source) re-walks chain + signatures from export alone — third-party verifiable offline (NFR-4, BR-5)
- Payload policy: hashes + extracted attributes by default; full payload capture opt-in per policy (NFR-7)

### 5.6 Governance/Evidence Reporter — Python

**Purpose:** compile ledger → governance/audit artifact mapped to the active pack's control framework (§5.4). This is what the buyer buys — an internal AI-governance report for general customers, a regulator-legible evidence report in regulated verticals.

**Outputs**
- Monthly + on-demand HTML/PDF: executive summary; control-by-control status (mapped via pack `control_map` — NIST AI RMF / ISO 42001 for general governance, HIPAA controls in the healthcare vertical); violation narratives (what, who—full provenance chain, which policy, which control, recommended remediation); orphan-call findings and a **principal-attribution breakdown**, reported over the two independent axes of §5.5 rather than one blended list: observed principal tier (attested / attested-coarse / orphan) × assertion status (absent / valid / invalid); coverage statement (what % of observed agent traffic was attributable, and at what confidence tier); policy version history in period; chain-integrity attestation for the period
- **Enforcement outcomes (ADR-14):** blocked-vs-flagged counts per policy, each policy's `policy_mode` history over the period, `action_applied` breakdown including fail-open and fail-closed events, shadow-mode diff summary for any policy that is a graduation candidate, and repeated-block patterns that indicate an agent retry loop rather than a single violation. A report that says "37 violations" without saying how many were actually stopped is not an enforcement claim
- Machine-readable JSON alongside every human report (for partner GRC tooling)

**Design rules:** narratives generated from decision data via templates — deterministic, no LLM in the report path (an LLM-written audit artifact undermines the entire independence pitch); every claim in the report links to ledger record seq numbers.

### 5.8 Packaging & install

- **Individual (free tier):** `brew install gurdy` / `npm i -g @gurdy/cli` / `pipx install gurdy` — one static Go binary per platform; fully local: embedded **inline shim** (never a tap — §4.4: a tap cannot enforce, so a tap-shaped dev mode could never deliver BR-11 local blocking), local SQLite ledger, local mini-report, bundled starter policies (filesystem, credential, and spend protections), and the local-enforce actuator (ADR-14). **Retention is manual and included** (author decision 2026-08-10): the local admin API's `POST /retention/prune` is free, because the free tier writes the same ledger at the same rate (D14: ~92 GB/day at NFR-2's rated load) and a user with no supported way to reclaim disk deletes the export by hand, destroying the chain — the exact outcome the signed retention record exists to prevent. What is *not* free is retention as a **policy**: schedules, per-tenant rules and fleet-wide application are `gurdy-fleet`. Same shape as ADR-14 draws for enforcement — the capability is free, the coordination is paid, and requiring a human to ask is the free tier's deliberate friction rather than a limitation. No account, no egress, no telemetry without opt-in
- **Team/enterprise (paid):** Helm chart (preferred) and Docker Compose profile; single `values.yaml` decision surface: topology (sidecar/proxy/tap), fail modes default, retention **policy** (scheduling and fleet-wide application of the pruning the free tier performs by hand — see the free-tier bullet above), IdP. Paid entitlements are delivered as **proprietary artifacts the customer receives** — central ledger, fleet policy distribution, packs, evidence reporting — not as flags flipped in open code
- **Fleet governance is a separate install (ADR-14):** `gurdy-fleet` is a distinct, signed, proprietary component delivered only to paid customers, comprising the fleet control plane and the central ledger it attests against. An estate without it can monitor and can block locally, but cannot graduate a policy across a fleet, roll a fleet back, or produce a central attestation of what was in force where. The boundary is *what is distributed*, consistent with ADR-8 — a fork gains the actuator, never the control plane
- **Licensing (ADR-13):** every OSS artifact above is Apache-2.0. Proprietary artifacts (`gurdy-fleet`, the packs, the evidence reporter) live in a **separate repository** so the Apache grant boundary is unambiguous at the repo level rather than argued file-by-file. `NOTICE` in the OSS repo states the split explicitly
- **Platform matrix (v1):** macOS (arm64 + x64) and Linux (x64 + arm64) are the supported native targets for the free-tier binary and the SDK-embedded core. **Windows is deferred to Phase 2** — interim guidance is WSL2 (Linux binary) with a documented native-Windows build item; a sizable share of developers (and most enterprise/regulated desktops) run Windows, so this is a known gap tracked in §9, not an oversight
- Signed images and binaries + SBOM (NFR-9); zero mandatory egress in all tiers (NFR-6). Because the SDK-embedded core ships as a **prebuilt per-platform Go binary inside the wheel/npm package** (§3.3), reproducibility is preserved by building each platform artifact from a pinned toolchain in a hermetic pipeline, publishing a per-artifact SBOM, and recording the embedded binary's content hash in the package manifest — so the core bundled in `pip`/`npm` is byte-for-byte reproducible and independently attestable, not an opaque blob riding inside a language package
- `gurdyctl` CLI: install preflight, bundle push, ledger export, verify, report trigger — same binary in both tiers

### 5.9 SDKs (`gurdy` for Python, `@gurdy/sdk` for TypeScript) — open-source (ADR-9)

**Purpose:** the five-minute on-ramp and provenance enrichment layer, in the two languages that cover the agent-development ecosystem (TS dominates MCP tooling; Python dominates data-science and ML estates). Explicitly **not** enforcement points — the proxy remains the authority (ADR-9). Both are thin shims over the identical wire contract and the bundled Go core (§3.3 single-implementation rule); neither contains governance logic. Both ship simultaneously at launch (OQ #7, resolved); Phase 1 budget extended to ~15 weeks accordingly. Parity is enforced by a **shared conformance suite**: a language-agnostic set of scenario fixtures (wire-contract request/response transcripts, provenance-propagation cases incl. async models, degrade behaviors) that both SDKs must pass — new behavior lands in the conformance suite first, then in each SDK.

**Developer surface**
- `@gurdy.task(scope=...)` decorator (and context-manager equivalent): mints/requests the transaction credential at task start via TIS, binds it to the execution context
- Automatic provenance propagation: sub-agent spawns and tool-client calls inside a task context inherit and extend `lineage[]` without further developer code; framework hooks for LangChain and Claude agent SDK ship in v1
- `gurdy.annotate(...)`: optional context enrichment (task description, ticket ref, data-purpose tag) attached to the txn

**Modes**
- **Dev mode (default when no proxy configured):** embedded **inline local shim, not a tap** — the wheel bundles the Go governance core as a platform binary, launched as a local subprocess on first use. **This must be inline (ADR-14):** §4.4 is explicit that a tap can never enforce (physics, not config), so an embedded *tap* would leave the free tier's five-minute on-ramp structurally unable to deliver the local blocking BR-11 and §5.8 promise. The dev-mode shim therefore sits in the call path — monitor by default, capable of local block when a policy is graduated (per §3.3 single-implementation rule; no Python reimplementation of mint/eval/ledger). Decisions evaluated locally against a bundled sample pack, mini-report rendered to file. Zero infrastructure; this is the demo and the OSS hook
- **Production mode:** SDK propagates context headers to the deployed proxy; all evaluation, ledgering, and enforcement happen at the chokepoint. **The SDK does not need manual attachment to every process:** the task boundary is marked once at the entry point (one decorator/context-manager or a framework hook) and `lineage[]` propagation carries identity down the whole call tree automatically; import-time auto-instrumentation of the MCP/HTTP clients (the `ddtrace`/OTel pattern) reduces the developer ask to "install + env var". SDK absence does **not** blank out provenance — the proxy-attested layer always captures the traffic, and the proxy records an **attested-coarse** principal derived from the environment (§5.2). Only traffic with no derivable principal at all is a bare orphan. High-confidence *human* attribution is what requires SDK/entry-point instrumentation; orphan-rate is therefore a human-attribution-*coverage* metric

**Trust model (normative)**
- SDK-supplied context is recorded as **asserted** (agent-side claim); proxy-observed facts are recorded as **attested** (infrastructure-side); an environment-derived principal recorded when no SDK is present is **attested-coarse** (§5.2). The decision record and evidence report distinguish all three; policies may require attestation for sensitive classifications
- The SDK never holds signing keys and cannot produce ledger entries in production mode

**Non-goals:** client-side blocking **in production mode** (the proxy remains the authority and the enforcement point — ADR-9 is unchanged by ADR-14; dev mode blocks because the embedded core *is* the proxy on that machine, not because the SDK gained enforcement powers), policy evaluation in production mode, any behavior whose absence weakens the audit claim.

## 6. Key Design Decisions (condensed ADRs)

| # | Decision | Alternatives considered | Rationale | Revisit when |
|---|---|---|---|---|
| ADR-1 | Embed Cedar as PDP | OPA/Rego; custom DSL; LLM-judge | Formally analyzable, sub-ms, governance-legible RBAC/ABAC semantics that read cleanly whether the pack is `agent-security` or a regulated vertical; custom DSL is undifferentiated work; LLM-judge breaks latency + determinism + audit defensibility | If partner GRC standardizes on Rego |
| ADR-2 | Self-minted ES256 JWTs (v1) | SPIFFE/SPIRE day one; OAuth token exchange | SPIRE is operationally heavy for partners' first two weeks (violates BR-2); JWT keeps mint path local (NFR-5); assertion contract designed for swap | Phase 3, partner infra permitting |
| ADR-3 | Monitor-first; **inline-sidecar-monitor is the default entry posture**, passive tap reserved for path-averse / never-enforce buyers | Enforce day one; tap-first for everyone | Nobody lets a startup block hospital traffic on day one; monitoring output *is* the sales artifact. Inline-monitor gives the same observability while keeping graduation to enforce a per-policy *config flip* (no topology migration) and 100% capture fidelity for shadow analysis (**local graduation and shadow diff: §8.3; fleet-wide graduation: §8.4**). Tap stays first-class for estates that reject path presence, but tap→enforce is a topology migration that must be budgeted (§4.4) | Never — graduation model is permanent; tap-vs-inline default revisited only if a partner segment shifts |
| ADR-5 | Go proxy + Python reporter, nothing else | Rust; Node; single language | Solo maintainability > peak performance; Go covers NFR-1/2 with headroom; Python owns document generation | Team ≥3 engineers |
| ADR-6 | Per-partition hash chains from v1 | Single global chain (simpler) | Global chain serializes writes and forces a painful migration exactly when traction hits (§ ledger spec) | N/A — cheap now |
| ADR-7 | No LLM anywhere in decision or report path | LLM-judge rails; LLM-drafted narratives | Determinism, latency, and the independence pitch all die otherwise; probabilistic checks belong async, out-of-band, later. **Reaffirmed permanent in v0.8.4** when `llm/completion` made model calls a governed action: governing model traffic is exactly the context in which "just have a model judge the payload" becomes tempting, and it is exactly where it must not happen. A classifier attaches a `finding` record after the fact (§5.5); the decision path never reads one | **Never** for the decision path. The async advisory lane itself lands Phase 3+ |
| ADR-9 | SDK as on-ramp, proxy as authority — one wire contract | SDK-only (max adoption simplicity); proxy-only (max control, no dev hook) | An SDK lives inside the process being audited: a compromised or prompt-injected agent can bypass its own instrumentation, so SDK-only breaks the independence and completeness claims (self-reported provenance = the homegrown weakness we differentiate against). Proxy-only sacrifices the five-minute developer experience that creates internal champions. Split the roles: SDK owns adoption, identity binding, and provenance *enrichment* (recorded as asserted); proxy owns interception, evaluation, and attestation (recorded as attested). Datadog ships SDKs because it sells observability; Okta doesn't ship client-side auth because it sells control — this product is Okta-shaped. | If MCP or agent frameworks gain a native, verifiable in-process attestation primitive |

---

> ADRs 4, 8, 10, 11, 12, 13 and 14 concern the commercial model. Their
> operative decisions are stated in §0; the reasoning is not published.

## 7. Threat Model & Failure Semantics (summary)

**Adversaries considered:** malicious/compromised agent (prompt-injected), over-scoped sub-agent (confused deputy), insider modifying logs, network attacker replaying assertions, operator misconfiguration.

| Threat | Control | Verified by |
|---|---|---|
| Scope widening via sub-agent spawn | Narrow-only derivation rule (TIS) | AT-corpus §8.4 |
| Assertion replay across txns | jti+nonce replay cache, ≤60s exp | AT-corpus §8.4 |
| Tool aliasing / name spoofing to dodge policy | Policy binds to upstream endpoint + tool signature, not display name | AT-corpus §8.4 |
| Ledger tampering | Hash chain + batch signatures + offline third-party verifier | Integrity tests §8.3 |
| Bypass by routing around proxy | Deploy-time NetworkPolicy templates (egress only via proxy); orphan-call detection as compensating control | Deployment tests §8.5 |
| Key exfiltration | In-memory keys, ≤24h rotation, KMS-wrap at rest | Key lifecycle tests §8.3 |
| Proxy crash (monitor) | Fails open by definition; gap **detected out-of-band** (decision volume reconciled against the agent's propagated OTel trace volume, or a proxy heartbeat whose *absence* the reporter flags) and recorded as a coverage finding — never silently indistinguishable from "no traffic" | Chaos tests §8.4 |
| Proxy crash (enforce) | Per-policy fail mode (FR-11): fail-closed on high-risk-classified (e.g., PHI in the healthcare vertical, credential/destructive ops in `agent-security`), fail-open+alert on low-risk. **Now also a free-tier concern** (ADR-14): a local single-instance install defaults to fail-open precisely because an unsupervised developer machine has no operator to notice a fail-closed stall | Chaos tests §8.4 |
| **Governed agent disarms its own enforcement via the local admin API** — a prompt-injected agent on the same host calls `POST /policy/rollback` or `/policy/reload` and removes the policy that would have blocked it | **Created by ADR-14 and currently unmitigated.** The admin API is localhost-bound with a CSRF/DNS-rebinding guard, which stops a *browser*, not a process that already runs on the box — and the governed agent always does. Under monitor this is a log-integrity problem; under local enforce it is a total enforcement bypass. Required before local enforce ships: authenticate mutating admin routes with a token readable only by the installing user, drop the agent's ability to read it, and record every bundle change as a ledger record so a disarm is at minimum *evident* even if not preventable | Local-enforce security tests §8.3 |
| Agent retries a blocked call until it succeeds, or reroutes to an unproxied path | Block is recorded per attempt, so repeated blocks are visible as a pattern rather than absorbed silently; egress NetworkPolicy and orphan detection remain the compensating controls for the reroute case | AT-corpus §8.4 |

**Bypass on a local install (ADR-14).** In a cluster the "route around the proxy" threat is answered by deploy-time NetworkPolicy templates. **A laptop has no NetworkPolicy.** A free-tier user's agent can often simply talk to the MCP server directly, so local enforcement is a control over a *configured* path, not a sealed one. The compensating controls are configuration-shaped — install-time MCP client config rewriting so the proxy is the configured endpoint, plus orphan/coverage detection that makes an un-proxied path visible in the local report — and they are weaker than the cluster story. Say so to free-tier users rather than implying a laptop is sealed.

**Model calls (v0.8.4).** `llm/completion` extends the chokepoint from tool traffic to the agent's model traffic, so both halves of what an agent did sit under one identity in one chain. The same boundary applies as to any other action: a model call that does not traverse the proxy is invisible, exactly like an un-proxied tool call, and the compensating controls are the same configuration-shaped ones (§7 bypass row). Governing the model call is not content inspection — the decision sees metadata (provider, model, endpoint, payload hash), and any judgement about *what was in* the payload arrives later as an advisory `finding` (§5.5, ADR-7).

**Honest limitation (documented for partners):** the platform governs the tool-call chokepoint. Agent-internal reasoning, side channels outside intercepted paths, and un-proxied egress are out of scope; orphan detection and network policy are compensating, not complete. Human attribution is tiered: high-confidence human identity requires SDK/entry-point instrumentation; SDK-absent traffic still receives an **attested-coarse** service principal from the environment (§5.2); only wholly unattributable traffic is a bare orphan. Orphan-rate is therefore a human-attribution-*coverage* metric — driving it down is an instrumentation goal, not a silent gap. This candor is a sales asset with security buyers, not a weakness.

---

## 8. Test Plan by Phase

### 8.2 Phase 1 — Core build (weeks 1–15, gates per build stage)

**Unit (continuous):**
- Proxy: MCP frame parsing (valid/malformed/truncated/unknown-version), attribute extraction per domain extractor (filesystem paths, HTTP hosts, DB queries, cloud-API actions; FHIR read/search/`_include`/chained/`$export`/batch bundles as the vertical example), traceparent propagation, bounded-queue overflow behavior
- TIS: mint/derive/verify round-trips, expiry, narrow-only scope derivation (property-based: generated scope pairs must never widen), rotation overlap window, replay cache eviction
- Ledger: canonicalization stability, chain append/verify, partition isolation, batch signature boundaries
- Policies: Cedar unit tests per policy — allow case, deny case, boundary case, error-mode case

**Integration (per stage exit):**
- Stage A (wk 3): proxy pass-through vs. direct baseline — byte-identical upstream behavior, latency delta measured
- Stage B (wk 5): txn mint → call assertion → provenance visible in decision record, incl. 3-deep sub-agent chain
- Stage C (wk 7): bundle load/hot-reload/rollback; decision carries correct `bundle_ver` across reload mid-traffic
- Stage D (wk 9): ledger export → `gurdy-verify` passes on a machine with no product installed (the independence test)
- Stage E (wk 12): full demo scenario — scripted dangerous tool calls (secret read, destructive fs op, egress to unlisted host) produce expected `agent-security` flags with full provenance

**Performance (wk 10–12, gate on NFR-1/2):**
- Microbench: mint, derive, Cedar eval each <1ms p99 standalone
- Load: 1k decisions/sec sustained 30 min per instance, p99 added latency ≤5ms, zero decision loss (monitor: drop counter = 0 at target rate)
- **Composed p99 under concurrency, per topology:** run the full hot path (hop + derive + extract + eval) under concurrent load in **both** sidecar and in-cluster-reverse-proxy topologies. The ≤5ms p99 gate is enforced for sidecar/tap and *measured/reported (not gated)* for reverse-proxy. **Never certify NFR-1 by summing standalone microbenchmarks** — mint is per-task (amortized) and excluded from the per-call budget; derive+extract+eval+hop are the per-call cost, and tail latencies compound worse than linearly under contention
- Fan-out burst: 20 parallel synthetic sub-agents × 50 concurrent calls — no queue overflow, correct lineage on every record **carrying a valid assertion** (lineage is an asserted field and is omitted otherwise, §5.5); mint/derive is spawn-time work and is measured separately from the per-call hot path

**SDKs (wk 10–15, both languages against the shared conformance suite):**
- Unit: decorator/wrapper txn binding; lineage propagation across each language's async models — Python: threads, asyncio, process pools; TS: promise chains, async_hooks/AsyncLocalStorage continuity, worker_threads (the known-hard cases, and they fail differently per language); graceful degrade when proxy unreachable; asserted-vs-attested labeling on every enriched field
- Integration: dev-mode inline local shim end-to-end (§5.9 — a tap cannot enforce, so dev mode is inline) (install → decorated task → local mini-report) on a clean machine in ≤5 min, scripted and timed in CI; production mode against live proxy — SDK-present vs. SDK-absent traffic produces correctly differentiated provenance granularity in the same ledger
- Adversarial: instrumented agent attempts to skip/monkey-patch its own SDK — proxy still captures and attributes the traffic (the ADR-9 claim, verified); SDK-asserted context contradicting proxy-observed facts is recorded with the discrepancy flagged — **scoped for Phase 1 to `assertion_status=invalid`**, which is the only contradiction honestly detectable while `principal` and `asserted_principal` occupy different namespaces (a service principal vs. an agent name are not comparable for equality). The full predicate needs asserted *scope* checked against the observed action/resource, or a workload-identity binding table; both are post-Phase-1
- Framework hooks: LangChain + Claude agent SDK (Python), MCP TypeScript SDK + a stock TS agent framework, sample apps in CI matrix
- Cross-language: mixed fleet (TS orchestrator spawning Python sub-agents and vice versa) produces one coherent lineage chain in the ledger
- Packaging: brew/npm/pipx install-to-first-decision timed in CI on mac/linux/arm64 — ≤5 min each channel

**Note on enforcement (ADR-14):** Phase 1 still **exits monitor-only**. The local enforce actuator is Phase 2 work — the decision moved the *paywall*, not the *schedule*, and Phase 1 is already the tightest phase in the plan (review-doc Issue 6). What Phase 1 must do now is stop foreclosing it: the actuator interface, per-policy `on_error`/`enforce_action` metadata, and the `fail_mode_applied` ledger field all land in Phase 1 even though nothing acts on them yet, because retrofitting a field into a ledger schema after evidence exists is a migration, not an edit.

**Adversarial corpus v1 (wk 8–12, ships with the `agent-security` pack):** minimum 25 recorded attack traces replayable in CI — scope-widening spawn chains, assertion replay (incl. cross-replica replay against a second proxy instance), tool-alias dodge, secret/credential exfiltration, destructive filesystem op, egress to an unlisted host, prompt-injection-driven tool abuse, spend-limit evasion, orphan flooding, malformed-MCP evasion. (Vertical packs ship their own corpus — e.g. FHIR compartment escape via chained search, `$export` smuggling — gated the same way.) Pass = every trace produces the documented expected decision.

**Phase 1 exit test:** stranger-run demo checklist (15 min, no author present) + full CI green.

### 8.3 Phase 2 — Design partner deployments (evidence integrity becomes primary)

| Category | Tests | Pass criterion |
|---|---|---|
| Deployment | Preflight on AKS/EKS/OpenShift-sim; air-gap install; tap-mode mirror fidelity (sampled diff vs. inline capture) | Install ≤2 wks partner effort (BR-2); mirror capture ≥99.5% of inline |
| Compatibility | Matrix: {LangChain, Claude agents, partner's orchestrator} × {MCP HTTP, stdio, generic HTTP} | Documented support/degrade per cell; no silent gaps |
| Evidence integrity | Monthly: full ledger re-verify per partner; mutation drill (deliberately corrupt a copy → verifier must fail loudly); clock-skew and restart-gap handling | 100% detection of injected mutations; gaps surfaced as coverage findings, never silently spliced |
| Report accuracy | Every narrative claim traced to ledger seq; partner compliance lead review each cycle; false-positive rate on flags tracked per policy | FP rate trending down release-over-release; zero unsupported claims |
| Key lifecycle | Rotation under live traffic; verifier handles multi-key periods | Zero decision gaps during rotation |
| Field telemetry as test | Coverage %, orphan rate, indeterminate-decision rate per partner | Orphan+indeterminate <5% by day 60, else instrumentation work item |

**Local enforcement (Phase 2, ADR-14 — free tier):**
- Actuator interface + local block actuator on both ingresses (HTTP short-circuit; stdio synthesized JSON-RPC error), batch-partial-block semantics per §5.1
- Per-policy `enforce_action`/`on_error` honored; `decision`/`policy_mode`/`action_applied`/`fail_mode_applied` all recorded and mutually consistent
- **Durability:** enforced-path records written synchronously before the actuator's effect is released; drill the queue-overflow and kill-mid-decision cases and assert no enforced call is ever unrecorded (§5.5)
- Fail-open default on single-instance installs, verified by a kill-under-load drill
- Shadow-mode diff tooling shipped *before* any policy may graduate; `decision=block` + `policy_mode=monitor` is the shadow record
- **Admin-API disarm test (§7):** a process running as the governed agent must not be able to roll back or reload the bundle; every bundle change lands in the ledger
- **Local bypass test:** agent talks to the MCP server directly, around the proxy — the un-proxied path must surface as a coverage finding in the local report
- **Agent-framework retry behavior:** replay a blocked call against real LangChain / Claude agent SDK / MCP TS clients and assert the agent degrades sanely rather than retrying forever. Protocol correctness is not the same as agent-loop correctness
- **Recovery UX:** "why was this blocked", temporary monitor override, and policy rollback are exercised end-to-end — the false-positive path is a first-class scenario, not an afterthought
- Enforce-path p99 re-measured against NFR-1 (now a free-tier gate); every adversarial-corpus trace given an expected *action* alongside its expected decision

### 8.4 Phase 3 — Fleet enforcement + hardening

| Category | Tests | Pass criterion |
|---|---|---|
| Fleet enforcement correctness | Shadow-mode diff: 30 days of would-have-blocked vs. monitor decisions before any policy graduates; **fleet-wide** staged rollout (monitor→warn→enforce) across instances with automated fleet rollback on FP spike; central attestation of which bundle was in force on which instance when | Shadow FP rate <1% on graduating policy; fleet rollback fires in drill; attestation matches per-instance ledgers exactly |
| Fail-mode drills | Kill proxy under enforce: high-risk-classified policies fail closed, low-risk fail open + alert; kill ledger writer: traffic unaffected (monitor), per-policy behavior (enforce) | Behavior matches FR-11 config exactly; partner-witnessed drill |
| Chaos | Pod eviction, network partition proxy↔ledger, bundle-push failure mid-fleet, replay-cache node loss; **monitor-mode proxy kill with out-of-band gap-detection assertion** | No incorrect *allow* on high-risk-classified path in any scenario; every monitor-mode coverage gap is *detected and surfaced*, never silently spliced |
| Adversarial corpus v2 | Corpus grows with every partner-observed novel pattern; red-team engagement (external, budgeted) against enforce mode; publish benchmark methodology + results | ≥60 traces; external red team findings triaged, criticals fixed pre-publication |
| First vertical pack | First regulated-vertical pack co-developed (ADR-12): control-map review, counsel trail, corpus, partner co-dev sign-off (general packs use security-expert review instead of counsel) | Pack gates identical to §5.4 |
| Load (enforce) | Re-run Phase 1 perf suite in enforce mode + step-up/escalate paths | NFR-1/2 hold with enforcement active |

### 8.5 Phase 4 — Productization

| Category | Tests | Pass criterion |
|---|---|---|
| Metering | Ledger-derived identity-under-management counts vs. synthetic known-truth fleets; invoice reproducibility from export | Exact match; partner can independently recompute their bill (trust feature) |
| Upgrade | N→N+1 upgrade under live traffic incl. ledger schema migration; rollback | Zero decision loss; chain continuity proof across upgrade |
| Multi-tenant isolation (if control plane built) | Bundle registry tenant isolation; no cross-tenant metadata leakage; pen test scope includes control plane | Clean pen test on isolation claims |
| Compliance-on-us | SOC 2 evidence collection automated from own systems; product's own ledger used as part of own audit trail (dogfood) | Type I complete before first paid contract signed |
| Regression permanence | Full adversarial corpus + chaos suite + perf gates run on every release candidate, forever | CI-enforced; no manual waivers without recorded ADR |

---
