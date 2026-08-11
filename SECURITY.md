# Security policy

Gurdy is a tool people are asked to trust with evidence. A defect here is not a
crash — it is a record that says something untrue, or an export that verifies
when it should not. This document says what we consider a vulnerability, what we
already know is weak, and how to tell us.

## Reporting

Use **[GitHub private vulnerability reporting](https://github.com/GurdyAI/gurdy/security/advisories/new)**.
It is private until we publish, and it needs no key exchange or mailing list.

Please do not open a public issue for anything in [What counts](#what-counts-as-a-vulnerability)
below.

**What to expect.** We are a two-person project and we will not pretend to a
24-hour SLA we cannot keep. We aim to acknowledge within **5 working days** and
to give you an assessment and a rough timeline within **15**. If a report is
serious and we go quiet, escalate by opening a public issue that says only *"I
have an unacknowledged security report, reference &lt;advisory id&gt;"* — no details.

**Disclosure.** We will agree timing with you. Our default is to publish an
advisory once a fix is released, crediting you unless you would rather we did
not. If we disagree about severity we will say so in the advisory rather than
quietly downgrade it.

**Safe harbour.** We will not pursue or support action against anyone acting in
good faith under this policy: testing against your own deployment, not accessing
others' data, not degrading a service you do not own, and giving us a reasonable
chance to fix before going public.

## Supported versions

Pre-release. Only `main` is supported; there are no tagged releases and no
backports. When that changes this section will say so.

## What counts as a vulnerability

The product makes a small number of claims. Anything that breaks one is in
scope, and the first is the one that matters most.

**1. Evidence integrity.** The export is the evidence. A third party with only
the files and a pinned public key must be able to tell whether they are intact.
In scope:

- Records that `gurdy-verify` accepts but that the proxy never wrote — forgery,
  a tampered record that still verifies, a truncation it does not notice.
- A chain that can be silently re-attributed to another tenant or workload.
- Anything that makes verification pass over unsigned records without saying so.
- A reporter that renders findings from an export that failed verification.

**2. Identity that can be chosen by the party being governed.** The
proxy-observed principal must never degrade, and an agent must not be able to
select the identity it is authorised as. In scope: a path where an agent-supplied
value reaches `principal`, `principal_tier`, or the Cedar principal; a way to
make asserted identity overwrite observed identity; a forged assertion recorded
as `valid`.

**3. Misattribution.** A call recorded under an agent that did not make it. We
treat this as *more* severe than a lost record, because a missing record is a
visible gap and a wrong one is not.

**4. Credential confinement.** `Gurdy-Txn` is a live bearer credential for a
whole transaction. In scope: getting it to an upstream or any host that is not
the configured proxy; extracting signing keys; finding private key material
inside a `-ledger-dir`, which is the directory people hand to auditors.

**5. Availability of the governed traffic.** Monitor mode may not drop, alter or
delay traffic (ADR-3). A way to make the proxy break, stall or corrupt the
traffic it is watching is in scope, including via a malformed frame, an
oversized body, or a hostile upstream.

**6. Scope escalation.** A derived child credential that is not a provable
narrowing of its parent.

**7. Silent coverage loss.** Records dropped, skipped or never written *without
being counted*. Losing evidence under pressure is a design tradeoff we
document; losing it invisibly is a bug.

## What does not count

Not because we do not care, but because saying so up front saves your time.

**A policy that fails to catch an attack is usually not a vulnerability.** The
bundled starter pack is three shallow rules, and we publish the attacks it does
not stop: see **[`corpus/`](corpus/)**, where seven traces are marked
`known_gap` with the reason and what would close each one. If your finding is
one of those, it is already public — though a *new* evasion of a control that is
supposed to work is very much worth reporting.

**Monitor mode not blocking is by design**, not a missing mitigation. `decision:
block` means a policy concluded it would have blocked; `action_applied` says what
happened. Local enforcement is Phase 2 (ADR-14).

**These are known, documented and unmitigated.** Please do not spend time on
them; do tell us if you find something *worse* than what is written down:

- **The admin API can be reached by any process on the host.** It is
  localhost-bound with a CSRF guard, which stops a browser and not a
  prompt-injected agent running on the same box — and the governed agent always
  is. It can reload or roll back policy. Under monitor mode that is log
  integrity; under Phase 2 enforcement it would be a total bypass, which is why
  token auth on mutating routes is a Phase 2 gate (§7, roadmap Phase 2).
  **`POST /retention/prune` widens this from "disarm the proxy" to "disarm it
  and delete evidence."** Not worse in *kind* — anyone who can POST here can
  also stop the process, and a stopped proxy records nothing — but worse in
  degree, so it is stated rather than left to be found. Two things bound it:
  pruning removes whole segments and only after appending a **signed retention
  record** naming what went, so the deletion is visible in the surviving chain
  rather than silent; and it cannot rewrite or shorten a segment, because that
  would mean re-hashing a chain. An attacker who prunes leaves a signed
  admission that they did.
- **Mint is unauthenticated** on the local Unix socket, deliberately. What it
  issues is an *asserted* claim that policy sees only as reserved context; the
  socket's owner-only mode is the control, so "who may mint" is "who may act as
  this user". This stops being adequate the moment enforcement lands or a policy
  reads scope (roadmap §3.B).
- **`MintTxn` accepts any root scope**, so an injected agent can mint
  `scope=*`. Harmless while nothing blocks and no policy reads scope.
- **A local relay is exempt from the unlisted-host egress rule**, because
  loopback classifies as `local` for dev mode (corpus trace 19).
- **No rate limiting anywhere.** A flood degrades evidence into counted drops
  (corpus trace 24).
- **An agent that controls its own MCP server controls its tool declarations**,
  so signature binding does not help there (`internal/toolsig`).

**Out of scope entirely:** findings against a deployment you do not own; social
engineering; physical access; denial of service by resource exhaustion of the
host itself; automated scanner output with no demonstrated impact.

## A note on the threat model

Gurdy's adversary is usually **the agent it is watching** — prompt-injected,
buggy, or acting on an instruction nobody sanctioned. It is not primarily a
network attacker. That shapes what we treat as severe: the agent chooses tool
names, argument names and its own claimed identity, so anything that lets those
choices influence the *record* is serious, and anything that lets them influence
the *policy principal* is critical.

We do trust the upstream MCP server's declarations about itself. If an agent also
controls its server, that is a different deployment question — which servers you
let an agent reach — and no amount of signature binding changes it.
