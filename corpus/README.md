# Adversarial corpus v1

Recorded attack traces, replayable in CI, that gate the policy pack (§8.2). The
spec's bar: **≥25 traces, pass = every trace produces the documented expected
decision.** Currently 26 traces — 19 defences pinned, 7 gaps documented.

```bash
cd proxy
go build -o /tmp/gp ./cmd/gurdy-proxy && go build -o /tmp/gc ./cmd/gurdy-conform
/tmp/gc -cases ../corpus/traces -proxy /tmp/gp
```

## Why it shares the conformance runner

A trace is a conformance case asking a different question. Conformance asks *did
the SDK produce the right evidence?*; the corpus asks *did the pack reach the
right verdict on an attack?* The case format, the judge, the per-case proxy and
the export verification are identical, and a forked judge is a judge that
drifts — which is the class of defect this project keeps finding. So the runner
is shared and only the questions differ.

Corpus traces are all `kind: "wire"`: an attacker does not politely use your SDK.

## Three outcomes, not two

| | Meaning |
|---|---|
| **PASS** | the pack defends against this, and the trace proves it |
| **GAP** | the attack **succeeds today**. The trace asserts what actually happens, says why, and names what closes it |
| **FAIL** | the trace and reality disagree — someone must look |

A GAP is not a soft failure and it is not a pass. It is printed with its reason
on every run, and the summary line says *"N documented gaps — attacks this pack
does NOT stop"*, so nobody can skim a green run and conclude more than it says.

### What stops `known_gap` becoming a graveyard

**A documented gap that no longer reproduces is a FAILURE.** If the pack improves
and the attack starts being caught, the trace goes red with:

> this known gap NO LONGER REPRODUCES — if the pack improved, delete the
> known_gap marker and assert the behaviour you now want

The corpus lying about a *weakness* is the same defect as lying about a defence,
so both are failures. This fired on its first run: a gap I asserted around
argument-name aliasing turned out not to exist, and the runner refused to let me
record it.

Every `known_gap` must carry `why` and `closes_with`. A trace that says an attack
succeeds without naming what fixes it is an excuse; the runner rejects it at load.

## Writing a trace

1. **State the attack in the attacker's terms** (`attack`), separately from what
   the trace pins (`why`). They are different sentences and conflating them
   produces traces nobody can safely change.
2. **Assert the policy, not just the decision.** `"policy": "flag-credential-read"`
   — a trace that checks only `decision: flag` passes when the *wrong* rule fires,
   which for a pack that gates on named controls is a pass for the wrong reason.
3. **Include the negative.** Trace 10 proves the egress control does *not* fire on
   a known provider. Without it the rule could match everything and every
   positive trace would still look right.
4. **Pin defences you would notice losing.** Trace 21 passes today; it exists so
   that narrowing the extractor's argument list turns a silent regression into a
   red run.
5. **Run it and believe the result over your assumptions.** Two of the first
   eighteen traces asserted behaviour the pack does not have — in both directions.

## What monitor mode means for a passing corpus

This build never blocks (ADR-3). `decision` is the policy's conclusion,
`action_applied` is what happened, and today every trace ends `forwarded` —
including the ones whose attack was detected. So "the corpus passes" currently
means **every attack produced the right verdict**, not that any was stopped.
Traces record `action_applied` now so that when the Phase 2 actuator lands, the
ones that should block gain an expected action and the rest stay honest.

## What is deliberately NOT here

Evidence-integrity attacks — a forged unsigned ledger tail, non-canonical base64
in a signature, cross-replica assertion replay — live as Go tests in
`internal/ledger` and `internal/tis`. They are sharper there: a unit test can
corrupt a specific byte and assert on the exact error, where a JSON fixture can
only observe the outcome. Converting them would lose precision to gain
uniformity.

Two limits of the harness, stated rather than papered over:

- It always points the proxy at a **loopback** upstream, so `provider()` returns
  `local` and no trace can exercise the genuinely-unlisted egress branch. That
  branch is covered in `internal/extract` tests.
- It runs **one proxy instance**, so cross-replica assertion replay is not
  reachable. It is covered in `internal/tis`.

## The loop, closed once already

Trace 05 shipped as a GAP: `resource_path` was matched case-sensitively while
`context.tool` was folded, so `/home/u/.SSH/id_rsa` reached the tool unflagged on
macOS and Windows — a one-line bypass of the flagship BR-11 control.

Fixing it turned the trace **red**, exactly as designed:

```
FAIL  [gap ] credential exfiltration: uppercase path segment — this known gap NO LONGER REPRODUCES
```

It is now a PASS that pins the fix, joined by trace 26, which varies case across
the *whole* path. That second one matters: a repair that special-cased `.ssh`
would pass 05 and fail 26. **A trace proves an instance; a pair proves the class.**

## The gaps, as of v1

Seven attacks currently succeed. Five trace back to one root cause — **controls
match on strings the governed party chooses** (tool name, argument name) — which
is the §7 aliasing problem and the reason tool-signature binding is on the
roadmap. The case dimension of that problem is now closed. The other two are
missing controls: no spend policy (BR-11 advertises three protections and ships
two) and no rate control.
