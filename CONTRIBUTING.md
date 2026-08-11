# Contributing

Thanks for looking. This is a small pre-release project with a few conventions
that are stronger than usual, because it builds evidence people are asked to
trust. They are all short and they are all here.

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin](DCO) — a one-line
sign-off, no paperwork, no account, no CLA to sign. Add `-s` when you commit:

```bash
git commit -s -m "your message"        # appends Signed-off-by: Your Name <you@example.com>
git rebase --signoff main              # if you forgot on commits you already made
```

That line certifies you wrote the patch, or have the right to submit it. The
full text is in [`DCO`](DCO) and CI checks for it on every pull request.

**What that means for your code, stated plainly:** contributions are licensed
under Apache-2.0 like the rest of this repository, and **they stay in the open
half.** Gurdy is open-core — there is a separate proprietary repository for
`gurdy-fleet` and the paid policy packs — and a DCO gives us no right to
relicense your work into it, which is deliberate. We chose a DCO over a CLA
*because* we do not intend to move contributed code into the paid product. If
that ever changed we would need your explicit permission, per contributor, per
patch. See [`NOTICE`](NOTICE) for exactly where the line sits.

Issues, discussions and security reports need no sign-off — see
[SECURITY.md](SECURITY.md) for the latter.

## The spec is normative

[`docs/spec.md`](docs/spec.md)
is the specification. Section numbers (§5.5), requirement IDs (FR-3, NFR-1,
BR-11) and ADR numbers appear throughout the code and point into it.

**The doc wins over the code.** If they disagree, the code is wrong — or the doc
needs amending, which is a deliberate act with a changelog entry, not a silent
edit. Read the relevant section before changing behaviour.

[`docs/roadmap.md`](docs/roadmap.md) sequences the spec and tracks debt items
D1–D13 with file locations. Check it before "fixing" something that is a
scheduled gap.

## Invariants

Breaking one of these breaks a requirement, not just a test. The full list is in
[`CLAUDE.md`](CLAUDE.md); these are the ones that catch people out.

- **Monitor mode never drops, alters or delays traffic** (ADR-3). `decision` is
  what the policy concluded, `action_applied` is what happened to the traffic,
  `policy_mode` is the rule's rollout state. Three fields, never collapsed.
- **Inspection failure never breaks traffic** (NFR-3). An oversized body, an
  undecodable frame, a failed identity derivation: all forward, all get recorded
  as indeterminate. Coverage gaps are *counted and surfaced*, never silent.
- **Hashes, not payloads** (NFR-7). Request and response bodies exist in the
  ledger as hashes. An extractor may derive a count or a hash from a body; it
  may never copy content out of one.
- **Observed identity never degrades** (§5.2). `principal` is what the proxy
  saw and is what policy evaluates on. Asserted values are the agent's claim and
  reach Cedar only as reserved context keys.
- **No secrets in the export.** `-ledger-dir` is what you hand a third party.
  Private keys live under `-state-dir`.
- **Ledger schema changes are migrations.** Adding a field once evidence exists
  in the field is expensive — land record fields early, even inert ones.
- **Single implementation.** The Go core owns mint, eval, ledger and verify. The
  SDKs and the reporter *ask* and report the answer. A second implementation of
  a security rule is one that will drift, and the permissive one wins.

## Tests must have teeth

The standard here is not coverage. It is: **break the code and confirm the test
fails.**

Every security-relevant change should come with a test, and you should mutate
the implementation to prove the test catches it. Say so in the PR description —
"reverting X fails `TestY`" — because a test that passes against the bug is
worse than no test: it is a claim of safety nobody checked.

This has caught real mistakes repeatedly, including several of ours:

- A conformance case that passed against the very defect it was named for.
- A percentile test that asserted the mislabelled denominator it was meant to fix.
- A corpus trace asserting a gap that did not exist.

Write the mutation **from the bug, not from the fix**. A test written from the
fix tends to pass against both.

New behaviour for the SDKs lands in [`conformance/`](conformance/) **first**,
then in each SDK. Two SDKs with two test suites drift; two judged by one corpus
cannot.

## Comments

Dense, and they explain *why* — especially where a boring choice was deliberate.
Cite the spec (`§5.5`, `FR-10`, `ADR-9`). Match the surrounding density.

Two conventions:

- `// ponytail:` marks a deliberate simplification with its known ceiling and
  upgrade path. Keep the form.
- A comment that records a bug someone already made is worth more than one that
  restates the code. Several in this tree exist because the obvious approach was
  tried and was wrong.

## The gate

Everything below must be green. CI runs the same things.

```bash
cd proxy
gofmt -l . && go vet ./... && go test -race ./...

# the shared corpus, both SDK drivers, and the adversarial traces
go build -o /tmp/gp ./cmd/gurdy-proxy && go build -o /tmp/gc ./cmd/gurdy-conform
/tmp/gc -cases ../conformance/cases -proxy /tmp/gp
/tmp/gc -cases ../conformance/cases -proxy /tmp/gp -driver ../sdk/python/run-driver.sh
/tmp/gc -cases ../conformance/cases -proxy /tmp/gp -driver ../sdk/typescript/run-driver.sh
/tmp/gc -cases ../corpus/traces     -proxy /tmp/gp
```

```bash
cd sdk/python     && uv sync && uv run pytest -q     # uv, never pip
cd sdk/typescript && npm install && npm test
cd reporter       && uv sync && uv run pytest -q
```

The coverage gate is a **ratchet at the measured floor, not a target**. Raise
`MIN` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) when it rises;
do not write tests whose only purpose is to move it.

## Adding an attack to the corpus

[`corpus/README.md`](corpus/README.md) has the full guide. The short version:
state the attack in the attacker's terms, assert the *policy* and not just the
decision, and **believe the result over your assumptions** — two of the first
eighteen traces asserted behaviour our own pack did not have, in both
directions.

If the attack succeeds today, mark it `known_gap` with why and what closes it.
That is not a failure, it is the corpus doing its job. A documented gap that
later stops reproducing **fails the build**, which is what stops the marker
becoming a graveyard.

## Commits and PRs

Explain *why*, not what — the diff already says what. If you found a defect
while building something else, say so; that context is usually the most valuable
part.

Update [`docs/roadmap.md`](docs/roadmap.md) and
[`docs/activity-log.md`](docs/activity-log.md) with the change, not afterwards.
The activity log records what was deliberately skipped and why, which is the
part nobody can reconstruct later.

## Code of conduct

Be decent. If that ever needs more words than this, we will add them.
