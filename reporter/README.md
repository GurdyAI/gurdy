# gurdy-report — the free-tier local governance report

Compiles a Gurdy decision ledger into an artifact a security owner can hand to a
reviewer (BR-11, §5.6). Markdown for a person, JSON for a tool.

```bash
uv run gurdy-report ./gurdy-ledger                       # to stdout
uv run gurdy-report ./gurdy-ledger -o report.md --json report.json
uv run gurdy-report ./gurdy-ledger --pubkey ledger.pub   # pin the key
```

Exit **0** if the export could carry a report, **1** if it could not, **2** on a
usage or verifier problem — so it composes into a pipeline that must not silently
accept an unusable ledger.

## What makes this an audit artifact rather than a summary

**No model anywhere in the path.** §5.6 is explicit: an LLM-written audit
artifact would undermine the independence claim the product rests on. Narratives
are templates over decision data, so the same export always produces byte-
identical output — which is what lets a reviewer diff two periods and lets anyone
reproduce the document from the ledger they were handed.

**It does not verify the chain itself.** §3.3 keeps one implementation of
verification in the Go core. This shells out to `gurdy-verify -json` and consumes
the verdict. Two implementations of a signature check drift, and the one that
drifts *permissively* is the one that ships a green report over a forged export.
If the verifier is missing, this refuses to run rather than reporting unverified
data — a report that skipped verification reads identically to one that didn't.

**Every claim carries its citation as a matter of type.** A `Claim` cannot be
constructed without the ledger seqs it rests on, and the renderer can see nothing
else. §5.6 requires it; enforcing it in the data structure is what stops it
decaying by the fourth draft.

## What it refuses to do

| Situation | Behaviour |
|---|---|
| Chain or signature verification fails | **NOT REPORTABLE**, zero findings, exit 1 |
| No exports found | **NOT REPORTABLE** — "0 violations" from an empty directory is indistinguishable from a proxy that never ran |
| Unsigned tail | fails verification by default; `--allow-unsigned-tail` for a *live* ledger only, since those records are forgeable by anyone with file access |
| Records dropped by the queue | reports, and every count becomes an explicit **floor** — a lossy export is still evidence of what it contains |
| Liveness gaps / no shutdown record | reports the period as containing unrecorded time |

The refusal is the point. A report rendered over evidence that failed
verification would be indistinguishable from one rendered over sound evidence,
and that difference is the entire value of the artifact.

## The honesty rules, and the failure each prevents

- **Denominators are records written, never "traffic".** A monitor can only count
  what passed through it and what it managed to record. Traffic that never
  reached the proxy is outside every number, and the report says so before it
  says anything else.
- **Coverage comes before findings.** A reader who sees "1 call flagged" first and
  "412 records dropped" in an appendix has been misled by the ordering alone.
- **Absence is not zero.** "No policy flagged anything" is supportable from an
  export; "nothing happened" is not. Absence claims must state what is missing
  and why, which is why `Claim.absence()` demands a reason instead of seqs.
- **Flagged is never reported without stopped.** This build is monitor-only
  (ADR-3): `decision=block` records what a policy *would* have done, and
  `action_applied` says what happened. §5.6 — a report that says "37 violations"
  without saying how many were actually stopped is not an enforcement claim.
- **Unanswered calls are counted as neither outcome.** A decision with no response
  record may have succeeded, failed, or still be in flight.
- **Attribution stays two axes.** Observed principal tier × assertion status,
  reported separately and then as a grid — never blended into one ordered scale.
  A call can be attested-coarse *with* a valid assertion; an earlier draft of the
  spec blended them and that was treated as a defect. `assertion_status=absent`
  is the ordinary case for an agent with no SDK and is not a failure.
- **An unpinned key proves consistency, not provenance.** Without `--pubkey` the
  key comes from the export itself, so an attacker who rewrote the file could
  embed their own. The report flags this.

## Not in the free tier

Control-framework mapping (NIST AI RMF / ISO 42001 / HIPAA), violation narratives
with remediation, HTML/PDF, and the period-over-period dashboard. Those need
`control_map.yaml` from the pack registry (§5.4, BR-4) and are the paid artifact
(§5.6). This one deliberately stops at "what happened, what was flagged, and what
this export cannot tell you."

## Development

```bash
uv sync && uv run pytest -q
```

The tests are mutation-checked: reporting findings over a failed chain, allowing
an uncited claim, and reporting violations without the stopped count each break a
named test.
