"""Rendering: Markdown for a person, JSON for a tool. Templates, never an LLM.

§5.6 is explicit that narratives are generated from decision data via templates —
"an LLM-written audit artifact undermines the entire independence pitch." So this
module is string formatting and nothing else. Two identical exports produce two
byte-identical reports, which is what lets a reviewer diff last month's against
this month's and lets anyone reproduce the artifact from the ledger they were
handed.

Markdown rather than HTML or PDF for the free tier: diffable, greppable, readable
with no browser, and it renders wherever the reader already is. The paid tier's
job is the framework-mapped HTML/PDF (§5.6); making the free one pretty first
would be optimising the wrong artifact.

The renderer walks claims and cannot do otherwise — it has no access to the
underlying records — so a number cannot reach the page without the citation that
`claims.Claim` forced it to carry.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .claims import Section
from .report import Report

HEADER = "# Gurdy governance report"

REFUSAL_BANNER = """> **NOT REPORTABLE.** This export cannot carry a governance report, and no
> findings are shown below. The reasons are listed immediately under this notice.
>
> This is deliberate. A report rendered over evidence that failed verification
> would be indistinguishable from one rendered over sound evidence, and the
> difference is the entire value of the artifact."""

PREAMBLE = """This report is compiled from a hash-chained decision ledger by
template, with no model in the path: the same export always produces the same
document (§5.6). Every claim cites the ledger records it rests on.

**Read the coverage section before the findings.** A monitor can only report what
passed through it and what it managed to record; the numbers here are bounded by
both, and where they are floors rather than totals they say so."""


def markdown(report: Report) -> str:
    out: list[str] = [HEADER, ""]
    out.append(f"Export: `{report.ledger_dir}`")
    out.append("")

    if not report.reportable:
        out += [REFUSAL_BANNER, ""]
        for reason in report.refusals:
            out.append(f"- {reason}")
        out.append("")
        # The integrity section still renders: the reader needs to know *what*
        # failed, and it is the only section built before the refusal.
        for section in report.sections:
            out += _section(section)
        return "\n".join(out).rstrip() + "\n"

    out += [PREAMBLE, ""]
    for section in report.sections:
        out += _section(section)
    return "\n".join(out).rstrip() + "\n"


def _section(section: Section) -> list[str]:
    out = [f"## {section.title}", ""]
    if not section.claims:
        # Should be unreachable: a section with nothing to say is not created.
        # Kept as a visible marker rather than silence, because an empty heading
        # reads as "checked, nothing found" and that is a claim.
        out += ["_No claims were generated for this section — this is a reporter bug, not a finding._", ""]
        return out
    for claim in section.claims:
        out.append(f"- {claim.text}")
        if claim.caveat:
            # Indented under the claim, not gathered into a footnote: a caveat a
            # reader has to go looking for is a caveat that does not apply.
            out.append(f"  - _{claim.caveat}._")
        out.append(f"  - Evidence: {claim.citation}")
    out.append("")
    return out


def as_json(report: Report) -> str:
    """The machine-readable sibling (§5.6), carrying the same claims and citations."""
    payload = {
        "tool": "gurdy-report",
        "export": report.ledger_dir,
        "reportable": report.reportable,
        "refusals": report.refusals,
        # Stated in the payload as well as the prose. A GRC tool ingesting this
        # needs to know the numbers are bounded by what the proxy saw and
        # recorded, and it will not read the Markdown.
        "interpretation": {
            "denominator": "counts are over records written to this ledger, never over traffic; "
            "traffic that did not reach the proxy is outside every number",
            "monitor_mode": "decision=block records what a policy would have done; "
            "action_applied says what happened to the traffic. This build never blocks (ADR-3)",
            "unanswered": "a decision with no response record may have succeeded, failed, or still "
            "be in flight; it is counted as neither",
            "findings": "classification findings are advisory and never a decision input (ADR-7); "
            "their absence says nothing about content",
        },
        "sections": [
            {
                "title": s.title,
                "claims": [
                    {
                        **{k: v for k, v in asdict(c).items() if k != "refs"},
                        "refs": list(c.refs),
                    }
                    for c in s.claims
                ],
            }
            for s in report.sections
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"
