"""Reading the export. Parsing only — no verification happens here.

The split matters: `verify.py` obtains the Go verifier's verdict on whether these
records are authentic, and this module reads them for content. Doing both here
would put a second implementation of a security check next to a JSON parser, and
whichever one an editor reached for would become the one that mattered.

So this module is deliberately credulous. It is only ever called on records the
Go verifier has already accepted (`report.build` refuses before reaching the
content sections otherwise), which is why it can afford to be.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Decision:
    seq: int
    call_id: str
    action: str
    tool: str
    decision: str
    action_applied: str
    policy_mode: str
    principal: str
    principal_tier: str
    assertion_status: str
    asserted_principal: str
    asserted_human_actor: str
    lineage: tuple[str, ...]
    bundle_ver: str
    policy_effects: tuple[dict, ...]
    source: str


@dataclass(frozen=True)
class Finding:
    seq: int
    call_id: str
    labels: tuple[str, ...]
    source: str


@dataclass
class LedgerData:
    decisions: list[Decision] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    #: (source file, call_id) pairs that have a response record. Keyed per chain,
    #: not globally: call_ids are unique per proxy instance but two partitions in
    #: one export can legitimately contain the same one, and a global set would
    #: let a response in chain A mark a decision in chain B as answered.
    answered_calls: set[tuple[str, str]] = field(default_factory=set)
    #: Qualified refs of coverage records, so a claim about lost evidence cites
    #: the records that admit the loss rather than pointing at nothing.
    coverage_refs: set[str] = field(default_factory=set)
    unreadable_lines: int = 0
    #: Files present in the directory that the verifier did not vouch for. Never
    #: parsed, always reported: a file that appeared after verification is
    #: exactly what a report must not silently absorb.
    unverified_files: tuple[str, ...] = ()

    @property
    def unanswered(self) -> list[Decision]:
        """Decisions with no response record joined to them.

        Includes decisions carrying no call_id at all. Those can never be joined
        to a response, so excluding them — as the first version did — quietly
        moved them out of the unanswered count and into nothing at all.
        """
        return [
            d for d in self.decisions
            if not d.call_id or (d.source, d.call_id) not in self.answered_calls
        ]


def _s(rec: dict, key: str) -> str:
    v = rec.get(key)
    return v if isinstance(v, str) else ""


def load(ledger_dir: Path, verified: set[str] | None = None) -> LedgerData:
    """Read the exports in a directory.

    `verified` is the set of filenames the Go verifier reported on. Anything else
    in the directory is listed as unverified and never parsed: the verifier ran
    over a set of files, and a report must describe that set rather than whatever
    the directory happens to contain by the time this reads it.
    """
    data = LedgerData()
    present = sorted(p.name for p in ledger_dir.glob("*.jsonl"))
    if verified is not None:
        data.unverified_files = tuple(n for n in present if n not in verified)
    for path in sorted(ledger_dir.glob("*.jsonl")):
        if verified is not None and path.name not in verified:
            continue
        source = path.name
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                # Counted, not skipped silently. The verifier hashes lines, so an
                # unparseable one still had integrity — it is our reader that
                # could not read it, and that distinction belongs in the report.
                data.unreadable_lines += 1
                continue
            if not isinstance(rec, dict):
                data.unreadable_lines += 1
                continue
            kind = _s(rec, "kind")
            seq = rec.get("seq")
            seq = int(seq) if isinstance(seq, (int, float)) else 0
            if kind == "decision":
                effects = rec.get("policy_effects")
                lineage = rec.get("lineage")
                data.decisions.append(
                    Decision(
                        seq=seq,
                        call_id=_s(rec, "call_id"),
                        action=_s(rec, "action"),
                        tool=_s(rec, "tool"),
                        decision=_s(rec, "decision"),
                        action_applied=_s(rec, "action_applied"),
                        policy_mode=_s(rec, "policy_mode"),
                        principal=_s(rec, "principal"),
                        principal_tier=_s(rec, "principal_tier"),
                        assertion_status=_s(rec, "assertion_status"),
                        asserted_principal=_s(rec, "asserted_principal"),
                        asserted_human_actor=_s(rec, "asserted_human_actor"),
                        lineage=tuple(x for x in lineage if isinstance(x, str)) if isinstance(lineage, list) else (),
                        bundle_ver=_s(rec, "bundle_ver"),
                        policy_effects=tuple(e for e in effects if isinstance(e, dict))
                        if isinstance(effects, list)
                        else (),
                        source=source,
                    )
                )
            elif kind == "response":
                if cid := _s(rec, "call_id"):
                    data.answered_calls.add((source, cid))
            elif kind == "coverage":
                data.coverage_refs.add(f"{source}:{seq}")
            elif kind == "finding":
                labels = rec.get("labels")
                data.findings.append(
                    Finding(
                        seq=seq,
                        call_id=_s(rec, "call_id"),
                        labels=tuple(x for x in labels if isinstance(x, str)) if isinstance(labels, list) else (),
                        source=_s(rec, "source"),
                    )
                )
    return data
