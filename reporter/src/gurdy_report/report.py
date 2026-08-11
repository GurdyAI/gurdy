"""Building the report model: the honesty rules live here, not in the template.

The template renders claims. Which claims exist, and whether the document may be
rendered as an ordinary report at all, is decided here — so a presentation change
cannot quietly relax an evidentiary rule.

The list this is designed against, which is the list of ways a report built from
real data still misleads its reader:

1. **Denominator.** Percentages are over *records written*, never over "traffic".
   The proxy can only count what it saw and what it managed to record; traffic
   that never reached it is outside every number by construction, and that
   sentence appears in the report rather than in this docstring.
2. **Survivorship.** The append queue drops on overflow. A run with drops has an
   unknown population, so its counts are floors and are labelled as such.
3. **Absence is not zero.** "No policy flagged anything" is supportable from an
   export; "nothing happened" is not. Absence claims must say what is absent.
4. **Monitor mode.** `decision=block` means *would have* blocked. A count of
   flagged calls with no statement that none were stopped is not an enforcement
   claim (§5.6).
5. **Unanswered calls.** A decision with no response record may have succeeded,
   failed, or still be in flight. It is never counted as a success.
6. **Unsigned tails.** Records past the last batch signature are chain-linked but
   unsigned, and a chain link is recomputable by anyone with file access.
   Reporting over them without saying so is reporting over forgeable data.
7. **Unrecorded time.** Liveness gaps and a missing shutdown record mean the
   period contains time in which nothing was written. The period is then not the
   period the reader thinks it is.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from pathlib import Path

from .claims import Claim, Section
from .ledger import Decision, LedgerData


def _refs(decisions) -> tuple[str, ...]:
    """Qualified citations for a set of decisions: '<export file>:<seq>'."""
    return tuple(f"{d.source}:{d.seq}" for d in decisions)
from .verify import Verification


@dataclass
class Report:
    ledger_dir: str
    sections: list[Section] = field(default_factory=list)
    #: Reasons this export cannot carry an ordinary report. Non-empty means the
    #: renderer emits a refusal instead, and the CLI exits nonzero.
    refusals: list[str] = field(default_factory=list)

    @property
    def reportable(self) -> bool:
        return not self.refusals

    def section(self, title: str, *, blocking: bool = False) -> Section:
        s = Section(title, blocking=blocking)
        self.sections.append(s)
        return s


def build(ledger_dir: Path, data: LedgerData, ver: Verification) -> Report:
    r = Report(ledger_dir=str(ledger_dir))

    _integrity(r, ver)
    if not r.reportable:
        # Deliberately stops here. Every section below would describe records
        # whose authenticity has just been rejected, and a document that reports
        # findings over unverified evidence is worse than one that reports
        # nothing: it looks the same as a real one.
        return r

    _coverage(r, ver, data)
    _what_happened(r, data)
    _attribution(r, data)
    _policies(r, data)
    return r


def _integrity(r: Report, ver: Verification) -> None:
    s = r.section("Chain integrity", blocking=True)

    if not ver.exports:
        r.refusals.append("no exports found — there is nothing to report on")
        s.add(Claim.absence("No ledger files were found.", because="the directory contains no .jsonl exports"))
        return

    for e in ver.failures:
        r.refusals.append(f"{Path(e.file).name} failed verification: {e.error}")
    if ver.failures and len(ver.failures) < len(ver.exports):
        # Partial failure still refuses the whole report. The chains share a
        # signing key and a process; one that fails to verify puts the others'
        # provenance in question, and a document that reported the good files
        # while burying the bad one would invite exactly the reading we cannot
        # support. Which files were sound is stated so the refusal is actionable.
        ok_names = ", ".join(Path(e.file).name for e in ver.exports if e.ok)
        r.refusals.append(
            f"{len(ver.exports) - len(ver.failures)} of {len(ver.exports)} export(s) did verify "
            f"({ok_names}), but no findings are reported while any chain in the set is unsound"
        )

    if r.refusals:
        s.add(
            Claim.absence(
                "This export does not verify. No findings are reported from it.",
                because="a ledger whose hash chain or signatures do not check out is not evidence, "
                "whatever it says; reporting over it would produce a document indistinguishable "
                "from one built on a sound export",
            )
        )
        return

    tails = [e for e in ver.exports if e.uncovered > 0]
    if tails:
        # Reached only via --allow-unsigned-tail, since the verifier fails these
        # by default. Records past the last batch signature are chain-linked but
        # unsigned, and a chain link is recomputable by anyone with file access —
        # so these are forgeable, and a report that counted them without saying
        # so would be citing attacker-controlled records as evidence.
        for e in tails:
            s.add(
                Claim(
                    f"{Path(e.file).name} has {e.uncovered} trailing record(s) that NO batch "
                    f"signature covers, and they are included in the findings below.",
                    refs=(f"{Path(e.file).name}:{e.last_seq}",),
                    caveat="anyone with write access to this file could have appended them with a "
                    "correct seq and prev_hash. Only the signature boundary rejects that, and it "
                    "was waived with --allow-unsigned-tail. Re-export after the ledger closes",
                )
            )

    for e in ver.exports:
        kind = "lifecycle" if e.is_lifecycle else "workload"
        s.add(
            Claim(
                f"{Path(e.file).name} ({kind}) verified: {e.records} records, "
                f"{e.batches} batch signature(s), key {e.kid or '(none)'}.",
                refs=(f'{Path(e.file).name}:{e.last_seq}',),
                caveat=""
                if ver.pinned
                else "the key was read from the export itself, so this confirms internal "
                "consistency, not provenance — a third party must pin the key with --pubkey",
            )
        )
        s.add(
            Claim(
                f"Chain head for {Path(e.file).name} is seq {e.last_seq}, hash {e.head_hash[:16]}…",
                refs=(f'{Path(e.file).name}:{e.last_seq}',),
                caveat="record this out of band; comparing it on the next verification is what "
                "detects a truncated export, which verification alone cannot",
            )
        )
        if e.unknown_kinds:
            s.add(
                Claim(
                    f"{e.unknown_kinds} record(s) are of a kind this verifier does not interpret.",
                    refs=(f'{Path(e.file).name}:{e.last_seq}',),
                    caveat="chained and signed, so covered by the integrity guarantee, but not "
                    "counted in the findings below — this export may come from a newer proxy",
                )
            )


def _coverage(r: Report, ver: Verification, data: LedgerData) -> None:
    """What the ledger admits it does not contain.

    Placed before the findings on purpose. A reader who sees "1 call flagged"
    first and "412 records dropped" in an appendix has been given the wrong
    impression by the ordering alone.
    """
    s = r.section("Coverage — what this report cannot see")

    dropped = sum(e.dropped for e in ver.exports)
    write_errors = sum(e.write_errors for e in ver.exports)
    identity_failed = sum(e.identity_failed for e in ver.exports)
    gaps = sum(e.liveness_gaps for e in ver.exports)
    restarts = sum(e.unclean_restarts for e in ver.exports)
    unclean = [e for e in ver.exports if e.is_lifecycle and e.clean_end is False]

    s.add(
        Claim.absence(
            "Traffic that never reached the proxy is absent from every number below.",
            because="a monitor records what passes through it; nothing in an export can "
            "describe a call that went around it",
            caveat="coverage of the *paths* into your tools is a deployment property, not "
            "something this report can measure",
        )
    )

    if dropped or write_errors:
        s.add(
            Claim(
                f"The ledger reports losing {dropped} record(s) to queue overflow and "
                f"{write_errors} to write errors.",
                refs=tuple(sorted(data.coverage_refs)),
                absent_because=""
                if data.coverage_refs
                else "the verifier counted these losses while walking the chain, but this reader "
                "found no coverage record to cite — treat the discrepancy itself as a finding",
                caveat="every count in this report is therefore a FLOOR, not a total: the calls "
                "behind those records happened and were decided, and are not represented below",
            )
        )
        # Deliberately NOT a refusal. A lossy export is still evidence of what it
        # does contain; refusing would destroy a usable record to make a point.
        # The counts become floors and say so, which is the honest treatment.
    else:
        s.add(
            Claim.absence(
                "The ledger reports no dropped records and no write errors.",
                because="no coverage record in this export declares a loss",
                caveat="this is the writer's own account; a crash takes its open window with it, "
                "so it remains a floor",
            )
        )

    if identity_failed:
        s.add(
            Claim(
                f"{identity_failed} call(s) were recorded with no derived assertion because "
                f"identity derivation failed inside the proxy.",
                refs=tuple(sorted(data.coverage_refs)),
                absent_because=""
                if data.coverage_refs
                else "reported by the verifier with no coverage record for this reader to cite",
                caveat="a proxy-internal gap, not an agent-side one: the claim may have been fine "
                "and our derivation was not",
            )
        )

    if data.unverified_files:
        s.add(
            Claim.absence(
                f"{len(data.unverified_files)} file(s) in the export directory were not covered by "
                f"the verification run and are excluded entirely: "
                + ", ".join(data.unverified_files)
                + ".",
                because="the verifier reported on a specific set of files; anything else present "
                "now either appeared afterwards or was not a ledger export",
                caveat="a file that appears between verification and reporting is exactly what a "
                "report must not absorb silently",
            )
        )

    if data.unreadable_lines:
        s.add(
            Claim.absence(
                f"{data.unreadable_lines} line(s) in the export could not be parsed by this reader "
                f"and are excluded from every count below.",
                because="the verifier hashes lines and accepted them, so their integrity holds — "
                "it is this reader that could not interpret them",
                caveat="a newer proxy, or a corrupted-but-signed line. Either way the findings below "
                "describe less than the export contains",
            )
        )

    if gaps or restarts or unclean:
        detail = []
        if gaps:
            detail.append(f"{gaps} interval(s) with no heartbeat")
        if restarts:
            detail.append(f"{restarts} restart(s) with no preceding shutdown")
        if unclean:
            detail.append("a chain with no shutdown record")
        s.add(
            Claim(
                "The period contains time in which the proxy wrote no evidence: " + "; ".join(detail) + ".",
                refs=tuple(sorted(data.coverage_refs)),
                absent_because=""
                if data.coverage_refs
                else "reported by the verifier with no coverage record for this reader to cite",
                caveat="traffic during those intervals is unrecorded. This report describes the "
                "time the proxy was writing, which is not the same as the period it covers",
            )
        )
    else:
        s.add(
            Claim.absence(
                "No unrecorded intervals: heartbeats are continuous and every restart followed a "
                "clean shutdown.",
                because="no coverage record reports a liveness gap or an unclean restart",
            )
        )


def _what_happened(r: Report, data: LedgerData) -> None:
    s = r.section("What the agents did")
    decisions = data.decisions

    if not decisions:
        s.add(
            Claim.absence(
                "No governed calls were recorded.",
                because="this export contains no decision records",
                caveat="which means either no governed traffic occurred, or none of it reached "
                "the proxy — those are different situations and an export cannot tell them apart",
            )
        )
        return

    s.add(Claim(f"{len(decisions)} governed call(s) recorded.", refs=_refs(decisions)))

    by_action: dict[str, list[Decision]] = collections.defaultdict(list)
    for d in decisions:
        by_action[d.action or "(unknown)"].append(d)
    for action, group in sorted(by_action.items()):
        tools = collections.Counter(d.tool for d in group if d.tool)
        named = ", ".join(f"{t} ×{n}" for t, n in tools.most_common(6)) or "(no tool named)"
        s.add(Claim(f"{action}: {len(group)} call(s) — {named}.", refs=_refs(group)))

    # Monitor mode: the distinction between what the policy concluded and what
    # happened to the traffic is the whole of §8.3, and collapsing it is how a
    # report turns a shadow observation into an enforcement claim.
    verdicts = collections.Counter(d.decision for d in decisions)
    flagged = [d for d in decisions if d.decision in ("flag", "block")]
    for verdict, n in sorted(verdicts.items()):
        refs = _refs(d for d in decisions if d.decision == verdict)
        s.add(Claim(f"decision={verdict}: {n} call(s).", refs=refs))

    applied = collections.Counter(d.action_applied or "(unrecorded)" for d in decisions)
    for what, n in sorted(applied.items()):
        refs = _refs(d for d in decisions if (d.action_applied or "(unrecorded)") == what)
        s.add(Claim(f"action_applied={what}: {n} call(s).", refs=refs))

    # Only values that actually mean the traffic was stopped. An unrecognised
    # action_applied is unknown, not stopped: inferring enforcement from a value
    # this build does not produce would manufacture the one claim §5.6 says a
    # monitor report must never make.
    stopped = [d for d in decisions if d.action_applied in ("blocked", "rewritten")]
    unknown_applied = [
        d for d in decisions
        if d.action_applied not in ("forwarded", "failed_open", "blocked", "rewritten", "")
    ]
    if flagged:
        s.add(
            Claim(
                f"{len(flagged)} call(s) were flagged or would have been blocked, and "
                f"{len(stopped)} were stopped.",
                refs=_refs(flagged),
                caveat="this build is monitor-only (ADR-3): a decision of 'block' records what a "
                "policy would have done, and the traffic was forwarded regardless. This is not an "
                "enforcement claim",
            )
        )

    if data.unanswered:
        s.add(
            Claim(
                f"{len(data.unanswered)} call(s) have no response record.",
                refs=_refs(data.unanswered),
                caveat="unanswered evidence (§5.5): the call may have succeeded, failed, or still "
                "be in flight. It is not counted as either outcome",
            )
        )

    if unknown_applied:
        s.add(
            Claim(
                f"{len(unknown_applied)} call(s) record an action_applied this reporter does not "
                f"recognise; they are counted as neither forwarded nor stopped.",
                refs=_refs(unknown_applied),
                caveat="a newer proxy, or a value that needs adding here — either way guessing "
                "which side it falls on would invent an enforcement claim",
            )
        )

    if data.findings:
        s.add(
            Claim(
                f"{len(data.findings)} advisory classification finding(s) are attached.",
                refs=tuple(f'{f.source}:{f.seq}' for f in data.findings),
                caveat="advisory only and never a decision input (ADR-7). A call with no finding is "
                "unclassified, which is not the same statement as classified benign",
            )
        )
    else:
        s.add(
            Claim.absence(
                "No classification findings are attached to any call.",
                because="this export contains no finding records",
                caveat="findings are produced by an async classifier that may not have run at all; "
                "their absence says nothing about content",
            )
        )


def _attribution(r: Report, data: LedgerData) -> None:
    """Two axes, never blended.

    §5.5 keeps observed principal tier and assertion status separate because they
    answer different questions: the first is what the proxy could establish about
    who called, the second is whether an agent-side claim verified. An earlier
    draft of the spec blended them into one list and that was treated as a defect
    — a call can be attested-coarse with a valid assertion, and reading that as
    one ordered scale loses the distinction the three-tier model exists for.
    """
    s = r.section("Attribution")
    decisions = data.decisions
    if not decisions:
        return

    tiers = collections.Counter(d.principal_tier or "(unrecorded)" for d in decisions)
    s.add(
        Claim(
            "Observed principal tier — what the proxy established independently: "
            + ", ".join(f"{k} {v}" for k, v in sorted(tiers.items()))
            + ".",
            refs=_refs(decisions),
            caveat="this axis never degrades: it is what the proxy saw, and an agent cannot "
            "influence it (§5.2)",
        )
    )

    statuses = collections.Counter(d.assertion_status or "(unrecorded)" for d in decisions)
    s.add(
        Claim(
            "Assertion status — whether an agent-side claim verified: "
            + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items()))
            + ".",
            refs=_refs(decisions),
            caveat="'absent' is the ordinary case for traffic from an agent with no SDK installed "
            "and is not a failure; 'invalid' means a credential was presented and did not verify",
        )
    )

    # The cross-tabulation, stated as the two-axis grid rather than a ranking.
    grid = collections.Counter(
        (d.principal_tier or "(unrecorded)", d.assertion_status or "(unrecorded)") for d in decisions
    )
    for (tier, status), n in sorted(grid.items()):
        refs = _refs(
            d
            for d in decisions
            if (d.principal_tier or "(unrecorded)") == tier
            and (d.assertion_status or "(unrecorded)") == status
        )
        s.add(Claim(f"tier={tier} × assertion={status}: {n} call(s).", refs=refs))

    with_human = [d for d in decisions if d.asserted_human_actor]
    denom = len(decisions)
    if with_human:
        s.add(
            Claim(
                f"{len(with_human)} of {denom} recorded call(s) name a human actor "
                f"({len(with_human) * 100 // denom}% of governed calls recorded).",
                refs=_refs(with_human),
                caveat="the denominator is governed calls recorded in this export — not ledger "
                "records, and not traffic. See the coverage section",
            )
        )
    else:
        s.add(
            Claim.absence(
                "No recorded call names a human actor.",
                because="no decision record carries asserted_human_actor",
                caveat="high-confidence human attribution requires an SDK at the task entry point "
                "(§5.9); without it the proxy still attributes a workload, but not a person",
            )
        )


def _policies(r: Report, data: LedgerData) -> None:
    s = r.section("Policies in force")
    decisions = data.decisions
    if not decisions:
        return

    bundles = collections.Counter(d.bundle_ver or "(unrecorded)" for d in decisions)
    for ver, n in sorted(bundles.items()):
        refs = _refs(d for d in decisions if (d.bundle_ver or "(unrecorded)") == ver)
        s.add(Claim(f"bundle {ver} decided {n} call(s).", refs=refs))
    if len(bundles) > 1:
        s.add(
            Claim(
                f"{len(bundles)} distinct policy bundles were in force during this period.",
                refs=_refs(decisions),
                caveat="findings from different bundles are not directly comparable: a call the "
                "later bundle would have flagged may predate it",
            )
        )

    fired: dict[str, list[Decision]] = collections.defaultdict(list)
    modes: dict[str, set[str]] = collections.defaultdict(set)
    for d in decisions:
        for eff in d.policy_effects:
            pid = eff.get("policy_id") or "(unnamed)"
            fired[pid].append(d)
            if eff.get("mode"):
                modes[pid].add(str(eff["mode"]))
    if not fired:
        s.add(
            Claim.absence(
                "No policy contributed to any recorded decision.",
                because="no decision record carries policy_effects",
                caveat="which is a statement about this export, not about the traffic: a policy "
                "that never matched and a policy that never loaded look identical here",
            )
        )
        return
    for pid, group in sorted(fired.items(), key=lambda kv: -len(kv[1])):
        mode = "/".join(sorted(modes[pid])) or "(unrecorded)"
        s.add(
            Claim(
                f"{pid} contributed to {len(group)} decision(s), rollout mode {mode}.",
                refs=_refs(group),
            )
        )
