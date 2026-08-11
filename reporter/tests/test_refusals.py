"""The properties that make this an audit artifact rather than a summary.

Everything here is about one question: can this report say something the ledger
does not support? A report that overstates is worse than no report, because it
carries the authority of the chain it was built from.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gurdy_report import Claim, UncitedClaim, build, markdown, as_json
from gurdy_report.ledger import Decision, LedgerData
from gurdy_report.verify import Export, Verification


def export(**kw) -> Export:
    base = dict(
        file="/x/acme_host-1.jsonl", ok=True, error="", records=10, decisions=4, answered=4,
        unmatched=0, batches=1, dropped=0, write_errors=0, identity_failed=0, clean_end=None,
        liveness_gaps=0, unclean_restarts=0, uncovered=0, unknown_kinds=0, tenant="acme",
        workload="host:1", instance_id="i#1", schema_version=1, kid="k", key_source="embedded",
        last_seq=10, head_hash="abc123",
    )
    base.update(kw)
    return Export(**base)


def decision(seq: int, **kw) -> Decision:
    base = dict(
        seq=seq, call_id=f"c{seq}", action="mcp/tools_call", tool="read_file", decision="allow",
        action_applied="forwarded", policy_mode="monitor", principal="svc:host:1",
        principal_tier="attested-coarse", assertion_status="absent", asserted_principal="",
        asserted_human_actor="", lineage=(), bundle_ver="v1", policy_effects=(), source="f.jsonl",
    )
    base.update(kw)
    return Decision(**base)


def data(*decisions: Decision, **kw) -> LedgerData:
    d = LedgerData(decisions=list(decisions))
    # Keyed per chain: a response in one partition must not mark a decision in
    # another as answered.
    d.answered_calls = kw.get("answered", {(x.source, x.call_id) for x in decisions})
    d.coverage_refs = kw.get("coverage_refs", set())
    return d


# --- a claim cannot exist without evidence ----------------------------------


def test_a_claim_without_a_citation_cannot_be_constructed():
    # §5.6: every claim links to a seq. Enforced by the type rather than by
    # discipline, because discipline decays and this is the property that makes
    # the document auditable.
    with pytest.raises(UncitedClaim, match="cites no ledger records"):
        Claim("4 calls were flagged.")


def test_an_absence_claim_must_say_what_is_absent():
    # "0 violations" is the sentence most in need of explanation, so the API
    # refuses to let it through without one.
    with pytest.raises(UncitedClaim):
        Claim.absence("Nothing was flagged.", because="")
    ok = Claim.absence("Nothing was flagged.", because="no decision record carries a flag")
    assert "no records" in ok.citation


# --- refusal, not caveats ----------------------------------------------------


def test_a_failed_chain_refuses_and_reports_no_findings():
    ver = Verification(exports=(export(ok=False, error="prev_hash mismatch — chain broken"),), pinned=True)
    rep = build(Path("/x"), data(decision(2, decision="flag")), ver)

    assert not rep.reportable
    out = markdown(rep)
    assert "NOT REPORTABLE" in out
    assert "prev_hash mismatch" in out
    # The decision that exists in the (rejected) ledger must not appear as a
    # finding: reporting over unverified records produces a document that reads
    # exactly like a sound one.
    assert "flagged" not in out
    assert "What the agents did" not in out


def test_an_empty_export_refuses_rather_than_reporting_zero():
    # "No violations" from an empty directory is the flattering reading. It is
    # also indistinguishable from a proxy that never ran.
    rep = build(Path("/x"), LedgerData(), Verification(exports=(), pinned=False))
    assert not rep.reportable
    assert "nothing to report on" in " ".join(rep.refusals)


def test_a_verified_export_is_reportable():
    rep = build(Path("/x"), data(decision(2)), Verification(exports=(export(),), pinned=True))
    assert rep.reportable
    assert "NOT REPORTABLE" not in markdown(rep)


# --- the ways a report flatters itself --------------------------------------


def test_flagged_calls_are_always_paired_with_how_many_were_stopped():
    # §5.6: "a report that says '37 violations' without saying how many were
    # actually stopped is not an enforcement claim."
    rep = build(
        Path("/x"),
        data(decision(2, decision="block", action_applied="forwarded")),
        Verification(exports=(export(),), pinned=True),
    )
    out = markdown(rep)
    assert "0 were stopped" in out
    assert "monitor-only" in out


def test_dropped_records_turn_every_count_into_a_floor():
    # The queue drops on overflow, so a run with drops has an unknown
    # population. The report must say so, and must not refuse — a lossy export
    # is still evidence of what it does contain.
    ver = Verification(exports=(export(dropped=412),), pinned=True)
    rep = build(Path("/x"), data(decision(2), coverage_refs={"f.jsonl:7"}), ver)
    assert rep.reportable
    out = markdown(rep)
    assert "412" in out and "FLOOR" in out


def test_unrecorded_time_is_reported_as_such():
    ver = Verification(exports=(export(liveness_gaps=3, unclean_restarts=1),), pinned=True)
    rep = build(Path("/x"), data(decision(2), coverage_refs={"f.jsonl:7"}), ver)
    out = markdown(rep)
    assert "no heartbeat" in out
    assert "unrecorded" in out


def test_unanswered_calls_are_counted_as_neither_outcome():
    ver = Verification(exports=(export(),), pinned=True)
    d = data(decision(2), decision(4))
    d.answered_calls = {("f.jsonl", "c2")}  # c4 has no response record
    rep = build(Path("/x"), d, ver)
    out = markdown(rep)
    assert "1 call(s) have no response record" in out
    assert "still" in out and "in flight" in out


def test_an_unpinned_key_is_flagged_as_not_proving_provenance():
    rep = build(Path("/x"), data(decision(2)), Verification(exports=(export(),), pinned=False))
    assert "not provenance" in markdown(rep)
    rep2 = build(Path("/x"), data(decision(2)), Verification(exports=(export(),), pinned=True))
    assert "not provenance" not in markdown(rep2)


def test_absence_of_findings_is_not_a_statement_about_content():
    rep = build(Path("/x"), data(decision(2)), Verification(exports=(export(),), pinned=True))
    out = markdown(rep)
    assert "No classification findings" in out
    assert "says nothing about content" in out


# --- the two axes stay two axes ---------------------------------------------


def test_attribution_reports_two_independent_axes_and_their_grid():
    # §5.5 keeps observed tier and assertion status separate: a call can be
    # attested-coarse with a valid assertion, and blending them into one ordered
    # scale loses the distinction the three-tier model exists for. An earlier
    # draft of the spec blended them and that was treated as a defect.
    ver = Verification(exports=(export(),), pinned=True)
    rep = build(
        Path("/x"),
        data(
            decision(2, principal_tier="attested-coarse", assertion_status="absent"),
            decision(4, principal_tier="attested-coarse", assertion_status="valid"),
            decision(6, principal_tier="attested", assertion_status="valid"),
        ),
        ver,
    )
    out = markdown(rep)
    assert "Observed principal tier" in out
    assert "Assertion status" in out
    # The cross-tab, so the reader can see the combination the two axes allow.
    assert "tier=attested-coarse × assertion=valid" in out
    assert "is not a failure" in out  # 'absent' explained rather than scored


def test_percentages_state_their_denominator():
    ver = Verification(exports=(export(),), pinned=True)
    rep = build(
        Path("/x"),
        data(decision(2, asserted_human_actor="alice@example.com"), decision(4)),
        ver,
    )
    out = markdown(rep)
    # The label must name the actual denominator. The first version said
    # "% of records written" while dividing by decision records — a reader would
    # have taken it as a share of everything the ledger contains, which includes
    # responses, coverage and lifecycle records.
    assert "% of governed calls recorded" in out
    assert "denominator is governed calls recorded in this export" in out
    assert "% of records written" not in out


# --- the machine-readable sibling carries the same honesty -------------------


def test_json_sibling_carries_citations_and_the_interpretation_notes():
    import json

    rep = build(Path("/x"), data(decision(2, decision="flag")), Verification(exports=(export(),), pinned=True))
    payload = json.loads(as_json(rep))
    assert payload["reportable"] is True
    # A GRC tool ingesting this will never read the Markdown, so the caveats
    # that make the numbers interpretable have to be in the data.
    assert "denominator" in payload["interpretation"]
    assert "monitor_mode" in payload["interpretation"]
    for section in payload["sections"]:
        for claim in section["claims"]:
            assert claim["refs"] or claim["absent_because"], claim["text"]


def test_json_sibling_reports_a_refusal_as_a_refusal():
    import json

    ver = Verification(exports=(export(ok=False, error="chain broken"),), pinned=True)
    payload = json.loads(as_json(build(Path("/x"), data(decision(2)), ver)))
    assert payload["reportable"] is False
    assert payload["refusals"]


def test_the_report_is_deterministic():
    # §5.6 forbids a model in the report path; the observable consequence is that
    # the same export always produces the same bytes, which is what lets a
    # reviewer diff two periods and anyone reproduce the artifact.
    ver = Verification(exports=(export(),), pinned=True)
    d = data(decision(2, decision="flag"), decision(4), decision(6, tool="delete_file"))
    first = markdown(build(Path("/x"), d, ver))
    second = markdown(build(Path("/x"), d, ver))
    assert first == second


# --- the findings review turned up, each pinned so it cannot return ----------


def test_a_citation_must_identify_a_record_not_just_a_number():
    # Every partition chain has its own seq space, so "seq 2" names one record
    # per file. A bare number satisfied §5.6 in form and was useless in practice.
    with pytest.raises(UncitedClaim, match="does not identify a record"):
        Claim("2 calls.", refs=("2",))
    ok = Claim("2 calls.", refs=("acme_host-1.jsonl:2",))
    assert "acme_host-1.jsonl:2" in ok.citation


def test_an_unsigned_tail_is_reported_where_the_reader_will_see_it():
    # Reachable only via --allow-unsigned-tail. Those records are chain-linked
    # but unsigned, and a chain link is recomputable by anyone with file access —
    # so counting them silently means citing attacker-controlled records.
    ver = Verification(exports=(export(uncovered=3),), pinned=True)
    rep = build(Path("/x"), data(decision(2)), ver)
    out = markdown(rep)
    assert "NO batch signature covers" in out
    assert "forge" in out or "appended them" in out


def test_stopped_is_never_inferred_from_an_unrecognised_action():
    # An action_applied this build does not produce must not be scored as
    # enforcement. Guessing which side it falls on would manufacture exactly the
    # claim §5.6 says a monitor report cannot make.
    ver = Verification(exports=(export(),), pinned=True)
    rep = build(
        Path("/x"),
        data(decision(2, decision="block", action_applied="quarantined-by-a-future-actuator")),
        ver,
    )
    out = markdown(rep)
    assert "0 were stopped" in out
    assert "does not recognise" in out


def test_a_decision_with_no_call_id_counts_as_unanswered():
    # It can never be joined to a response, so excluding it — as the first
    # version did — moved it out of the unanswered count and into nothing at all.
    ver = Verification(exports=(export(),), pinned=True)
    d = data(decision(2, call_id=""))
    d.answered_calls = set()
    rep = build(Path("/x"), d, ver)
    assert "1 call(s) have no response record" in markdown(rep)


def test_a_response_in_one_chain_does_not_answer_a_decision_in_another():
    ver = Verification(exports=(export(), export(file="/x/b.jsonl", workload="host:2")), pinned=True)
    d = data(decision(2, source="a.jsonl"), decision(2, source="b.jsonl"))
    d.answered_calls = {("a.jsonl", "c2")}  # same call_id, different chain
    rep = build(Path("/x"), d, ver)
    assert "1 call(s) have no response record" in markdown(rep)


def test_files_the_verifier_did_not_cover_are_named_and_excluded():
    ver = Verification(exports=(export(),), pinned=True)
    d = data(decision(2))
    d.unverified_files = ("appeared-later.jsonl",)
    out = markdown(build(Path("/x"), d, ver))
    assert "appeared-later.jsonl" in out
    assert "excluded entirely" in out


def test_lines_this_reader_could_not_parse_are_surfaced():
    ver = Verification(exports=(export(),), pinned=True)
    d = data(decision(2))
    d.unreadable_lines = 4
    out = markdown(build(Path("/x"), d, ver))
    assert "4 line(s)" in out and "could not be parsed" in out


def test_partial_verification_failure_refuses_the_whole_report():
    # The chains share a signing key and a process. One that fails puts the
    # others' provenance in question, and a report that showed the good files
    # while burying the bad one would invite a reading we cannot support.
    ver = Verification(
        exports=(export(), export(file="/x/bad.jsonl", ok=False, error="prev_hash mismatch")),
        pinned=True,
    )
    rep = build(Path("/x"), data(decision(2)), ver)
    assert not rep.reportable
    joined = " ".join(rep.refusals)
    assert "bad.jsonl" in joined
    # And it says which ones WERE sound, so the refusal is actionable.
    assert "did verify" in joined


def test_a_verifier_that_could_not_do_its_job_is_not_a_verification(tmp_path, monkeypatch):
    # Exit 1 means "an export failed" and the JSON is the answer. Exit 2 and above
    # mean the verifier never completed one — bad flags, unreadable key, a build
    # without -json — and JSON on stdout would then be a partial answer that
    # reads like a complete one.
    import subprocess as sp

    import gurdy_report.verify as verify_mod

    fake = tmp_path / "fake-verify"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)

    def run_exit2(cmd, **kw):
        return sp.CompletedProcess(cmd, 2, stdout='{"exports":[{"file":"a","ok":true}]}', stderr="bad flag")

    monkeypatch.setattr(verify_mod.subprocess, "run", run_exit2)
    with pytest.raises(verify_mod.VerifierUnavailable, match="did not complete a verification"):
        verify_mod.verify(tmp_path, verifier=str(fake))


def test_an_empty_verdict_is_not_a_pass(tmp_path, monkeypatch):
    import subprocess as sp

    import gurdy_report.verify as verify_mod

    fake = tmp_path / "fake-verify"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(
        verify_mod.subprocess,
        "run",
        lambda cmd, **kw: sp.CompletedProcess(cmd, 0, stdout='{"exports":[]}', stderr=""),
    )
    with pytest.raises(verify_mod.VerifierUnavailable, match="no exports"):
        verify_mod.verify(tmp_path, verifier=str(fake))


def test_a_string_false_is_not_a_pass():
    # `bool("false")` is True, and this field decides whether a chain is treated
    # as sound — the one place in the codebase where loose coercion is a security
    # bug rather than a style question.
    from gurdy_report.verify import _export

    assert _export({"file": "a", "ok": "false"}).ok is False
    assert _export({"file": "a", "ok": True}).ok is True
    assert _export({"file": "a"}).ok is False
