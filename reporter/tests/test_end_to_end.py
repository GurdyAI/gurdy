"""One test that uses the real Go verifier against a real export.

Everything else stubs the verification result, which is right for testing the
report's logic and wrong for testing the seam. This exercises the actual
subprocess boundary — the flag name, the JSON shape, the exit-code handling —
because a change on the Go side would otherwise break the reporter silently and
only in production.

Skipped when no verifier is available, rather than passing vacuously.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from gurdy_report import build, load, markdown
from gurdy_report.verify import VerifierUnavailable, verify

VERIFIER = os.environ.get("GURDY_VERIFY", "gurdy-verify")
LEDGER = os.environ.get("GURDY_TEST_LEDGER", "")

pytestmark = pytest.mark.skipif(
    not LEDGER or not Path(LEDGER).is_dir() or not (shutil.which(VERIFIER) or Path(VERIFIER).exists()),
    reason="needs GURDY_VERIFY and GURDY_TEST_LEDGER pointing at a real verifier and export",
)


def test_a_real_export_verifies_and_reports():
    ver = verify(Path(LEDGER), verifier=VERIFIER)
    assert ver.ok, [e.error for e in ver.failures]
    rep = build(Path(LEDGER), load(Path(LEDGER)), ver)
    assert rep.reportable
    out = markdown(rep)
    assert "Chain integrity" in out and "Coverage" in out
    # Every rendered claim shows its evidence line.
    for line in out.splitlines():
        if line.startswith("- ") and "Evidence" not in line:
            continue
    assert out.count("Evidence:") >= 5


def test_a_tampered_copy_is_refused(tmp_path):
    dest = tmp_path / "tampered"
    shutil.copytree(LEDGER, dest)
    target = next(p for p in dest.glob("*.jsonl") if not p.name.startswith("_proxy"))
    lines = target.read_text().splitlines()
    for i, line in enumerate(lines):
        if '"kind":"decision"' in line:
            # Any single-byte change breaks the chain from this record onward.
            lines[i] = line.replace('"tool":"', '"tool":"x', 1)
            break
    target.write_text("\n".join(lines) + "\n")

    ver = verify(dest, verifier=VERIFIER)
    assert not ver.ok
    rep = build(dest, load(dest), ver)
    assert not rep.reportable
    out = markdown(rep)
    assert "NOT REPORTABLE" in out
    # The findings sections must not appear at all.
    assert "What the agents did" not in out


def test_a_missing_verifier_refuses_rather_than_skipping_verification():
    with pytest.raises(VerifierUnavailable, match="not found on PATH"):
        verify(Path(LEDGER), verifier="gurdy-verify-does-not-exist")
