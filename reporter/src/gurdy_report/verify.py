"""Chain verification, obtained rather than reimplemented.

§3.3's single-implementation rule: the Go core is the only implementation of
mint, eval, ledger and verify. A Python hash-chain walker would be a second
security-critical implementation of the property the entire product rests on,
and two implementations of a signature check drift — the one that drifts
*permissively* is the one that ships a green report over a forged export.

So this shells out to `gurdy-verify -json` and reads the answer. The cost is a
subprocess; the benefit is that there is exactly one thing in the world that
decides whether a Gurdy export verifies.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class VerifierUnavailable(RuntimeError):
    """The verifier could not be run at all.

    Fatal, and not degradable: a report that skipped verification because the
    verifier was missing would be a report over unverified data that looks
    exactly like a report over verified data.
    """


@dataclass(frozen=True)
class Export:
    """One partition's verification result, as the Go verifier reported it."""

    file: str
    ok: bool
    error: str
    records: int
    decisions: int
    answered: int
    unmatched: int
    batches: int
    dropped: int
    write_errors: int
    identity_failed: int
    clean_end: bool | None
    liveness_gaps: int
    unclean_restarts: int
    uncovered: int
    unknown_kinds: int
    tenant: str
    workload: str
    instance_id: str
    schema_version: int
    kid: str
    key_source: str
    last_seq: int
    head_hash: str

    @property
    def is_lifecycle(self) -> bool:
        """The proxy's own lifecycle chain rather than a workload's evidence.

        Decided by the **signed** `workload` field being empty, not by the
        filename. §5.5 v0.8.5 moved chain identity inside the signature exactly
        because a filename is unsigned and renaming one silently re-attributes a
        whole chain; a reporter that then read the filename back would undo that
        for its own purposes. The lifecycle chain is the one that is evidence of
        no workload.
        """
        return self.workload == ""

    @property
    def unanswered(self) -> int:
        return max(0, self.decisions - self.answered)


@dataclass(frozen=True)
class Verification:
    exports: tuple[Export, ...]
    pinned: bool

    @property
    def ok(self) -> bool:
        return bool(self.exports) and all(e.ok for e in self.exports)

    @property
    def failures(self) -> tuple[Export, ...]:
        return tuple(e for e in self.exports if not e.ok)


def _export(raw: dict) -> Export:
    return Export(
        file=raw.get("file", ""),
        # `is True`, not bool(): the string "false" is truthy, and this field is
        # the one that decides whether a chain is treated as sound.
        ok=raw.get("ok") is True,
        error=raw.get("error", ""),
        records=int(raw.get("records", 0)),
        decisions=int(raw.get("decisions", 0)),
        answered=int(raw.get("answered", 0)),
        unmatched=int(raw.get("unmatched", 0)),
        batches=int(raw.get("batches", 0)),
        dropped=int(raw.get("dropped", 0)),
        write_errors=int(raw.get("write_errors", 0)),
        identity_failed=int(raw.get("identity_failed", 0)),
        clean_end=raw.get("clean_end"),
        liveness_gaps=int(raw.get("liveness_gaps", 0)),
        unclean_restarts=int(raw.get("unclean_restarts", 0)),
        uncovered=int(raw.get("uncovered", 0)),
        unknown_kinds=int(raw.get("unknown_kinds", 0)),
        tenant=raw.get("tenant", ""),
        workload=raw.get("workload", ""),
        instance_id=raw.get("instance_id", ""),
        schema_version=int(raw.get("schema_version", 0)),
        kid=raw.get("kid", ""),
        key_source=raw.get("key_source", ""),
        last_seq=int(raw.get("last_seq", 0)),
        head_hash=raw.get("head_hash", ""),
    )


def verify(
    ledger_dir: Path,
    *,
    verifier: str = "gurdy-verify",
    pubkey: Path | None = None,
    allow_unsigned_tail: bool = False,
) -> Verification:
    """Run the Go verifier over an export directory and parse its verdict."""
    exe = shutil.which(verifier) or (verifier if Path(verifier).exists() else None)
    if exe is None:
        raise VerifierUnavailable(
            f"{verifier!r} not found on PATH. The reporter does not verify chains "
            f"itself — §3.3 keeps one implementation of that in the Go core — so it "
            f"cannot produce a report without it. Build it with "
            f"`go build -o gurdy-verify ./cmd/gurdy-verify` and pass --verifier."
        )
    cmd = [exe, "-json"]
    if pubkey is not None:
        cmd += ["-pubkey", str(pubkey)]
    if allow_unsigned_tail:
        cmd.append("-allow-unsigned-tail")
    cmd.append(str(ledger_dir))

    # Exit 1 means "an export failed to verify" and the JSON is still the answer.
    # Exit 2 and above mean the verifier could not do its job at all — bad flags,
    # unreadable key, a build that does not support -json — and JSON on stdout
    # would then be a partial answer that reads like a complete one.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode >= 2:
        raise VerifierUnavailable(
            f"{verifier} exited {proc.returncode}, so it did not complete a verification: "
            f"{proc.stderr.strip()[:400] or proc.stdout.strip()[:200]}"
        )
    if not proc.stdout.strip():
        raise VerifierUnavailable(
            f"{verifier} produced no output (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise VerifierUnavailable(
            f"{verifier} -json did not produce JSON: {exc}. "
            f"A verifier this reporter cannot parse is a verifier it must not "
            f"pretend to have run."
        ) from exc

    exports = tuple(_export(e) for e in payload.get("exports", []))
    if not exports:
        raise VerifierUnavailable(
            f"{verifier} reported no exports. An empty verdict is not a pass — it means the "
            f"verifier found nothing to check, and reporting over the directory anyway would "
            f"describe records nothing verified."
        )
    return Verification(exports=exports, pinned=bool(payload.get("pinned")))
