"""gurdy-report — the free-tier local governance report (BR-11, §5.6).

Compiles a hash-chained decision ledger into an artifact a security owner can
hand to a reviewer. Deterministic and template-driven: no model anywhere in the
path, because an LLM-written audit artifact would undermine the independence
claim the product rests on (§5.6).

Three properties are load-bearing, each because of a specific way a report built
from real data still misleads its reader:

- **It does not verify the chain itself.** §3.3 keeps one implementation of that
  in the Go core; this invokes ``gurdy-verify -json`` and consumes the verdict.
  Two implementations of a signature check drift, and the permissive one is the
  one that ships a green report over a forged export.
- **It refuses rather than caveats when the evidence is not evidence.** An export
  that fails verification produces a NOT REPORTABLE document and a nonzero exit,
  because a report over unverified records looks exactly like a report over sound
  ones.
- **Every claim carries its citation as a matter of type, not discipline.** A
  :class:`~gurdy_report.claims.Claim` cannot be built without the seqs it rests
  on, and the renderer can see nothing else.
"""

from .claims import Claim, Section, UncitedClaim
from .ledger import LedgerData, load
from .render import as_json, markdown
from .report import Report, build
# Exported as `verify_export`, not `verify`: a package attribute with the same
# name as its submodule shadows it, and `from gurdy_report import verify` then
# silently yields the function. That cost two debugging rounds during this build.
from .verify import Verification, VerifierUnavailable
from .verify import verify as verify_export

__all__ = [
    "Claim",
    "LedgerData",
    "Report",
    "Section",
    "UncitedClaim",
    "Verification",
    "VerifierUnavailable",
    "as_json",
    "build",
    "load",
    "markdown",
    "verify_export",
]
__version__ = "0.1.0"
