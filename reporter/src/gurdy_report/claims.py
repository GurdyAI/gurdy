"""A claim and its citation, welded together.

§5.6: "every claim in the report links to ledger record seq numbers." That is
easy to satisfy on the first draft and easy to lose on the fourth, because a
number is trivial to interpolate into a template and a citation is extra work.

So the citation is not a convention here, it is the type. A :class:`Claim`
cannot be constructed without the seqs it rests on, the renderer accepts nothing
but claims, and a claim with no evidence raises at construction rather than
rendering as an uncited assertion. The rule is enforced by the data structure
because a rule enforced by discipline is a rule that decays.

The one deliberate exception is :meth:`Claim.absence`, for the statements a
report has to make about things that are *not* in the ledger — and it demands a
reason instead of seqs, because "0 violations" with no citation is exactly the
sentence that needs the most explaining.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class UncitedClaim(ValueError):
    """Raised when a claim is built without evidence.

    Deliberately fatal. A report that renders one uncited number has broken the
    property that makes it an audit artifact rather than a summary, and failing
    at build time is the only way anyone finds out.
    """


@dataclass(frozen=True)
class Claim:
    """One statement the report makes, and the records it rests on."""

    text: str
    #: Qualified record references, "<export file>:<seq>". A bare seq does NOT
    #: identify a ledger record: every partition chain has its own seq space, so
    #: "seq 2" names one record per file and the reader cannot tell which was
    #: meant. That made the §5.6 citation requirement satisfiable in form and
    #: useless in practice.
    refs: tuple[str, ...] = ()
    #: Set when the claim is about something the ledger does *not* contain. Then
    #: `seqs` is legitimately empty and this says why, so an absence can never
    #: be quietly presented as a measurement.
    absent_because: str = ""
    #: A caveat that must travel with this specific claim wherever it is
    #: rendered — not collected in a footnote nobody reads.
    caveat: str = ""

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise UncitedClaim("a claim with no text is not a claim")
        if not self.refs and not self.absent_because:
            raise UncitedClaim(
                f"claim {self.text!r} cites no ledger records and gives no reason for "
                f"the absence. Every claim links to a seq (§5.6); if the claim is "
                f"*about* an absence, use Claim.absence() and say what is missing."
            )
        for r in self.refs:
            if ":" not in r or not r.rsplit(":", 1)[1].isdigit():
                raise UncitedClaim(
                    f"claim {self.text!r} cites {r!r}, which does not identify a record. "
                    f"A citation is '<export file>:<seq>' — a seq alone is ambiguous across chains."
                )

    @classmethod
    def absence(cls, text: str, because: str, caveat: str = "") -> "Claim":
        """A claim about what is *not* in the ledger.

        The whole reason this exists: "no policy flagged anything" and "nothing
        happened" are different statements, and only the first is supportable
        from an export. `because` is required so the difference reaches the page.
        """
        if not because.strip():
            raise UncitedClaim("an absence claim must say what is absent and why")
        return cls(text=text, absent_because=because, caveat=caveat)

    @property
    def citation(self) -> str:
        """How the claim renders its evidence."""
        if not self.refs:
            return f"no records — {self.absent_because}"
        shown = ", ".join(self.refs[:8])
        if len(self.refs) > 8:
            shown += f", +{len(self.refs) - 8} more"
        return shown


@dataclass
class Section:
    """A titled group of claims. The renderer walks these and nothing else."""

    title: str
    claims: list[Claim] = field(default_factory=list)
    #: Blocks the report from rendering as a normal artifact. Used for the
    #: findings that change what the whole document means — an unverifiable
    #: chain, a period with unrecorded time.
    blocking: bool = False

    def add(self, claim: Claim) -> "Section":
        self.claims.append(claim)
        return self
