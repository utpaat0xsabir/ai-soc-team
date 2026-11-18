"""AI-05C1: proposed-only review of trusted synthetic L1 inference.

This is not an authorization boundary or an issuance authority.
Only trusted application code may supply orchestration results.
"""

from dataclasses import dataclass
from typing import Literal

from app.analysts.inference import InferenceResult


ReviewOutcome = Literal[
    "OBSERVATION_VALIDATED",
    "HUMAN_REVIEW_REQUIRED",
    "INSUFFICIENT_EVIDENCE",
    "REJECTED",
]


@dataclass(frozen=True, slots=True)
class L1ReviewDecision:
    outcome: ReviewOutcome
    proposed_only: Literal[True] = True
    executable: Literal[False] = False


def review_l1_result(value: object) -> L1ReviewDecision:
    """Classify a completed synthetic result without granting authority."""

    rejected = L1ReviewDecision(outcome="REJECTED")

    if type(value) is not InferenceResult:
        return rejected

    try:
        serialized = value.model_dump_json()

        if len(serialized.encode("utf-8")) > 131072:
            return rejected

        result = InferenceResult.model_validate_json(serialized)
    except Exception:
        return rejected

    if (
        result.status != "COMPLETED"
        or result.reason != "ACCEPTED_PROPOSAL"
        or result.classification != "SYNTHETIC / TEST ONLY"
        or result.source != "FAKE_MODEL / TEST ONLY"
        or result.executable is not False
        or result.parsed is None
        or result.parsed.status != "ACCEPTED"
    ):
        return rejected

    evaluation = result.parsed.evaluation

    if (
        evaluation is None
        or evaluation.executable is not False
        or evaluation.proposed_only is not True
    ):
        return rejected

    outcomes: dict[str, ReviewOutcome] = {
        "VALID": "OBSERVATION_VALIDATED",
        "REQUIRES_HUMAN_REVIEW": "HUMAN_REVIEW_REQUIRED",
        "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE",
    }

    return L1ReviewDecision(
        outcome=outcomes.get(evaluation.outcome, "REJECTED")
    )
