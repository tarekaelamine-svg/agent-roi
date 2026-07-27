from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DecisionOutcome(str, Enum):
    ACCEPT = "accept"
    ABSTAIN = "abstain"
    HUMAN_REVIEW = "human_review"
    RETRY = "retry"


@dataclass(frozen=True)
class ConfidenceInputs:
    prob: Optional[float] = None
    margin: Optional[float] = None
    z_score: Optional[float] = None
    entropy: Optional[float] = None
    llm_self_score: Optional[float] = None


@dataclass(frozen=True)
class DecisionPolicy:
    min_confidence: float = 0.75
    abstain_action: DecisionOutcome | str = DecisionOutcome.HUMAN_REVIEW

    # Positive evidence weights. Entropy is subtracted as a penalty.
    w_prob: float = 0.55
    w_margin: float = 0.20
    w_z: float = 0.15
    w_entropy: float = 0.10
    w_llm: float = 0.10

    def __post_init__(self) -> None:
        minimum = self._finite_number(self.min_confidence, "min_confidence")
        if not 0.0 <= minimum <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")
        object.__setattr__(self, "min_confidence", minimum)

        try:
            outcome = (
                self.abstain_action
                if isinstance(self.abstain_action, DecisionOutcome)
                else DecisionOutcome(str(self.abstain_action))
            )
        except ValueError as exc:
            allowed = ", ".join(item.value for item in DecisionOutcome)
            raise ValueError(f"abstain_action must be one of: {allowed}") from exc
        object.__setattr__(self, "abstain_action", outcome)

        for name in ("w_prob", "w_margin", "w_z", "w_entropy", "w_llm"):
            value = self._finite_number(getattr(self, name), name)
            if value < 0:
                raise ValueError(f"{name} must be >= 0")
            object.__setattr__(self, name, value)

        if self._weight_denominator() <= 0:
            raise ValueError("At least one confidence weight must be > 0")

    @staticmethod
    def _finite_number(value: float, name: str) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be numeric") from exc
        if not math.isfinite(number):
            raise ValueError(f"{name} must be finite")
        return number

    @staticmethod
    def _clamp01(value: float) -> float:
        return max(0.0, min(1.0, value))

    @staticmethod
    def _stable_sigmoid(value: float) -> float:
        if value >= 0:
            z = math.exp(-value)
            return 1.0 / (1.0 + z)
        z = math.exp(value)
        return z / (1.0 + z)

    def _weight_denominator(self) -> float:
        # A fixed denominator means missing signals reduce evidence sufficiency
        # instead of allowing one weak source to receive full influence.
        return self.w_prob + self.w_margin + self.w_z + self.w_entropy + self.w_llm

    def score(self, x: ConfidenceInputs) -> float:
        score = 0.0

        if x.prob is not None:
            score += self.w_prob * self._clamp01(self._finite_number(x.prob, "prob"))

        if x.margin is not None:
            score += self.w_margin * self._clamp01(self._finite_number(x.margin, "margin"))

        if x.z_score is not None:
            z = self._finite_number(x.z_score, "z_score")
            score += self.w_z * self._stable_sigmoid(z)

        if x.entropy is not None:
            entropy = self._finite_number(x.entropy, "entropy")
            entropy_normalized = self._clamp01(entropy / 2.5)
            score -= self.w_entropy * entropy_normalized

        if x.llm_self_score is not None:
            llm_score = self._clamp01(
                self._finite_number(x.llm_self_score, "llm_self_score")
            )
            score += self.w_llm * llm_score

        return self._clamp01(score / self._weight_denominator())

    def decide(self, x: ConfidenceInputs) -> DecisionOutcome:
        return (
            DecisionOutcome.ACCEPT
            if self.score(x) >= self.min_confidence
            else self.abstain_action
        )
