"""scorer.py

Risk Score Fusion
Algorithm: Weighted Average Scoring

We combine scores from 3 layers into a final 0–100 risk score:
- Layer 1 (rules/Aho–Corasick): 40%
- Layer 2 (Transformer semantic classification): 45%
- Layer 3 (statistical anomaly): 15%

Then we assign:
- 0–30  => SAFE (green)    => action: ALLOWED
- 31–70 => SUSPICIOUS      => action: FLAGGED
- 71–100=> DANGEROUS (red) => action: BLOCKED

All layer scores are normalized to 0–100.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class FusionWeights:
    keyword: float = 0.40
    nlp: float = 0.45
    anomaly: float = 0.15


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def weighted_average(scores: Dict[str, float], weights: FusionWeights) -> float:
    """Weighted average fusion.

    This is a simple, explainable late-fusion method that works well when
    layers have different strengths and occasional failures.
    """

    keyword = clamp(scores.get("keyword_score", 0.0), 0.0, 100.0)
    nlp = clamp(scores.get("nlp_score", 0.0), 0.0, 100.0)
    anomaly = clamp(scores.get("anomaly_score", 0.0), 0.0, 100.0)

    final = keyword * weights.keyword + nlp * weights.nlp + anomaly * weights.anomaly
    return float(clamp(final, 0.0, 100.0))


def label_for_score(score: float) -> Tuple[str, str, str]:
    """Return (label, color, action) for the final score."""

    score = clamp(score, 0.0, 100.0)
    if score <= 30:
        return ("SAFE", "green", "ALLOWED")
    if score <= 70:
        return ("SUSPICIOUS", "yellow", "FLAGGED")
    return ("DANGEROUS", "red", "BLOCKED")
