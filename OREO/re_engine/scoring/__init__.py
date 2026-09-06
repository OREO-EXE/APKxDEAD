"""Deterministic suspicious-code ranking for the APK RE engine.

This package answers "which parts of this APK deserve deeper investigation?"
It ranks classes, methods, components, APIs, strings and network functions by
evidence-based, explainable scores. It is deliberately not a malware-family
classifier: it never imports ``ai.*`` and never runs an LLM.
"""

from re_engine.scoring.models import (
    SUSPICION_VERSION,
    RankingResult,
    ScoringReason,
    SuspicionScore,
    TargetKind,
)
from re_engine.scoring.scorer import SuspicionScorer

__all__ = [
    "SUSPICION_VERSION",
    "TargetKind",
    "ScoringReason",
    "SuspicionScore",
    "RankingResult",
    "SuspicionScorer",
]