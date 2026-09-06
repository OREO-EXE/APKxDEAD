"""Data models for the deterministic suspicious-code ranking subsystem.

This is an evidence-ranking layer, not a malware-family classifier. It answers
questions like "which class in this APK deserves the deepest manual review?"
Every :class:`SuspicionScore` carries the concrete reasons and the raw evidence
references that produced it, so a score can always be explained and audited.

Rules of this subsystem:

    - a score is never emitted without at least one reason
    - every reason carries the evidence reference it came from
    - everything is deterministic: no randomness, no LLM, no classifier imports
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List

SUSPICION_VERSION = "0.1.0"


class TargetKind(str, enum.Enum):
    """The kind of APK surface a suspicion score refers to."""

    CLASS = "class"
    METHOD = "method"
    COMPONENT = "component"
    API = "api"
    STRING = "string"
    NETWORK = "network"


@dataclass
class ScoringReason:
    """One explainable reason contributing ``weight`` points to a score."""

    label: str
    weight: int
    category: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "weight": self.weight,
            "category": self.category,
            "evidence": self.evidence,
        }


@dataclass
class SuspicionScore:
    """A ranked suspicion score for one target.

    ``target`` identifies the ranked surface (a descriptor, method id, dotted
    class name, component name, API reference or string literal).
    ``evidence_refs`` is the deduplicated, sorted set of raw evidence
    references that back the score (permissions, API ids, strings, caller
    method ids, ...).
    """

    target: str
    kind: TargetKind
    score: int
    reasons: List[ScoringReason] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    analyzer_version: str = SUSPICION_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind.value,
            "score": self.score,
            "reasons": [r.to_dict() for r in self.reasons],
            "evidence_refs": list(self.evidence_refs),
            "analyzer_version": self.analyzer_version,
        }


@dataclass
class RankingResult:
    """Ranked suspicion output for one APK, sorted highest score first."""

    scores: List[SuspicionScore] = field(default_factory=list)
    analyzer_version: str = SUSPICION_VERSION
    summary: str = ""

    def by_kind(self, kind: TargetKind | str) -> List[SuspicionScore]:
        wanted = kind.value if isinstance(kind, TargetKind) else str(kind)
        return [s for s in self.scores if s.kind.value == wanted]

    def counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for score in self.scores:
            key = score.kind.value
            counts[key] = counts.get(key, 0) + 1
        return {key: counts[key] for key in sorted(counts)}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer_version": self.analyzer_version,
            "summary": self.summary,
            "counts": self.counts(),
            "scores": [s.to_dict() for s in self.scores],
        }