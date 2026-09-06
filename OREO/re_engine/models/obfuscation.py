"""Structured obfuscation and anti-analysis evidence model.

An :class:`ObfuscationFinding` carries one measured obfuscation/anti-analysis
technique with:

    type         which technique (see :class:`ObfuscationType`)
    target       the unit the finding applies to (class descriptor, method id,
                 or ``app`` for app-wide measurements)
    score        0.0..1.0 score derived from real observed metrics
    evidence     concrete, measured evidence strings (never fabricated)
    confidence   how strongly the observed metrics support the claim

The score is always *computed* from observed bytecode/string distributions,
never supplied as a fixed value.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from re_engine.models.finding import Confidence, Severity


class ObfuscationType(str, enum.Enum):
    """The seven obfuscation / anti-analysis technique families."""

    IDENTIFIER = "identifier"
    STRING = "string"
    REFLECTION = "reflection"
    DYNAMIC_LOADING = "dynamic_loading"
    RUNTIME_EXECUTION = "runtime_execution"
    ANTI_ANALYSIS = "anti_analysis"
    CONTROL_FLOW = "control_flow"


@dataclass
class ObfuscationFinding:
    """One measured obfuscation / anti-analysis technique."""

    type: ObfuscationType
    target: str
    score: float
    evidence: List[str]
    confidence: Confidence
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    analyzer: Optional[str] = None
    metadata: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.type = _coerce_type(self.type)
        self.confidence = _coerce_member(self.confidence, Confidence)
        self.severity = _coerce_member(self.severity, Severity)
        self.score = max(0.0, min(1.0, float(self.score)))
        self.evidence = list(self.evidence or [])

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": self.type.value,
            "target": self.target,
            "score": round(self.score, 4),
            "evidence": list(self.evidence),
            "confidence": self.confidence.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "analyzer": self.analyzer,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ObfuscationFinding":
        return cls(
            type=_coerce_type(data.get("type", "")),
            target=str(data.get("target", "")),
            score=float(data.get("score", 0.0)),
            evidence=[str(e) for e in data.get("evidence", [])],
            confidence=_coerce_member(data.get("confidence"), Confidence),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            severity=_coerce_member(data.get("severity"), Severity),
            analyzer=data.get("analyzer"),
            metadata=dict(data.get("metadata", {})),
        )


def _coerce_type(value) -> ObfuscationType:
    if isinstance(value, ObfuscationType):
        return value
    try:
        return ObfuscationType(str(value))
    except ValueError:
        return ObfuscationType.IDENTIFIER


def _coerce_member(value, enum_type):
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except ValueError:
        return list(enum_type)[-1]