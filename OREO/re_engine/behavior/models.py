"""Behavioral profile models.

The behavior-reconstruction engine turns low-level evidence (manifest,
bytecode API usage, strings, permissions, call-graph and data-flow results)
into an evidence-backed :class:`BehaviorFinding` for every behavior in the
catalogue. Each finding carries *why* it was reached (explanation), *what*
backed it (evidence_refs) and the related classes / methods / permissions /
data flows observed.

Statuses
--------
    TRUE     a concrete, evidence-backed claim was proven (e.g. a boot
             receiver is registered for BOOT_COMPLETED).
    FALSE    nothing relevant was observed; the engine is (within its scan
             bounds) confident the behavior has no evidence.
    UNKNOWN  the app *could* exhibit the behavior but the evidence is
             ambiguous or merely permissive (e.g. a permission is granted but
             no code path was found). UNKNOWN is never promoted to TRUE.

Determinism & isolation
-----------------------
Nothing here imports the malware-family classifier, an LLM, or a feature
pipeline; iteration order and output are sorted and deduplicated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class BehaviorStatus(str, Enum):
    """Whether the evidence supports a behavior claim."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:  # enum str == value for convenient output
        return self.value


@dataclass
class BehaviorFinding:
    """One evidence-backed behavioral claim about the analyzed APK."""

    behavior_id: str
    behavior_name: str
    category: str
    status: BehaviorStatus
    confidence: str
    explanation: str
    evidence_refs: List[str] = field(default_factory=list)
    related_classes: List[str] = field(default_factory=list)
    related_methods: List[str] = field(default_factory=list)
    related_permissions: List[str] = field(default_factory=list)
    related_data_flows: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "behavior_id": self.behavior_id,
            "behavior_name": self.behavior_name,
            "category": self.category,
            "status": self.status.value,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "evidence_refs": list(self.evidence_refs),
            "related_classes": sorted(set(self.related_classes)),
            "related_methods": sorted(set(self.related_methods)),
            "related_permissions": sorted(set(self.related_permissions)),
            "related_data_flows": sorted(set(self.related_data_flows)),
        }


@dataclass
class BehaviorResult:
    """Output of the behavior-reconstruction engine for one APK."""

    findings: List[BehaviorFinding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    summary: str = ""

    def by_status(self, status: BehaviorStatus) -> List[BehaviorFinding]:
        return [f for f in self.findings if f.status == status]

    def by_category(self) -> Dict[str, List[BehaviorFinding]]:
        by: Dict[str, List[BehaviorFinding]] = {}
        for finding in self.findings:
            by.setdefault(finding.category, []).append(finding)
        return {k: by[k] for k in sorted(by)}

    def status_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in BehaviorStatus}
        for finding in self.findings:
            counts[finding.status.value] += 1
        return counts

    def true_behaviors(self) -> List[BehaviorFinding]:
        return self.by_status(BehaviorStatus.TRUE)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "stats": dict(self.stats),
            "limitations": list(self.limitations),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_behavioral_reconstruction(self):
        """Backward-compatible compact behavior map for the report model."""
        from re_engine.output.report import BehavioralReconstruction

        behaviors: Dict[str, List[str]] = {}
        for finding in self.by_status(BehaviorStatus.TRUE):
            behaviors.setdefault(finding.behavior_name, []).extend(
                _cap(finding.evidence_refs, 8)
            )
        return BehavioralReconstruction(behaviors=behaviors, summary=self.summary)


def _cap(values, limit: int):
    return sorted(set(values))[:limit]