"""Deterministic data-flow finding models.

A :class:`DataFlowFinding` records one source -> sink data-flow path that was
actually established (or not) by the engine's bounded register taint analysis.
Each finding is fully evidence-backed and carries a status that conveys how
confidently a real leak is believed to exist.

Statuses
--------
    CONFIRMED        source and sink connected inside a single method by a
                     direct register-wide data flow (no indirection).
    PROBABLE         a direct flow across an intra-app method boundary, or via
                     an instance/static field that is unambiguously written by
                     the source and read by the sink.
    POSSIBLE         a flow that relies on parameters, virtual dispatch,
                     callback indirection (Handler/Thread/Runnable), or
                     container (Bundle/ClipData/JSON/Cursor) propagation.
    NOT_ESTABLISHED  the same sensitive source and sink were both observed in
                     the app, but no concrete data-flow path could be proven.
                     Optional and capped; included only to keep the output
                     honest about what was *not* connected.

Nothing here imports the malware-family classifier or runs an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class FlowStatus(str, Enum):
    """How confidently a source-to-sink flow was established."""

    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"

    def __str__(self) -> str:  # keep enum str == value for convenience
        return self.value


@dataclass
class DataFlowFinding:
    """One source -> sink data-flow finding (evidence-backed)."""

    flow_id: str
    source: str
    source_method: str
    path: List[str]
    sink: str
    sink_method: str
    transformations: List[str] = field(default_factory=list)
    confidence: str = "low"
    evidence_refs: List[str] = field(default_factory=list)
    status: FlowStatus = FlowStatus.POSSIBLE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source": self.source,
            "source_method": self.source_method,
            "path": list(self.path),
            "transformations": sorted(set(self.transformations)),
            "sink": self.sink,
            "sink_method": self.sink_method,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "status": self.status.value,
        }


@dataclass
class DataFlowResult:
    """Output of the data-flow engine for one APK."""

    findings: List[DataFlowFinding] = field(default_factory=list)
    not_established: List[DataFlowFinding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "stats": dict(self.stats),
            "limitations": list(self.limitations),
            "findings": [f.to_dict() for f in self.findings],
            "not_established": [f.to_dict() for f in self.not_established],
        }

    def by_status(self, status: FlowStatus) -> List[DataFlowFinding]:
        return [f for f in self.findings if f.status == status]

    def sink_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.sink] = counts.get(finding.sink, 0) + 1
        return {k: counts[k] for k in sorted(counts)}

    def source_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.source] = counts.get(finding.source, 0) + 1
        return {k: counts[k] for k in sorted(counts)}
