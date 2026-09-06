"""Standardized evidence model for the RE engine.

Every analyzer (and future AI stages) contributes findings through this single
model. Findings are the only way evidence enters the AnalysisContext.

Confidence contract
-------------------
An analyzer/AI must NEVER claim evidence that does not exist. If evidence was
not directly observed, the finding must lower its ``confidence`` to one of the
allowed values rather than fabricate supporting references. See
:class:`Confidence`.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


class Confidence(str, enum.Enum):
    """Allowed confidence values for a finding."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Severity(str, enum.Enum):
    """Impact/severity of a finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, enum.Enum):
    """High-level category of a finding."""

    MANIFEST = "MANIFEST"
    PERMISSION = "PERMISSION"
    COMPONENT = "COMPONENT"
    DEX = "DEX"
    API = "API"
    STRING = "STRING"
    NETWORK = "NETWORK"
    CERTIFICATE = "CERTIFICATE"
    NATIVE_LIB = "NATIVE_LIB"
    BEHAVIOR = "BEHAVIOR"
    INFORMATION = "INFORMATION"
    WARNING = "WARNING"
    ERROR = "ERROR"


class EvidenceType(str, enum.Enum):
    """Type of evidence a finding is based on."""

    MANIFEST = "MANIFEST"
    PERMISSION = "PERMISSION"
    DEX = "DEX"
    API = "API"
    STRING = "STRING"
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    CERTIFICATE = "CERTIFICATE"
    NATIVE_LIB = "NATIVE_LIB"
    CODE = "CODE"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"


class FindingStatus(str, enum.Enum):
    """Lifecycle status of a finding."""

    OPEN = "OPEN"
    REVIEWED = "REVIEWED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"


@dataclass
class Finding:
    """A single, standardized piece of reversible-engineering evidence.

    All fields are optional at construction time except ``category`` and
    ``title``; defaults are provided for safety. An analyzer must only set
    ``supporting_api`` / ``supporting_string`` / ``supporting_url`` when the
    referenced evidence genuinely exists in the context.
    """

    category: FindingCategory
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.UNKNOWN
    evidence_type: EvidenceType = EvidenceType.OBSERVED
    finding_id: str = field(default_factory=lambda: f"find_{uuid.uuid4().hex[:12]}")
    source_file: Optional[str] = None
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    instruction_ref: Optional[str] = None
    line_ref: Optional[int] = None
    supporting_api: Optional[str] = None
    supporting_string: Optional[str] = None
    supporting_url: Optional[str] = None
    parent_id: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    analyzer: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN
    metadata: Dict[str, object] = field(default_factory=dict)

    def promote_confidence(self, confidence: Confidence) -> None:
        """Raise the finding confidence to the given value."""
        self.confidence = confidence

    def demote_confidence(self, confidence: Confidence) -> None:
        """Lower the finding confidence to the given value.

        This is an explicit anti-overclaim safeguard.
        """
        self.confidence = confidence

    def set_status(self, status: FindingStatus) -> None:
        self.status = status

    def to_dict(self) -> Dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence_type": self.evidence_type.value,
            "source_file": self.source_file,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "instruction_ref": self.instruction_ref,
            "line_ref": self.line_ref,
            "supporting_api": self.supporting_api,
            "supporting_string": self.supporting_string,
            "supporting_url": self.supporting_url,
            "parent_id": self.parent_id,
            "timestamp": self.timestamp,
            "analyzer": self.analyzer,
            "status": self.status.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Finding":
        kept = {k: v for k, v in data.items() if k != "metadata"}

        def coerce(field_name: str, enum_type):
            value = kept.get(field_name)
            if isinstance(value, enum_type):
                return
            if value is not None:
                kept[field_name] = enum_type(value)

        coerce("category", FindingCategory)
        coerce("severity", Severity)
        coerce("confidence", Confidence)
        coerce("evidence_type", EvidenceType)
        coerce("status", FindingStatus)

        finding = cls(**kept)
        if "metadata" in data and isinstance(data["metadata"], dict):
            finding.metadata = data["metadata"]
        return finding
