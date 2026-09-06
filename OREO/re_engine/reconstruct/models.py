"""Data models for the code-reconstruction subsystem.

The reconstruction stage converts raw DEX bytecode into a normalized
:class:`CodeArtifact` (Smali or Java representation plus the observed
references). The models here are self-contained: they only depend on the
standard library so they can be imported and (de)serialized anywhere in the
pipeline.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ARTIFACT_CLASS = "class"
ARTIFACT_METHOD = "method"
LANGUAGE_SMALI = "smali"
LANGUAGE_JAVA = "java"

ARTIFACT_TYPES = (ARTIFACT_CLASS, ARTIFACT_METHOD)
LANGUAGES = (LANGUAGE_SMALI, LANGUAGE_JAVA)

# Deterministic default caps for a bounded reconstruction run.
DEFAULT_METHOD_ARTIFACTS = 40
DEFAULT_CLASS_ARTIFACTS = 12
DEFAULT_JAVA_METHODS = 5
DEFAULT_JAVA_CLASSES = 5
DEFAULT_SOURCE_CAP = 20000
DEFAULT_REF_CAP = 200
DEFAULT_CALLER_SCAN_CAP = 15000
DEFAULT_FINDING_TARGET_CAP = 10
DEFAULT_COMPONENT_CLASS_CAP = 5
DEFAULT_COMPONENT_METHODS_PER_CLASS = 8
DEFAULT_FALLBACK_METHOD_CAP = 10


@dataclass
class CodeArtifact:
    """A normalized, serializable piece of reconstructed code.

    ``type`` is ``"class"`` or ``"method"``. ``language`` is ``"smali"``
    (authoritative, rebuilt straight from DEX instructions) or ``"java"``
    (best-effort reconstruction from a decompiler backend - never
    authoritative). ``evidence_refs`` carries only references that were
    directly observed in the method/class bytecode.
    """

    artifact_id: str
    type: str
    class_name: str
    method_name: Optional[str]
    signature: str
    source: str
    language: str
    source_location: str
    evidence_refs: List[Dict[str, str]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "type": self.type,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "signature": self.signature,
            "language": self.language,
            "source": self.source,
            "source_location": self.source_location,
            "evidence_refs": self.evidence_refs,
        }
        if self.provenance:
            data["provenance"] = self.provenance
        if self.metadata:
            data["metadata"] = self.metadata
        return data


@dataclass
class ReconstructionResult:
    """Output of a reconstruction run over one APK's DEX files."""

    artifacts: List[CodeArtifact] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    reaching_components: Dict[str, List[str]] = field(default_factory=dict)
    summary: str = ""
    backend: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "backend": self.backend,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "errors": list(self.errors),
            "stats": dict(self.stats),
            "reaching_components": {
                mid: sorted(components)
                for mid, components in self.reaching_components.items()
            },
        }

    def to_behavioral(self):
        """Convert into the report-level behavioral reconstruction object."""
        from re_engine.output.report import BehavioralReconstruction

        return BehavioralReconstruction(behaviors={}, summary=self.summary)


def artifact_id(
    artifact_type: str,
    class_descriptor: str,
    method_name: Optional[str],
    signature: str,
    language: str,
    source: str,
) -> str:
    """Deterministic artifact id: stable across runs for identical content."""
    raw = "|".join(
        [
            artifact_type,
            class_descriptor,
            method_name or "",
            signature,
            language,
            source[:512],
        ]
    )
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    return f"art_{digest[:24]}"