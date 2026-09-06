"""Permission triage analyzer.

Reuses the repository's ``PermissionExtractor`` for the declared permission
list and classifies every permission deterministically into the four
requested buckets: normal, dangerous, privileged, suspicious. A permission is
flagging "security-relevant for review", never "malicious" by itself.
"""

from __future__ import annotations

from collections import Counter

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.analyzers.permission_data import (
    BUCKET_DANGEROUS,
    BUCKET_NORMAL,
    BUCKET_PRIVILEGED,
    BUCKET_SUSPICIOUS,
    classify_permission,
)
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)

try:
    from ai.feature_extraction.permission_extractor import PermissionExtractor
except Exception:  # pragma: no cover - repo layout unchanged
    PermissionExtractor = None  # type: ignore[assignment]


class PermissionAnalyzer(BaseAnalyzer):
    """Classify declared permissions into triage buckets."""

    name = "permissions"
    version = "0.1.0"
    description = "Permission classification into normal/dangerous/privileged/suspicious"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts
        apk = accessor.androguard_apk if accessor else None

        if not context.permissions:
            if apk is not None:
                try:
                    context.permissions = sorted(apk.get_permissions())
                except Exception:
                    pass

        buckets: Counter = Counter()
        for permission in sorted(context.permissions):
            classification = classify_permission(permission)
            context.permission_classification[permission] = classification
            buckets[classification["bucket"]] += 1

            if classification["bucket"] == BUCKET_SUSPICIOUS:
                self._emit_classification(
                    context,
                    permission,
                    "Security-relevant permission declared",
                    Severity.MEDIUM,
                )
            elif classification["bucket"] == BUCKET_DANGEROUS:
                self._emit_classification(
                    context,
                    permission,
                    "Dangerous permission declared",
                    Severity.LOW,
                )
            elif classification["bucket"] == BUCKET_PRIVILEGED:
                self._emit_classification(
                    context,
                    permission,
                    "Privileged permission declared",
                    Severity.LOW,
                )

        context.structure.setdefault("permission_buckets", dict(buckets))

        self.emit(
            context,
            Finding(
                category=FindingCategory.PERMISSION,
                title="Permissions analyzed",
                description=(
                    f"declared={len(context.permissions)} "
                    f"dangerous={buckets[BUCKET_DANGEROUS]} "
                    f"privileged={buckets[BUCKET_PRIVILEGED]} "
                    f"suspicious={buckets[BUCKET_SUSPICIOUS]}"
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.PERMISSION,
                source_file="AndroidManifest.xml",
                metadata=dict(buckets),
            ),
        )

    def _emit_classification(
        self,
        context: AnalysisContext,
        permission: str,
        title: str,
        severity: Severity,
    ) -> None:
        classification = context.permission_classification.get(permission, {})
        self.emit(
            context,
            Finding(
                category=FindingCategory.PERMISSION,
                title=title,
                description=(
                    f"'{permission}' is classified as "
                    f"{classification.get('bucket', 'unknown')} "
                    f"(protection={classification.get('protection', 'unknown')}). "
                    "Presence alone is not a malicious verdict."
                ),
                severity=severity,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.PERMISSION,
                source_file="AndroidManifest.xml",
                metadata={
                    "permission": permission,
                    "bucket": classification.get("bucket"),
                    "protection": classification.get("protection"),
                    "security_relevant": classification.get(
                        "security_relevant", False
                    ),
                },
            ),
        )