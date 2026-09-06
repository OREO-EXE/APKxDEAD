"""APK metadata triage analyzer.

Reuses the androguard-backed ``MetadataExtractor`` from the repository's
feature extraction layer and records additional signing information.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)

try:
    from ai.feature_extraction.metadata_extractor import MetadataExtractor
except Exception:  # pragma: no cover - repo layout unchanged
    MetadataExtractor = None  # type: ignore[assignment]


class MetadataAnalyzer(BaseAnalyzer):
    """Capture hash, size, package identity and signing scheme."""

    name = "metadata"
    version = "0.1.0"
    description = "APK metadata: hashes, identity, SDK levels, signing"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts
        apk = accessor.androguard_apk if accessor else None

        if context.sha256 is None:
            context.sha256 = _sha256_of(accessor.apk_path)
        if context.md5 is None:
            context.md5 = _md5_of(accessor.apk_path)
        context.apk_size = accessor.apk_path.stat().st_size

        if apk is not None:
            context.package_name = _safe_get(apk, "get_package")
            context.app_name = _safe_get(apk, "get_app_name")
            context.version_name = _safe_get(apk, "get_androidversion_name")
            context.version_code = _safe_get(apk, "get_androidversion_code")
            context.min_sdk = _safe_get(apk, "get_min_sdk_version")
            context.target_sdk = _safe_get(apk, "get_target_sdk_version")
            _record_signing_schemes(context, apk)

        if context.package_name:
            self.emit(
                context,
                Finding(
                    category=FindingCategory.INFORMATION,
                    title="APK metadata captured",
                    description=(
                        f"package={context.package_name} "
                        f"label={context.app_name or 'N/A'} "
                        f"version={context.version_name or '?'} "
                        f"({context.version_code or '?'}) "
                        f"sdk={context.min_sdk}/{context.target_sdk}"
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.OBSERVED,
                    source_file=context.apk_path,
                ),
            )


def _safe_get(apk, method_name: str):
    try:
        return getattr(apk, method_name)()
    except Exception:
        return None


def _record_signing_schemes(context: AnalysisContext, apk) -> None:
    schemes = []
    for label, check in (
        ("v1", "is_signed_v1"),
        ("v2", "is_signed_v2"),
        ("v3", "is_signed_v3"),
        ("v31", "is_signed_v31"),
    ):
        try:
            if getattr(apk, check)():
                schemes.append(label)
        except Exception:
            continue
    context.signature_schemes = schemes


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _md5_of(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()