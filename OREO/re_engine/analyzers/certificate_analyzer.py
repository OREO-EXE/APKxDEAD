"""Signing certificate triage analyzer.

Reads the APK signing certificates via androguard (asn1crypto-backed) and
records subject/issuer, fingerprints, validity and signature algorithm, the
used signing schemes, plus deterministic expiry/self-signed findings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext, Certificate
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)


class CertificateAnalyzer(BaseAnalyzer):
    """Capture signing certificates and flag expiry / self-signed status."""

    name = "certificate"
    version = "0.1.0"
    description = "Signing certificate extraction and triage"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts
        apk = accessor.androguard_apk if accessor else None

        if apk is None or not context.certificates:
            cert_objects = self._certificate_objects(apk)
            records = context.certificates or []
            for cert in cert_objects:
                records.append(_to_certificate(cert))
            context.certificates = records
        else:
            cert_objects = []

        if not context.signature_schemes and apk is not None:
            context.signature_schemes = _detect_schemes(apk)

        now = datetime.now(timezone.utc)
        for index, cert in enumerate(context.certificates):
            if cert.not_after:
                parsed, _ = _parse_time(cert.not_after)
                if parsed and parsed < now:
                    self.emit(
                        context,
                        Finding(
                            category=FindingCategory.CERTIFICATE,
                            title="Expired signing certificate",
                            description=(
                                f"Certificate #{index + 1} expired on "
                                f"{cert.not_after} (subject={cert.subject or 'N/A'})."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            evidence_type=EvidenceType.CERTIFICATE,
                            source_file="META-INF/*",
                            metadata={"cert_index": index},
                        ),
                    )
            if cert.subject and cert.subject == cert.issuer:
                self.emit(
                    context,
                    Finding(
                        category=FindingCategory.CERTIFICATE,
                        title="Self-signed certificate",
                        description=(
                            "Signing certificate is self-signed "
                            f"(subject == issuer): {cert.subject}."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        evidence_type=EvidenceType.CERTIFICATE,
                        source_file="META-INF/*",
                        metadata={"cert_index": index},
                    ),
                )

        if context.certificates:
            self.emit(
                context,
                Finding(
                    category=FindingCategory.CERTIFICATE,
                    title="Signing certificates captured",
                    description=(
                        f"certs={len(context.certificates)} "
                        f"schemes={','.join(context.signature_schemes) or 'none'}"
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.CERTIFICATE,
                    source_file="META-INF/*",
                ),
            )

    def _certificate_objects(self, apk):
        if apk is None:
            return []
        try:
            return list(apk.get_certificates())
        except Exception:
            return []


# ----------------------------------------------------------------------
def _to_certificate(cert) -> Certificate:
    record = Certificate()
    try:
        record.subject = cert.subject.human_friendly
    except Exception:
        pass
    try:
        record.issuer = cert.issuer.human_friendly
    except Exception:
        pass
    try:
        record.sha256 = cert.sha256
    except Exception:
        pass
    try:
        record.sha1 = cert.sha1
    except Exception:
        pass
    try:
        record.serial = str(cert.serial_number)
    except Exception:
        pass
    try:
        record.not_before = cert.not_valid_before.isoformat()
    except Exception:
        pass
    try:
        record.not_after = cert.not_valid_after.isoformat()
    except Exception:
        pass
    try:
        record.signature_algorithm = cert.signature_algo
    except Exception:
        pass
    return record


def _detect_schemes(apk) -> List[str]:
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
    return schemes


def _parse_time(value: str):
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None, False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed, True