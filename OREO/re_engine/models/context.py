"""Central analysis context for the RE engine.

A single :class:`AnalysisContext` travels through the entire pipeline. Every
analyzer contributes evidence to it. It mirrors the provenance of an APK
submission: hashes, package identity, extracted artifacts (manifest, certs,
DEX, strings, native libs) and the accumulated findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from re_engine.models.finding import Finding
from re_engine.models.obfuscation import ObfuscationFinding


@dataclass
class Submission:
    """Who/what submitted the APK and when."""

    apk_path: Optional[str] = None
    server: Optional[str] = None
    user: Optional[str] = None
    submitted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ModuleInfo:
    """Description of a module that contributed to the analysis."""

    name: str
    version: str = "0.1.0"
    description: str = ""


@dataclass
class Component:
    """A manifest-declared Android component."""

    name: str
    exported: bool = False
    kind: str = "activity"  # activity | service | receiver | provider
    intent_filters: List[str] = field(default_factory=list)
    process: Optional[str] = None


@dataclass
class Certificate:
    """Signing certificate details."""

    subject: Optional[str] = None
    issuer: Optional[str] = None
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    signature_algorithm: Optional[str] = None


@dataclass
class NativeLibrary:
    """A native library found under ``lib/<abi>/`` in the APK."""

    name: str
    abi: Optional[str] = None
    size: int = 0
    architecture: Optional[str] = None
    exported_symbols: List[str] = field(default_factory=list)
    suspicious_reasons: List[str] = field(default_factory=list)


@dataclass
class DexSummary:
    """High-level DEX/bytecode information."""

    dex_count: int = 0
    total_classes: int = 0
    total_methods: int = 0
    api_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class AnalysisContext:
    """The single source of truth for one APK's reverse-engineering run."""

    apk_path: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    apk_size: int = 0

    # Extracted manifest
    manifest_xml: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)

    # DEX / bytecode
    dex: DexSummary = field(default_factory=DexSummary)
    classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)

    # Strings / network indicators
    strings: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)

    # Certificates
    certificates: List[Certificate] = field(default_factory=list)
    signature_schemes: List[str] = field(default_factory=list)

    # Native libraries
    native_libraries: List[str] = field(default_factory=list)
    native_lib_details: List[NativeLibrary] = field(default_factory=list)

    # Structure
    structure: Dict[str, object] = field(default_factory=dict)
    suspicious_files: List[str] = field(default_factory=list)
    embedded_archives: List[str] = field(default_factory=list)

    # Permission classification {permission: {"bucket", "protection", ...}}
    permission_classification: Dict[str, Dict[str, object]] = field(
        default_factory=dict
    )

    # Manifest detail
    main_activity: Optional[str] = None
    exported_components: List[str] = field(default_factory=list)
    boot_receivers: List[str] = field(default_factory=list)
    foreground_services: List[str] = field(default_factory=list)
    accessibility_components: List[str] = field(default_factory=list)
    device_admin_components: List[str] = field(default_factory=list)
    intent_filters: Dict[str, List[str]] = field(default_factory=dict)
    application_flags: Dict[str, object] = field(default_factory=dict)

    # DEX / bytecode detail
    packages: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    method_signatures: List[str] = field(default_factory=list)
    api_references: List[str] = field(default_factory=list)
    inheritance: Dict[str, str] = field(default_factory=dict)
    interfaces: Dict[str, List[str]] = field(default_factory=dict)

    # Strings detail
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    shell_commands: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    encoded_strings: List[str] = field(default_factory=list)

    # Obfuscation / anti-analysis (structured, measured metrics)
    obfuscation: List[ObfuscationFinding] = field(default_factory=list)

    # Raw artifacts (populated by the engine, not analyzers)
    artifacts: Optional["ApkAccessor"] = None

    # Evidence
    findings: List[Finding] = field(default_factory=list)

    # Processing metadata
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    modules: List[ModuleInfo] = field(default_factory=list)
    submission: Submission = field(default_factory=Submission)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: Optional[str] = None

    # ------------------------------------------------------------------
    # Evidence contribution
    # ------------------------------------------------------------------
    def add_finding(self, finding: Finding) -> None:
        """Register a finding and wire its analyzer id if not provided."""
        self.findings.append(finding)

    def findings_by_category(self):
        from re_engine.models.finding import FindingCategory

        by: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            by.setdefault(finding.category.value, []).append(finding)
        return by

    def findings_by_severity(self):
        from re_engine.models.finding import Severity

        order = [s for s in Severity]
        by: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            by.setdefault(finding.severity.value, []).append(finding)
        return by

    def oldest_findings(self, limit: int = 50) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.timestamp)[:limit]

    # ------------------------------------------------------------------
    # Warnings / errors
    # ------------------------------------------------------------------
    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def register_module(self, name: str, version: str = "0.1.0",
                        description: str = "") -> None:
        self.modules.append(ModuleInfo(name, version, description))

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------
    def component_names(self, kind: Optional[str] = None) -> List[str]:
        if kind is None:
            return [c.name for c in self.components]
        return [c.name for c in self.components if c.kind == kind]

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def mark_completed(self) -> None:
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def is_complete(self) -> bool:
        return self.completed_at is not None
