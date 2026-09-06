"""Structured RE report models and serializers.

The final stage of the pipeline converts the accumulated :class:
`~re_engine.models.context.AnalysisContext` (plus any behavioral
reconstruction) into a structured, machine-readable RE report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from re_engine.models.context import AnalysisContext
from re_engine.models.finding import Finding


@dataclass
class ReReportSection:
    """A single named section of the RE report."""

    name: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ArchitecturalSummary:
    """Structural snapshot of the APK (manifest + DEX surface)."""

    package_name: Optional[str] = None
    sha256: Optional[str] = None
    apk_size: int = 0
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    permissions_count: int = 0
    components: Dict[str, int] = field(default_factory=dict)
    classes: int = 0
    methods: int = 0
    dex_count: int = 0
    native_libraries: List[str] = field(default_factory=list)


@dataclass
class BehavioralReconstruction:
    """Output of the behavioral reconstruction stage.

    ``behaviors`` maps a behavior label (e.g. ``sms_exfiltration``) to the
    findings that support it.
    """

    behaviors: Dict[str, List[str]] = field(default_factory=dict)
    summary: str = ""


@dataclass
class ReReport:
    """Structured reverse-engineering report."""

    package_name: Optional[str] = None
    sha256: Optional[str] = None
    pipeline_version: str = "0.1.0"
    sections: List[ReReportSection] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    architectural: Optional[ArchitecturalSummary] = None
    behavioral: Optional[BehavioralReconstruction] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "package_name": self.package_name,
            "sha256": self.sha256,
            "pipeline_version": self.pipeline_version,
            "sections": [s.__dict__ for s in self.sections],
            "findings": self.findings,
            "architectural": (
                self.architectural.__dict__ if self.architectural else None
            ),
            "behavioral": (
                self.behavioral.__dict__ if self.behavioral else None
            ),
            "warnings": self.warnings,
            "errors": self.errors,
        }
        return data


def build_architectural_summary(context: AnalysisContext) -> ArchitecturalSummary:
    components = {}
    for component in context.components:
        components[component.kind] = components.get(component.kind, 0) + 1

    return ArchitecturalSummary(
        package_name=context.package_name,
        sha256=context.sha256,
        apk_size=context.apk_size,
        min_sdk=context.min_sdk,
        target_sdk=context.target_sdk,
        permissions_count=len(context.permissions),
        components=components,
        classes=context.dex.total_classes,
        methods=context.dex.total_methods,
        dex_count=context.dex.dex_count,
        native_libraries=list(context.native_libraries),
    )


def build_re_report(
    context: AnalysisContext,
    behavioral: Optional[BehavioralReconstruction] = None,
    code_reconstruction: Optional[Dict[str, Any]] = None,
    suspicion_ranking: Optional[Dict[str, Any]] = None,
    callgraph: Optional[Dict[str, Any]] = None,
    dataflow: Optional[Dict[str, Any]] = None,
    behavior: Optional[Dict[str, Any]] = None,
) -> ReReport:
    """Assemble the structured RE report from the analysis context."""
    report = ReReport(
        package_name=context.package_name,
        sha256=context.sha256,
        findings=[f.to_dict() for f in context.findings],
        architectural=build_architectural_summary(context),
        behavioral=behavioral,
        warnings=list(context.warnings),
        errors=list(context.errors),
    )

    report.sections.append(
        ReReportSection(
            name="identity",
            data={
                "package_name": context.package_name,
                "app_name": context.app_name,
                "version_name": context.version_name,
                "version_code": context.version_code,
                "sha256": context.sha256,
                "apk_size": context.apk_size,
            },
        )
    )
    report.sections.append(
        ReReportSection(
            name="permissions",
            data={"permissions": sorted(context.permissions)},
        )
    )
    report.sections.append(
        ReReportSection(
            name="components",
            data={
                component.kind: [
                    c.name for c in context.components if c.kind == component.kind
                ]
                for component in context.components
            },
        )
    )
    report.sections.append(
        ReReportSection(
            name="dex",
            data={
                "dex_count": context.dex.dex_count,
                "classes": context.dex.total_classes,
                "methods": context.dex.total_methods,
                "api_counts": context.dex.api_counts,
            },
        )
    )
    report.sections.append(
        ReReportSection(
            name="network_indicators",
            data={
                "urls": context.urls,
                "domains": context.domains,
                "ips": context.ips,
            },
        )
    )
    report.sections.append(
        ReReportSection(
            name="certificates",
            data=[c.__dict__ for c in context.certificates],
        )
    )
    report.sections.append(
        ReReportSection(
            name="native_libraries",
            data={
                "libraries": sorted(context.native_libraries),
                "details": [n.__dict__ for n in context.native_lib_details],
            },
        )
    )
    report.sections.append(
        ReReportSection(
            name="permission_classification",
            data=context.permission_classification,
        )
    )
    report.sections.append(
        ReReportSection(
            name="manifest_detail",
            data={
                "main_activity": context.main_activity,
                "exported_components": sorted(context.exported_components),
                "boot_receivers": sorted(context.boot_receivers),
                "foreground_services": sorted(context.foreground_services),
                "accessibility_components": sorted(
                    context.accessibility_components
                ),
                "device_admin_components": sorted(
                    context.device_admin_components
                ),
                "application_flags": context.application_flags,
                "signature_schemes": context.signature_schemes,
            },
        )
    )
    report.sections.append(
        ReReportSection(
            name="structure",
            data=context.structure,
        )
    )
    report.sections.append(
        ReReportSection(
            name="strings_summary",
            data={
                "urls": context.urls[:200],
                "ipv4": context.ipv4[:200],
                "ipv6": context.ipv6[:200],
                "emails": context.emails[:200],
                "file_paths": context.file_paths[:200],
                "shell_commands": context.shell_commands[:200],
                "suspicious_keywords": context.suspicious_keywords[:200],
                "encoded_strings": context.encoded_strings[:200],
            },
        )
    )

    if getattr(context, "obfuscation", None):
        report.sections.append(
            ReReportSection(
                name="obfuscation",
                data=[f.to_dict() for f in context.obfuscation],
            )
        )

    if code_reconstruction:
        report.sections.append(
            ReReportSection(
                name="code_reconstruction",
                data=code_reconstruction,
            )
        )

    if suspicion_ranking:
        report.sections.append(
            ReReportSection(
                name="suspicion_ranking",
                data=suspicion_ranking,
            )
        )

    if callgraph:
        report.sections.append(
            ReReportSection(
                name="callgraph",
                data=callgraph,
            )
        )

    if dataflow:
        report.sections.append(
            ReReportSection(
                name="dataflow",
                data=dataflow,
            )
        )

    if behavior:
        report.sections.append(
            ReReportSection(
                name="behavior",
                data=behavior,
            )
        )

    return report


def serialize_json(report: ReReport, pretty: bool = True) -> str:
    indent = 2 if pretty else None
    return json.dumps(report.to_dict(), indent=indent, default=str, sort_keys=False)


def serialize_markdown(report: ReReport) -> str:
    """A minimal human-readable markdown rendering of the report."""
    lines: List[str] = []
    lines.append("# RE Report")
    lines.append("")
    lines.append(f"- **Package**: {report.package_name or 'N/A'}")
    lines.append(f"- **SHA-256**: {report.sha256 or 'N/A'}")
    lines.append(f"- **Pipeline**: {report.pipeline_version}")
    lines.append("")

    if report.architectural:
        arch = report.architectural
        lines.append("## Architecture")
        lines.append("")
        lines.append(
            f"- Classes: {arch.classes} | Methods: {arch.methods} | "
            f"DEX files: {arch.dex_count}"
        )
        lines.append(f"- Permissions: {arch.permissions_count}")
        if arch.components:
            for kind, count in sorted(arch.components.items()):
                lines.append(f"- {kind}: {count}")
        if arch.native_libraries:
            lines.append(
                "- Native libraries: " + ", ".join(sorted(arch.native_libraries))
            )
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if report.findings:
        for finding in report.findings:
            lines.append(
                f"- [{finding.get('severity', 'INFO')}] "
                f"{finding.get('title', '')} "
                f"({finding.get('confidence', 'UNKNOWN')})"
            )
    else:
        lines.append("- No findings recorded.")
    lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in report.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for error in report.errors:
            lines.append(f"- {error}")
        lines.append("")

    return "\n".join(lines)