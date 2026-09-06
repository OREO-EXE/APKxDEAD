"""Unit tests for the structured RE report output."""

import json

from re_engine.models.context import AnalysisContext, Component, Certificate
from re_engine.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)
from re_engine.output.report import (
    ArchitecturalSummary,
    BehavioralReconstruction,
    ReReport,
    build_architectural_summary,
    build_re_report,
    serialize_json,
    serialize_markdown,
)


def populate_context() -> AnalysisContext:
    ctx = AnalysisContext()
    ctx.package_name = "com.example.app"
    ctx.sha256 = "abc123"
    ctx.apk_size = 1024
    ctx.min_sdk = "21"
    ctx.target_sdk = "34"
    ctx.permissions = ["android.permission.INTERNET", "android.permission.SEND_SMS"]
    ctx.components = [
        Component(name="MainActivity", exported=True, kind="activity"),
        Component(name="SmsService", exported=True, kind="service"),
    ]
    ctx.dex.total_classes = 42
    ctx.dex.total_methods = 1200
    ctx.dex.dex_count = 2
    ctx.dex.api_counts = {"NETWORK": 5}
    ctx.urls = ["https://c2.example.com/x"]
    ctx.domains = ["c2.example.com"]
    ctx.ips = ["1.2.3.4"]
    ctx.certificates = [
        Certificate(subject="CN=evilsigner", issuer="CN=ca", sha256="deadbeef")
    ]
    ctx.native_libraries = ["libnative.so"]
    ctx.add_finding(
        Finding(
            category=FindingCategory.NETWORK,
            title="C2 endpoint",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            analyzer="test",
        )
    )
    return ctx


def test_architectural_summary():
    ctx = populate_context()
    summary = build_architectural_summary(ctx)
    assert isinstance(summary, ArchitecturalSummary)
    assert summary.package_name == "com.example.app"
    assert summary.permissions_count == 2
    assert summary.components == {"activity": 1, "service": 1}
    assert summary.classes == 42
    assert summary.methods == 1200


def test_build_re_report_sections():
    ctx = populate_context()
    report = build_re_report(ctx)
    assert isinstance(report, ReReport)
    names = [s.name for s in report.sections]
    assert "identity" in names
    assert "permissions" in names
    assert "components" in names
    assert "dex" in names
    assert "network_indicators" in names
    assert "certificates" in names
    assert "native_libraries" in names


def test_serialize_json_roundtrip():
    ctx = populate_context()
    report = build_re_report(ctx)
    payload = json.loads(serialize_json(report))
    assert payload["package_name"] == "com.example.app"
    assert payload["architectural"]["permissions_count"] == 2
    assert len(payload["findings"]) == 1


def test_serialize_markdown():
    ctx = populate_context()
    report = build_re_report(ctx)
    md = serialize_markdown(report)
    assert "# RE Report" in md
    assert "com.example.app" in md
    assert "C2 endpoint" in md


def test_behavioral_reconstruction_presence():
    ctx = populate_context()
    behavior = BehavioralReconstruction(
        behaviors={"sms_exfiltration": ["find-1"]},
        summary="possible SMS exfiltration",
    )
    report = build_re_report(ctx, behavioral=behavior)
    assert report.behavioral is not None
    assert report.behavioral.behaviors["sms_exfiltration"] == ["find-1"]