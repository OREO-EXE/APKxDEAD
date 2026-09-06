"""Unit tests for the central AnalysisContext."""

from re_engine.models.context import AnalysisContext, Component, Certificate
from re_engine.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)


def make_finding():
    return Finding(
        category=FindingCategory.PERMISSION,
        title="Suspicious permission",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        analyzer="test",
    )


def test_context_defaults():
    ctx = AnalysisContext()
    assert ctx.findings == []
    assert ctx.warnings == []
    assert ctx.errors == []
    assert ctx.apk_size == 0
    assert not ctx.is_complete()


def test_context_add_finding_and_grouping():
    ctx = AnalysisContext()
    f1 = make_finding()
    f2 = Finding(
        category=FindingCategory.NETWORK,
        title="C2 URL",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        analyzer="test",
    )
    ctx.add_finding(f1)
    ctx.add_finding(f2)

    assert len(ctx.findings) == 2
    by_category = ctx.findings_by_category()
    assert set(by_category.keys()) == {"PERMISSION", "NETWORK"}
    assert len(by_category["NETWORK"]) == 1

    by_severity = ctx.findings_by_severity()
    assert len(by_severity["HIGH"]) == 1


def test_context_warn_error_register_module():
    ctx = AnalysisContext()
    ctx.warn("low disk space")
    ctx.error("dex parse failed")
    ctx.register_module("manifest", "0.1.0", "extracts manifest")

    assert ctx.warnings == ["low disk space"]
    assert ctx.errors == ["dex parse failed"]
    assert ctx.modules[0].name == "manifest"


def test_context_components_and_permissions():
    ctx = AnalysisContext()
    ctx.permissions = ["android.permission.INTERNET", "android.permission.SEND_SMS"]
    ctx.components = [
        Component(name="MainActivity", exported=True, kind="activity"),
        Component(name="SmsService", exported=True, kind="service"),
    ]

    assert ctx.has_permission("android.permission.SEND_SMS")
    assert not ctx.has_permission("android.permission.CAMERA")

    assert ctx.component_names() == ["MainActivity", "SmsService"]
    assert ctx.component_names("service") == ["SmsService"]
    assert set(ctx.component_names("activity")) == {"MainActivity"}


def test_context_completion_markers():
    ctx = AnalysisContext()
    assert not ctx.is_complete()
    ctx.mark_completed()
    assert ctx.is_complete()
    assert ctx.completed_at is not None
    assert ctx.completed_at >= ctx.started_at