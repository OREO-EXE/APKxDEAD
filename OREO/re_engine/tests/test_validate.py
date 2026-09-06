"""Unit tests for the evidence-validation safeguard."""

from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)
from re_engine.utils.validate import validate_finding_support


def test_valid_finding_passes():
    ctx = AnalysisContext()
    ctx.strings = ["https://c2.example.com/x"]
    ctx.urls = ["https://c2.example.com/x"]

    finding = Finding(
        category=FindingCategory.NETWORK,
        title="C2 endpoint",
        supporting_url="https://c2.example.com/x",
        supporting_string="https://c2.example.com/x",
    )
    assert validate_finding_support(ctx, finding) == []


def test_url_not_observed_is_flagged():
    ctx = AnalysisContext()
    finding = Finding(
        category=FindingCategory.NETWORK,
        title="Phantom C2",
        supporting_url="https://nonexistent.example.com/upload",
    )
    violations = validate_finding_support(ctx, finding)
    assert len(violations) == 1
    assert "supporting_url not found" in violations[0]


def test_api_not_observed_is_flagged():
    ctx = AnalysisContext()
    finding = Finding(
        category=FindingCategory.API,
        title="Suspicious API",
        supporting_api="Lcom/evil/CommandExec;->execute",
    )
    violations = validate_finding_support(ctx, finding)
    assert "supporting_api not found" in violations[0]


def test_api_observed_in_classes_passes():
    ctx = AnalysisContext()
    ctx.classes = ["Lcom/evil/CommandExec;"]
    finding = Finding(
        category=FindingCategory.API,
        title="CommandExec",
        supporting_api="Lcom/evil/CommandExec;",
    )
    assert validate_finding_support(ctx, finding) == []


def test_permission_finding_must_be_declared():
    ctx = AnalysisContext()
    ctx.permissions = ["android.permission.INTERNET"]

    honest = Finding(
        category=FindingCategory.PERMISSION,
        title="android.permission.INTERNET",
        evidence_type=EvidenceType.PERMISSION,
    )
    assert validate_finding_support(ctx, honest) == []

    dishonest = Finding(
        category=FindingCategory.PERMISSION,
        title="android.permission.CAMERA",
        evidence_type=EvidenceType.PERMISSION,
        severity=Severity.HIGH,
    )
    violations = validate_finding_support(ctx, dishonest)
    assert "permission not declared" in violations[0]


def test_descriptive_permission_title_uses_metadata():
    """Descriptive titles (not permission-shaped) are checked via metadata."""
    ctx = AnalysisContext()
    ctx.permissions = ["android.permission.SEND_SMS"]

    ok = Finding(
        category=FindingCategory.PERMISSION,
        title="Security-relevant permission declared",
        evidence_type=EvidenceType.PERMISSION,
        metadata={"permission": "android.permission.SEND_SMS"},
    )
    assert validate_finding_support(ctx, ok) == []

    lying = Finding(
        category=FindingCategory.PERMISSION,
        title="Security-relevant permission declared",
        evidence_type=EvidenceType.PERMISSION,
        metadata={"permission": "com.example.fake.PERM"},
    )
    violations = validate_finding_support(ctx, lying)
    assert "permission not declared" in violations[0]