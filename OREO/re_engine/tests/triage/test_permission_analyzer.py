"""Unit tests for the permission triage analyzer."""

from re_engine.analyzers.permission_analyzer import PermissionAnalyzer
from re_engine.analyzers.permission_data import (
    BUCKET_DANGEROUS,
    BUCKET_NORMAL,
    BUCKET_SUSPICIOUS,
)
from re_engine.models.context import AnalysisContext

from .fixtures import FakeApk, inject_fakes, real_accessor


def _ctx(tmp_path, permissions):
    path = tmp_path / "app.apk"
    path.write_bytes(b"")
    accessor = real_accessor(path)
    inject_fakes(accessor, fake_apk=FakeApk(permissions=permissions))
    ctx = AnalysisContext()
    ctx.artifacts = accessor
    return ctx


def test_classifies_buckets(tmp_path):
    ctx = _ctx(
        tmp_path,
        [
            "android.permission.INTERNET",        # normal
            "android.permission.READ_MEDIA_AUDIO",  # dangerous (not suspicious)
            "android.permission.SEND_SMS",        # dangerous AND secure-relevant -> suspicious
            "android.permission.FORCE_STOP_PACKAGES",  # privileged
        ],
    )
    PermissionAnalyzer().run(ctx)

    assert set(ctx.permission_classification) == {
        "android.permission.INTERNET",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.SEND_SMS",
        "android.permission.FORCE_STOP_PACKAGES",
    }
    assert (
        ctx.permission_classification["android.permission.INTERNET"]["bucket"]
        == BUCKET_NORMAL
    )
    assert (
        ctx.permission_classification["android.permission.READ_MEDIA_AUDIO"]["bucket"]
        == BUCKET_DANGEROUS
    )
    assert (
        ctx.permission_classification["android.permission.SEND_SMS"]["bucket"]
        == BUCKET_SUSPICIOUS
    )
    assert (
        ctx.permission_classification["android.permission.FORCE_STOP_PACKAGES"]["bucket"]
        == "privileged"
    )


def test_suspicious_permission_flagged_medium(tmp_path):
    # SYSTEM_ALERT_WINDOW is security-relevant; floats to the suspicious bucket.
    perm = "android.permission.SYSTEM_ALERT_WINDOW"
    ctx = _ctx(tmp_path, [perm])
    PermissionAnalyzer().run(ctx)

    assert ctx.permission_classification[perm]["bucket"] == BUCKET_SUSPICIOUS
    assert ctx.permission_classification[perm]["security_relevant"] is True
    flagged = [
        f for f in ctx.findings
        if f.metadata.get("permission") == perm
        and f.title == "Security-relevant permission declared"
    ]
    assert len(flagged) == 1
    assert flagged[0].severity.value == "MEDIUM"
    assert flagged[0].evidence_type.value == "PERMISSION"


def test_dangerous_permission_flagged_low(tmp_path):
    ctx = _ctx(tmp_path, ["android.permission.READ_MEDIA_AUDIO"])
    PermissionAnalyzer().run(ctx)
    flagged = [
        f for f in ctx.findings
        if f.metadata.get("permission") == "android.permission.READ_MEDIA_AUDIO"
    ]
    assert flagged[0].severity.value == "LOW"


def test_findings_reference_declared_permission(tmp_path):
    from re_engine.utils.validate import validate_finding_support

    ctx = _ctx(tmp_path, ["android.permission.SEND_SMS"])
    PermissionAnalyzer().run(ctx)
    for finding in ctx.findings:
        violations = validate_finding_support(ctx, finding)
        assert violations == []


def test_summary_finding(tmp_path):
    ctx = _ctx(tmp_path, ["android.permission.INTERNET"])
    PermissionAnalyzer().run(ctx)
    assert any(
        f.title == "Permissions analyzed" for f in ctx.findings
    )