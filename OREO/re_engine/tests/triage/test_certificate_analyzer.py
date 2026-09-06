"""Unit tests for the certificate triage analyzer (fake certs)."""

from datetime import datetime, timedelta, timezone

from re_engine.analyzers.certificate_analyzer import CertificateAnalyzer
from re_engine.models.context import AnalysisContext

from .fixtures import FakeApk, FakeCertificate, inject_fakes, real_accessor


def _ctx(tmp_path, certificates, schemes=None):
    path = tmp_path / "app.apk"
    path.write_bytes(b"")
    accessor = real_accessor(path)
    inject_fakes(
        accessor,
        fake_apk=FakeApk(
            certificates=certificates,
            schemes=schemes or ["v1", "v2", "v3"],
        ),
    )
    ctx = AnalysisContext()
    ctx.artifacts = accessor
    return ctx


def test_certificate_record_populated(tmp_path):
    ctx = _ctx(
        tmp_path,
        [
            FakeCertificate(
                subject="CN=Test Org",
                sha256="c" * 64,
                sha1="d" * 40,
                serial="987",
            )
        ],
    )
    CertificateAnalyzer().run(ctx)

    assert len(ctx.certificates) == 1
    cert = ctx.certificates[0]
    assert cert.subject == "CN=Test Org"
    assert cert.issuer == "CN=Test Org"
    assert cert.sha256 == "c" * 64
    assert cert.sha1 == "d" * 40
    assert cert.serial == "987"
    assert cert.signature_algorithm == "sha256WithRSAEncryption"
    assert ctx.signature_schemes == ["v1", "v2", "v3"]


def test_self_signed_flagged(tmp_path):
    ctx = _ctx(
        tmp_path,
        [FakeCertificate(subject="CN=A", issuer="CN=A")],
    )
    CertificateAnalyzer().run(ctx)
    assert any(
        f.title == "Self-signed certificate" for f in ctx.findings
    )


def test_expired_certificate_flagged(tmp_path):
    expired = FakeCertificate(
        not_before=datetime(2015, 1, 1),
        not_after=datetime(2020, 1, 1),
    )
    ctx = _ctx(tmp_path, [expired])
    CertificateAnalyzer().run(ctx)
    findings = [f for f in ctx.findings if f.title == "Expired signing certificate"]
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_valid_certificate_not_expired(tmp_path):
    valid = FakeCertificate(
        not_before=datetime(2020, 1, 1),
        not_after=datetime.now(timezone.utc) + timedelta(days=365),
    )
    ctx = _ctx(tmp_path, [valid])
    CertificateAnalyzer().run(ctx)
    assert not any(
        f.title == "Expired signing certificate" for f in ctx.findings
    )


def test_summary_finding(tmp_path):
    ctx = _ctx(tmp_path, [FakeCertificate()])
    CertificateAnalyzer().run(ctx)
    assert any(
        f.title == "Signing certificates captured" for f in ctx.findings
    )