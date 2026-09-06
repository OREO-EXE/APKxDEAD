"""Unit tests for the metadata triage analyzer."""

from re_engine.analyzers.metadata_analyzer import MetadataAnalyzer
from re_engine.models.context import AnalysisContext

from .fixtures import FakeApk, inject_fakes, real_accessor


def _context_with_apk(tmp_path, fake_apk=None):
    zip_path = tmp_path / "app.apk"
    zip_path.write_bytes(b"")
    ctx = AnalysisContext()
    accessor = real_accessor(zip_path)
    inject_fakes(accessor, fake_apk=FakeApk() if fake_apk is None else fake_apk)
    ctx.artifacts = accessor
    return ctx


def test_metadata_captures_identity(tmp_path):
    ctx = _context_with_apk(tmp_path)
    MetadataAnalyzer().run(ctx)

    assert ctx.package_name == "com.example.triage"
    assert ctx.app_name == "TriageApp"
    assert ctx.version_name == "1.0.0"
    assert ctx.version_code == "1"
    assert ctx.min_sdk == "23"
    assert ctx.target_sdk == "30"
    assert ctx.sha256 is not None and len(ctx.sha256) == 64
    assert ctx.md5 is not None and len(ctx.md5) == 32
    assert ctx.apk_size == 0


def test_metadata_records_signing_schemes(tmp_path):
    ctx = _context_with_apk(
        tmp_path, FakeApk(schemes=["v1", "v2", "v3"])
    )
    MetadataAnalyzer().run(ctx)
    assert ctx.signature_schemes == ["v1", "v2", "v3"]


def test_metadata_emits_information_finding(tmp_path):
    ctx = _context_with_apk(tmp_path)
    MetadataAnalyzer().run(ctx)
    assert any(f.analyzer == "metadata" for f in ctx.findings)
    assert all(f.analyzer == "metadata" for f in ctx.findings)


def test_metadata_without_androguard(tmp_path):
    zip_path = tmp_path / "app.apk"
    zip_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    ctx = AnalysisContext()
    accessor = real_accessor(zip_path)
    ctx.artifacts = accessor  # androguard_apk becomes None (bad file)
    MetadataAnalyzer().run(ctx)
    assert ctx.sha256 is not None
    assert ctx.signature_schemes == []