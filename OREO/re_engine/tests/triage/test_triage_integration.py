"""End-to-end triage tests.

The full-pipeline tests against the real ``samples/app.apk`` (F-Droid) are
gated behind an androguard import; analysis is deterministic and offline.
"""

from pathlib import Path

import pytest

from re_engine.engine import REEngine
from re_engine.models.context import AnalysisContext
from re_engine.triage import create_triage_engine, run_triage

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")


def test_create_triage_engine_registers_nine_analyzers():
    engine = create_triage_engine("whatever.apk")
    names = [a.name for a in engine.analyzers]
    assert names == [
        "metadata",
        "structure",
        "manifest",
        "permissions",
        "dex",
        "strings",
        "obfuscation",
        "native_lib",
        "certificate",
    ]


def test_run_triage_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_triage(str(tmp_path / "nope.apk"))


def _build_fake_pipeline(tmp_path):
    """Synthetic APK: every analyzer runs without androguard's real parser."""
    from re_engine.analyzers.certificate_analyzer import CertificateAnalyzer
    from re_engine.analyzers.dex_analyzer import DexAnalyzer
    from re_engine.analyzers.manifest_analyzer import ManifestAnalyzer
    from re_engine.analyzers.metadata_analyzer import MetadataAnalyzer
    from re_engine.analyzers.native_lib_analyzer import NativeLibAnalyzer
    from re_engine.analyzers.permission_analyzer import PermissionAnalyzer
    from re_engine.analyzers.string_analyzer import StringAnalyzer
    from re_engine.analyzers.structure_analyzer import StructureAnalyzer

    from .fixtures import (
        FakeApk,
        FakeCertificate,
        build_elf,
        build_zip,
        fake_manifest_xml,
        inject_fakes,
        real_accessor,
    )

    manifest = fake_manifest_xml(
        """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.payload">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="com.example.payload.ACCESS_PAYLOAD"/>
  <application android:debuggable="true">
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <receiver android:name=".BootReceiver">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <service android:name=".AccService"
             android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
  </application>
</manifest>"""
    )

    entries = {
        "AndroidManifest.xml": b"<binary-manifest/>",
        "classes.dex": b"dex\n035\x00" + b"https://c2.payload.example/beacon",
        "assets/boot.zip": b"PK\x03\x04" + b"\x00" * 16 + b"payload.zip",
        "lib/arm64-v8a/libhook.so": build_elf(
            machine=183,
            defined_symbols=["Java_com_example_hook_impl"],
            imported_symbols=["dlopen", "system"],
        ),
        "META-INF/CERT.RSA": b"\x30\x82\x01\x0a",
    }
    path = build_zip(entries, tmp_path / "app.apk")
    accessor = real_accessor(path)
    fake_apk = FakeApk(
        package="com.example.payload",
        main_activity=".Main",
        permissions=[
            "android.permission.INTERNET",
            "com.example.payload.ACCESS_PAYLOAD",
        ],
        certificates=[FakeCertificate(subject="CN=Payload", issuer="CN=Payload")],
        manifest_xml=manifest,
        schemes=["v1", "v2"],
    )
    inject_fakes(accessor, fake_apk=fake_apk)

    context = AnalysisContext()
    context.artifacts = accessor
    for analyzer in (
        MetadataAnalyzer(),
        StructureAnalyzer(),
        ManifestAnalyzer(),
        PermissionAnalyzer(),
        DexAnalyzer(),
        StringAnalyzer(),
        NativeLibAnalyzer(),
        CertificateAnalyzer(),
    ):
        analyzer.register(context)
        analyzer.run(context)
    return context


def test_synthetic_full_pipeline(tmp_path):
    from re_engine.utils.validate import validate_finding_support

    ctx = _build_fake_pipeline(tmp_path)

    assert ctx.package_name == "com.example.payload"
    assert ctx.main_activity == ".Main"
    assert ".BootReceiver" in ctx.boot_receivers
    assert ctx.accessibility_components == [".AccService"]
    assert ctx.application_flags.get("debuggable") == "true"
    assert ctx.signature_schemes == ["v1", "v2"]
    assert ctx.structure["dex_files"] == ["classes.dex"]
    assert ctx.structure["manifest"]["present"] is True

    # every single finding must be internally honest
    for finding in ctx.findings:
        violations = validate_finding_support(ctx, finding)
        assert violations == [], f"{finding.title}: {violations}"

    unsupported = [f.title for f in ctx.findings if f.supporting_string is not None]
    assert unsupported  # at least one finding carries a concrete string


def test_report_build(tmp_path):
    from re_engine.output.report import build_re_report

    ctx = _build_fake_pipeline(tmp_path)
    report = build_re_report(ctx)
    sections = {s.name for s in report.sections}
    assert {
        "identity",
        "permissions",
        "manifest_detail",
        "structure",
        "strings_summary",
        "permission_classification",
    } <= sections
    assert report.findings


def test_engine_run_pipeline(tmp_path):
    context = _build_fake_pipeline(tmp_path)

    class PipelineEngine(REEngine):
        def run(self):
            self._context = context
            return self.report(context, self.reconstruct(context))

    report = PipelineEngine(apk_path=tmp_path / "app.apk").run()
    assert report.package_name == "com.example.payload"
    assert any(
        f["category"] == "CERTIFICATE" for f in report.findings
    )


# ----------------------------------------------------------------------
# Real-sample integration tests (require androguard)
# ----------------------------------------------------------------------


def test_real_sample_full_triage():
    pytest.importorskip("androguard")
    from re_engine import triage

    report = triage.run_triage(SAMPLE_APK)
    assert report.package_name == "org.fdroid.fdroid"
    assert report.architectural.dex_count >= 1
    assert report.architectural.classes > 1000
    assert not report.errors
    findings = list(report.findings)
    assert findings
    assert any(f["category"] == "CERTIFICATE" for f in findings)
    assert any(f["category"] == "NATIVE_LIB" for f in findings)


def test_real_sample_signatures_schemes_and_certs():
    pytest.importorskip("androguard")
    from re_engine import triage

    report = triage.run_triage(SAMPLE_APK)
    sections = {s.name: s.data for s in report.sections}
    manifest = sections["manifest_detail"]
    assert manifest["signature_schemes"], "expected at least one scheme"


def test_real_sample_repeated_run_is_deterministic():
    pytest.importorskip("androguard")

    keys = set()
    for _ in range(2):
        report = run_triage(SAMPLE_APK)
        key = (
            report.sha256,
            len(report.findings),
            tuple(sorted({f["title"] for f in report.findings})),
        )
        keys.add(key)
    assert len(keys) == 1, "runs should be byte-for-byte reproducible"
