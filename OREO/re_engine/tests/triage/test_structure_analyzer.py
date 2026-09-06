"""Unit tests for the structure triage analyzer."""

import zipfile

from re_engine.analyzers.structure_analyzer import StructureAnalyzer
from re_engine.models.context import AnalysisContext

from .fixtures import build_zip, real_accessor


def _ctx(tmp_path, entries):
    path = build_zip(entries, tmp_path / "app.apk", compression=zipfile.ZIP_DEFLATED)
    ctx = AnalysisContext()
    ctx.artifacts = real_accessor(path)
    return ctx


def test_detects_dex_and_manifest(tmp_path):
    ctx = _ctx(
        tmp_path,
        {
            "AndroidManifest.xml": b"<manifest/>",
            "classes.dex": b"dex\n035\x00",
            "classes2.dex": b"dex\n035\x00",
            "resources.arsc": b"\x02\x00\x00\x00" + b"\x00" * 20,
            "res/layout/main.xml": b"<layout/>",
            "assets/maps.txt": b"data",
            "lib/arm64-v8a/libfoo.so": build_elf_blob(),
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0",
            "META-INF/CERT.RSA": b"\x30\x82\x01\x0a",
        },
    )
    StructureAnalyzer().run(ctx)

    assert ctx.structure["manifest"]["present"] is True
    assert ctx.structure["dex_files"] == ["classes.dex", "classes2.dex"]
    assert ctx.structure["resources"]["resources_arsc_present"] is True
    assert ctx.structure["resources"]["resource_dir_entries"] == 1
    assert ctx.structure["assets"]["entry_count"] == 1
    assert ctx.structure["lib"]["entry_count"] == 1
    assert ctx.structure["meta_inf"]["manifest_mf"] is True
    assert ctx.structure["meta_inf"]["signature_files"] == ["META-INF/CERT.RSA"]


def test_missing_manifest_is_flagged_high(tmp_path):
    ctx = _ctx(tmp_path, {"classes.dex": b"dex\n035\x00"})
    StructureAnalyzer().run(ctx)
    findings = [f for f in ctx.findings if f.title == "Missing AndroidManifest.xml"]
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_embedded_apk_flagged(tmp_path):
    payload = b"PK\x03\x04" + b"\x00" * 30 + b"evil.apk"
    ctx = _ctx(
        tmp_path,
        {"assets/evil.apk": payload, "AndroidManifest.xml": b"<manifest/>"},
    )
    StructureAnalyzer().run(ctx)
    assert "assets/evil.apk" in ctx.embedded_archives
    assert any(
        f.title == "Embedded archive detected" for f in ctx.findings
    )


def test_suspicious_file_detected(tmp_path):
    ctx = _ctx(
        tmp_path,
        {"payload/boot.dex": b"dex\n035\x00", "AndroidManifest.xml": b"<m/>"},
    )
    StructureAnalyzer().run(ctx)
    assert any("payload" in item for item in ctx.suspicious_files)


def test_single_dex_not_treated_as_embedding(tmp_path):
    ctx = _ctx(
        tmp_path,
        {"classes.dex": b"dex\n035\x00", "AndroidManifest.xml": b"<m/>"},
    )
    StructureAnalyzer().run(ctx)
    assert ctx.embedded_archives == []


def build_elf_blob() -> bytes:
    from .fixtures import build_elf

    return build_elf(machine=183, defined_symbols=["java_com_example_JNI"])


def test_structure_summary_finding(tmp_path):
    ctx = _ctx(tmp_path, {"AndroidManifest.xml": b"<m/>"})
    StructureAnalyzer().run(ctx)
    assert any(f.analyzer == "structure" for f in ctx.findings)