"""Unit tests for the string triage analyzer."""

import zipfile

from re_engine.analyzers.string_analyzer import StringAnalyzer
from re_engine.models.context import AnalysisContext

from .fixtures import build_zip, real_accessor


def _ctx(tmp_path, entries):
    path = build_zip(entries, tmp_path / "app.apk", compression=zipfile.ZIP_DEFLATED)
    ctx = AnalysisContext()
    ctx.artifacts = real_accessor(path)
    return ctx


def test_detects_urls_and_ips(tmp_path):
    ctx = _ctx(
        tmp_path,
        {
            "assets/config.txt": (
                b"server=https://c2.example.com/upload\n"
                b"ip=203.0.113.9\n"
                b"email=ops@example.org\n"
                b"path=/data/data/com.example\n"
            )
        },
    )
    StringAnalyzer().run(ctx)

    assert "https://c2.example.com/upload" in ctx.urls
    assert "203.0.113.9" in ctx.ipv4
    assert "ops@example.org" in ctx.emails
    assert "/data/data/com.example" in ctx.file_paths


def test_detects_shell_commands_and_keywords(tmp_path):
    ctx = _ctx(
        tmp_path,
        {"assets/script.sh": b"Id=`sh -c su -c chmod 755 /data/x`;\nrun payload"},
    )
    StringAnalyzer().run(ctx)

    assert any("sh -c" in cmd for cmd in ctx.shell_commands)
    assert "payload" in ctx.suspicious_keywords


def test_scans_dex_bytes(tmp_path):
    dex_blob = b"dex\n035\x00" + b"https://dex.example.com/c2"
    ctx = _ctx(
        tmp_path,
        {"classes.dex": dex_blob, "AndroidManifest.xml": b"<m/>"},
    )
    StringAnalyzer().run(ctx)
    assert "https://dex.example.com/c2" in ctx.urls


def test_all_findings_are_supported_by_strings(tmp_path):
    from re_engine.utils.validate import validate_finding_support

    ctx = _ctx(
        tmp_path,
        {"assets/t.txt": b"go to https://a.example.net/x now"},
    )
    StringAnalyzer().run(ctx)
    assert ctx.urls
    for finding in ctx.findings:
        assert validate_finding_support(ctx, finding) == []


def test_summary_finding(tmp_path):
    ctx = _ctx(tmp_path, {"assets/t.txt": b"nothing special here"})
    StringAnalyzer().run(ctx)
    assert any(f.title == "Strings extracted" for f in ctx.findings)