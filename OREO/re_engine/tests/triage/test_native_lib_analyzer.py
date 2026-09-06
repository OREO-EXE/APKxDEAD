"""Unit tests for the native library triage analyzer."""

import zipfile

from re_engine.analyzers.native_lib_analyzer import NativeLibAnalyzer
from re_engine.models.context import AnalysisContext
from re_engine.utils.elfutil import elf_info

from .fixtures import build_elf, build_zip, real_accessor


def _ctx(tmp_path, entries):
    path = build_zip(entries, tmp_path / "app.apk", compression=zipfile.ZIP_STORED)
    ctx = AnalysisContext()
    ctx.artifacts = real_accessor(path)
    return ctx


def _arm_elf():
    return build_elf(
        machine=62,
        defined_symbols=["Java_com_example_Native_run", "helper_impl"],
        imported_symbols=["system", "dlopen", "connect"],
    )


def test_elf_fixture_is_parseable():
    info = elf_info(_arm_elf())
    assert info is not None
    assert info["architecture"] == "EM_X86_64 (x86_64)"
    assert set(info["symbols"]) == {
        "Java_com_example_Native_run",
        "helper_impl",
    }
    assert set(info["imports"]) == {"system", "dlopen", "connect"}


def test_native_lib_parsed(tmp_path):
    ctx = _ctx(
        tmp_path,
        {
            "lib/arm64-v8a/libexample.so": _arm_elf(),
            "lib/x86/libexample.so": _arm_elf(),
            "AndroidManifest.xml": b"<m/>",
        },
    )
    NativeLibAnalyzer().run(ctx)

    assert ctx.native_libraries == ["libexample.so"]
    assert len(ctx.native_lib_details) == 1
    detail = ctx.native_lib_details[0]
    assert detail.name == "libexample.so"
    assert detail.abi == "arm64-v8a"
    assert detail.architecture == "EM_X86_64 (x86_64)"
    assert "Java_com_example_Native_run" in detail.exported_symbols


def test_suspicious_name_flagged(tmp_path):
    ctx = _ctx(
        tmp_path,
        {
            "lib/arm64-v8a/libfrida_hook.so": _arm_elf(),
            "lib/arm64-v8a/libok.so": _arm_elf(),
            "AndroidManifest.xml": b"<m/>",
        },
    )
    NativeLibAnalyzer().run(ctx)

    flagged = [
        d for d in ctx.native_lib_details
        if any("frida" in r for r in d.suspicious_reasons)
    ]
    assert len(flagged) == 1
    findings = [
        f for f in ctx.findings
        if f.title == "Native library warrants review"
        and "frida" in f.source_file
    ]
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_non_elf_library_skipped(tmp_path):
    ctx = _ctx(
        tmp_path,
        {
            "lib/arm64-v8a/libstuff.so": b"not an elf at all",
            "AndroidManifest.xml": b"<m/>",
        },
    )
    NativeLibAnalyzer().run(ctx)
    assert ctx.native_libraries == ["libstuff.so"]
    assert ctx.native_lib_details[0].architecture is None