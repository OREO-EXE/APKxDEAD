"""Unit tests for the DEX triage analyzer (fake androguard DEX objects)."""

from re_engine.analyzers.dex_analyzer import DexAnalyzer
from re_engine.models.context import AnalysisContext

from .fixtures import (
    FakeDex,
    FakeDexClass,
    FakeInstruction,
    inject_fakes,
    real_accessor,
)


def _fake_classes():
    return [
        FakeDexClass(
            "Lcom/example/MainActivity;",
            "Landroid/app/Activity;",
            [],
            fields=[("url", "Ljava/lang/String;")],
            methods=[
                ("onCreate", "(Landroid/os/Bundle;)V", "public",
                 [FakeInstruction("invoke-virtual",
                                  "Lcom/example/Net;->call(Ljava/lang/String;)V")]),
            ],
        ),
        FakeDexClass(
            "Lcom/example/Net;",
            "Ljava/lang/Object;",
            ["Ljava/io/Serializable;"],
            fields=[],
            methods=[
                ("call", "(Ljava/lang/String;)V", "public static",
                 [FakeInstruction("invoke-static",
                                  "Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;")]),
            ],
        ),
    ]


def _ctx(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(b"")
    accessor = real_accessor(path)
    classes = _fake_classes()
    inject_fakes(
        accessor,
        fake_dex=[FakeDex(classes[:1]), FakeDex(classes[1:])],
    )
    ctx = AnalysisContext()
    ctx.artifacts = accessor
    return ctx


def test_extracts_classes_and_packages(tmp_path):
    ctx = _ctx(tmp_path)
    DexAnalyzer().run(ctx)

    assert set(ctx.classes) == {"Lcom/example/MainActivity;", "Lcom/example/Net;"}
    assert "com.example" in ctx.packages
    assert ctx.dex.dex_count == 2
    assert ctx.dex.total_classes == 2
    assert ctx.dex.total_methods == 2


def test_extracts_inheritance_and_interfaces(tmp_path):
    ctx = _ctx(tmp_path)
    DexAnalyzer().run(ctx)

    assert ctx.inheritance["Lcom/example/MainActivity;"] == "Landroid/app/Activity;"
    assert ctx.interfaces["Lcom/example/Net;"] == ["Ljava/io/Serializable;"]
    assert ctx.fields == ["url:Ljava/lang/String;"]


def test_api_references_classified(tmp_path):
    ctx = _ctx(tmp_path)
    DexAnalyzer().run(ctx)

    assert ctx.api_references, "expected some API references"
    invoking = [
        api for api in ctx.api_references
        if api.endswith("call")
    ]
    assert invoking, "expected the Net.call method reference"


def test_dex_summary_finding(tmp_path):
    ctx = _ctx(tmp_path)
    DexAnalyzer().run(ctx)
    assert any(f.title == "DEX analysis complete" for f in ctx.findings)


def test_no_dex_is_graceful(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(b"")
    accessor = real_accessor(path)
    inject_fakes(accessor, fake_dex=[])
    ctx = AnalysisContext()
    ctx.artifacts = accessor
    DexAnalyzer().run(ctx)
    assert ctx.dex.dex_count == 0
    assert any(f.title == "DEX analysis complete" for f in ctx.findings)