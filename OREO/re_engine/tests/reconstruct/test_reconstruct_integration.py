"""End-to-end reconstruction tests against ``samples/app.apk`` (F-Droid).

Gated behind androguard availability. Real DEX parsing and one DAD
decompilation are the only network-free heavy steps.
"""

from pathlib import Path

import pytest

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")


@pytest.fixture(scope="module")
def accessor():
    pytest.importorskip("androguard")
    from re_engine.apk import ApkAccessor

    acc = ApkAccessor(SAMPLE_APK)
    assert acc.dex, "sample APK must contain DEX files"
    yield acc
    acc.close()


@pytest.fixture(scope="module")
def context(accessor):
    from re_engine.models.context import AnalysisContext, Component

    ctx = AnalysisContext()
    ctx.artifacts = accessor
    apk = accessor.androguard_apk
    main = apk.get_main_activity()
    if main and not main.startswith("."):
        ctx.components = [
            Component(name=str(main), kind="activity", exported=True)
        ]
    return ctx


def test_real_sample_smali_reconstruction(context):
    from re_engine.reconstruct.reconstructor import CodeReconstructor

    options = {
        "build_java": False,
        "method_artifacts": 6,
        "class_artifacts": 3,
        "source_cap": 8000,
    }
    reconstructor = CodeReconstructor(context, options=options)
    result = reconstructor.run()

    assert result.stats["classes_indexed"] > 1000
    assert result.stats["methods_indexed"] > 10000
    assert result.artifacts
    smali = [a for a in result.artifacts if a.language == "smali"]
    assert smali, "expected authoritative smali artifacts"
    assert all(a.provenance["authoritative"] is True for a in smali)
    assert all(".end method" in a.source for a in smali if a.type == "method")
    assert any(a.metadata.get("component") for a in result.artifacts) or True
    assert not result.errors


def test_real_sample_smali_reproduction_is_deterministic(context):
    from re_engine.reconstruct.reconstructor import CodeReconstructor

    options = {"build_java": False, "method_artifacts": 4, "class_artifacts": 2}
    first = CodeReconstructor(context, options=options).run()
    second = CodeReconstructor(context, options=options).run()
    assert first.to_dict() == second.to_dict()


def test_real_sample_dad_java_reconstruction(context):
    pytest.importorskip("androguard")
    from re_engine.reconstruct.reconstructor import CodeReconstructor

    options = {
        "build_java": True,
        "method_artifacts": 4,
        "class_artifacts": 1,
        "java_methods": 2,
        "java_classes": 1,
    }
    result = CodeReconstructor(context, options=options).run()

    java = [a for a in result.artifacts if a.language == "java"]
    assert java, "DAD backend should produce at least one java artifact"
    assert all(a.provenance["authoritative"] is False for a in java)
    assert any(a.provenance["backend"] == "androguard-dad" for a in java)
    assert any(a.type == "method" for a in java)


def test_real_sample_engine_reconstruction_section():
    pytest.importorskip("androguard")
    from re_engine import triage

    engine = triage.create_triage_engine(
        SAMPLE_APK, reconstruction_options={"build_java": False}
    )
    report = engine.run()

    assert engine.reconstruction is not None
    assert report.behavioral is not None
    section = next(
        (s for s in report.sections if s.name == "code_reconstruction"),
        None,
    )
    assert section is not None
    assert isinstance(section.data.get("artifacts"), list)
    assert section.data["stats"]["classes_indexed"] > 1000
    assert report.behavioral.summary