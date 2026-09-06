"""Unit tests for the CodeReconstructor (duck-typed, no androguard)."""

from re_engine.reconstruct.models import LANGUAGE_JAVA, LANGUAGE_SMALI
from re_engine.reconstruct.reconstructor import CodeReconstructor
from re_engine.tests.reconstruct.fixtures import fake_context, send_mid


def non_java_options():
    return {"build_java": False, "source_cap": 4000, "ref_cap": 50}


def test_run_produces_deterministic_artifacts():
    context = fake_context()
    first = CodeReconstructor(context, options=non_java_options()).run()
    second = CodeReconstructor(context, options=non_java_options()).run()

    assert len(first.artifacts) > 0
    assert first.to_dict() == second.to_dict()
    assert first.summary.startswith("reconstructed")
    assert first.stats["classes_indexed"] == 2
    assert first.stats["methods_indexed"] == 4


def test_run_targets_finding_anchored_method():
    context = fake_context()
    result = CodeReconstructor(context, options=non_java_options()).run()

    send_artifacts = [a for a in result.artifacts if a.method_name == "send"]
    assert send_artifacts, "the finding-anchored method must be reconstructed"
    artifact = send_artifacts[0]
    assert artifact.language == LANGUAGE_SMALI
    assert artifact.class_name == "com.evil.Payload"
    assert artifact.signature == "(Ljava/lang/String;)Z"
    assert artifact.source_location.endswith(send_mid())

    kinds = {ref["kind"] for ref in artifact.evidence_refs}
    assert {"calls", "strings", "classes", "fields"} <= kinds
    assert any(
        ref["ref"] == "https://c2.example.com/beacon"
        for ref in artifact.evidence_refs
        if ref["kind"] == "strings"
    )
    assert artifact.metadata["api_usage"]
    assert artifact.provenance["authoritative"] is True


def test_class_artifact_for_component():
    context = fake_context()
    result = CodeReconstructor(context, options=non_java_options()).run()

    main_artifacts = [
        a for a in result.artifacts if a.class_name == "com.evil.Main"
    ]
    assert main_artifacts
    class_artifact = next(
        a for a in main_artifacts if a.type == "class"
    )
    assert class_artifact.metadata["component"]["kind"] == "activity"
    assert any(
        ref["kind"] == "interface"
        for ref in class_artifact.evidence_refs
    )


def test_reaching_components():
    context = fake_context()
    result = CodeReconstructor(context, options=non_java_options()).run()
    reaching = result.reaching_components
    assert reaching.get(
        "Lcom/evil/Main;->onCreate(Landroid/os/Bundle;)V"
    ) == ["com.evil.Main"]
    assert send_mid() not in reaching


def test_reconstruct_method_explicit():
    context = fake_context()
    reconstructor = CodeReconstructor(context, options=non_java_options())
    artifact = reconstructor.reconstruct_method(send_mid())
    assert artifact is not None
    assert artifact.method_name == "send"
    assert artifact.language == LANGUAGE_SMALI
    assert reconstructor.reconstruct_method("Lcom/x/Missing;->n()V") is None


def test_caller_analysis():
    context = fake_context()
    reconstructor = CodeReconstructor(context, options=non_java_options())
    analysis = reconstructor.caller_analysis(send_mid())
    assert analysis["target"] == send_mid()
    assert "Lcom/evil/Main;->onCreate(Landroid/os/Bundle;)V" in analysis["callers"]
    assert "Lcom/evil/Payload;->callGraphTest(I)V" in analysis["callers"]
    assert analysis["callees"]
    assert any("getBytes" in c for c in analysis["callees"])


def test_java_requested_but_without_backend_is_honest():
    context = fake_context()
    options = dict(non_java_options())
    options["build_java"] = True
    options["java_methods"] = 2
    options["java_classes"] = 1
    result = CodeReconstructor(context, options=options).run()
    assert all(a.language == LANGUAGE_SMALI for a in result.artifacts)
    assert result.stats["java_artifacts"] == 0


def test_targets_and_unresolved_targets():
    context = fake_context()
    reconstructor = CodeReconstructor(context, options=non_java_options())
    result = reconstructor.run(targets=[send_mid(), "Lcom/nope/X;->y()V"])
    assert any(a.method_name == "send" for a in result.artifacts)
    assert any("unresolved target" in error for error in result.errors)


def test_java_option_ignored_when_gated_false_and_summary_ok():
    context = fake_context()
    result = CodeReconstructor(context, options=non_java_options()).run()
    assert "java=" not in result.summary or "java=0" in result.summary
    assert result.backend is None