"""Unit tests for the reconstruct data models."""

from re_engine.reconstruct.models import (
    ARTIFACT_CLASS,
    ARTIFACT_METHOD,
    CodeArtifact,
    ReconstructionResult,
    artifact_id,
)


def sample_artifact() -> CodeArtifact:
    return CodeArtifact(
        artifact_id=artifact_id(
            ARTIFACT_METHOD,
            "Lcom/evil/Payload;",
            "send",
            "(Ljava/lang/String;)Z",
            "smali",
            ".method public send(Ljava/lang/String;)Z\n.end method",
        ),
        type=ARTIFACT_METHOD,
        class_name="com.evil.Payload",
        method_name="send",
        signature="(Ljava/lang/String;)Z",
        source=".method public send(Ljava/lang/String;)Z\n.end method",
        language="smali",
        source_location="dex[0]:Lcom/evil/Payload;->send(Ljava/lang/String;)Z",
        evidence_refs=[{"kind": "call", "ref": "Ljava/lang/Object;-><init>"}],
        provenance={"backend": "dex-instructions", "authoritative": True},
        metadata={"descriptor": "(Ljava/lang/String;)Z"},
    )


def test_artifact_required_fields_serialize():
    artifact = sample_artifact()
    data = artifact.to_dict()
    for key in (
        "artifact_id",
        "type",
        "class_name",
        "method_name",
        "signature",
        "source",
        "language",
        "source_location",
        "evidence_refs",
    ):
        assert key in data
    assert data["provenance"]["authoritative"] is True
    assert data["metadata"]["descriptor"] == "(Ljava/lang/String;)Z"


def test_artifact_id_deterministic():
    kwargs = {
        "artifact_type": ARTIFACT_METHOD,
        "class_descriptor": "Lcom/evil/Payload;",
        "method_name": "send",
        "signature": "(Ljava/lang/String;)Z",
        "language": "smali",
        "source": ".method public send(Ljava/lang/String;)Z\n.end method",
    }
    first = artifact_id(**kwargs)
    second = artifact_id(**kwargs)
    assert first == second
    assert first.startswith("art_")
    assert artifact_id(**{**kwargs, "source": "other"}) != first


def test_class_artifact_has_no_method():
    artifact = CodeArtifact(
        artifact_id="art_abc",
        type=ARTIFACT_CLASS,
        class_name="com.evil.Payload",
        method_name=None,
        signature="Lcom/evil/Payload;",
        source=".class Lcom/evil/Payload;",
        language="smali",
        source_location="dex[0]:Lcom/evil/Payload;",
    )
    data = artifact.to_dict()
    assert data["type"] == ARTIFACT_CLASS
    assert data["method_name"] is None
    assert "provenance" not in data


def test_reconstruction_result_to_dict():
    result = ReconstructionResult(
        artifacts=[sample_artifact()],
        errors=["nope"],
        stats={"classes_indexed": 1},
        reaching_components={"mid-1": ["com.evil.Main"]},
        summary="ok",
    )
    data = result.to_dict()
    assert data["artifacts"][0]["class_name"] == "com.evil.Payload"
    assert data["errors"] == ["nope"]
    assert data["reaching_components"]["mid-1"] == ["com.evil.Main"]


def test_reconstruction_result_to_behavioral():
    result = ReconstructionResult(summary="possible exfil", errors=["x"])
    behavior = result.to_behavioral()
    assert behavior.summary == "possible exfil"
    assert behavior.behaviors == {}