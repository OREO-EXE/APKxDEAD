"""Unit tests for the RE engine evidence model (Finding)."""

from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingStatus,
    Severity,
)


def test_finding_defaults():
    finding = Finding(
        category=FindingCategory.PERMISSION,
        title="Suspicious permission declared",
    )
    assert finding.finding_id.startswith("find_")
    assert finding.severity == Severity.INFO
    assert finding.confidence == Confidence.UNKNOWN
    assert finding.evidence_type == EvidenceType.OBSERVED
    assert finding.status == FindingStatus.OPEN
    assert finding.analyzer is None
    assert finding.timestamp


def test_finding_full_population():
    finding = Finding(
        category=FindingCategory.NETWORK,
        title="C2 endpoint",
        description="Hardcoded URL used for exfiltration",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence_type=EvidenceType.URL,
        source_file="classes.dex",
        class_name="com/app/C2",
        method_name="send",
        line_ref=42,
        instruction_ref="invoke-virtual",
        supporting_api="Ljavax/net/ssl/HttpsURLConnection;->connect",
        supporting_string="https://c2.example.com/upload",
        supporting_url="https://c2.example.com/upload",
        parent_id="parent-1",
        analyzer="demo",
        status=FindingStatus.REVIEWED,
    )
    assert finding.finding_id.startswith("find_")
    assert finding.supporting_api.endswith("connect")
    assert finding.class_name == "com/app/C2"


def test_confidence_roundtrip_allowed_values():
    allowed = {
        Confidence.CONFIRMED,
        Confidence.HIGH,
        Confidence.MEDIUM,
        Confidence.LOW,
        Confidence.UNKNOWN,
    }
    seen = {c for c in Confidence}
    assert seen == allowed


def test_finding_to_dict_roundtrip():
    finding = Finding(
        category=FindingCategory.MANIFEST,
        title="Exported activity",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        evidence_type=EvidenceType.MANIFEST,
        source_file="AndroidManifest.xml",
        class_name="com/app/MainActivity",
        supporting_string="intent://host",
        analyzer="manifest_analyzer",
        metadata={"exported": True},
    )
    data = finding.to_dict()
    assert data["category"] == "MANIFEST"
    assert data["confidence"] == "MEDIUM"
    assert data["severity"] == "MEDIUM"
    assert data["metadata"] == {"exported": True}

    restored = Finding.from_dict(data)
    assert restored.finding_id == finding.finding_id
    assert restored.category == FindingCategory.MANIFEST
    assert restored.confidence == Confidence.MEDIUM
    assert restored.severity == Severity.MEDIUM
    assert restored.evidence_type == EvidenceType.MANIFEST
    assert restored.analyzer == "manifest_analyzer"
    assert restored.metadata == {"exported": True}
    assert restored.timestamp == finding.timestamp


def test_finding_parent_link():
    parent = Finding(category=FindingCategory.DEX, title="parent")
    child = Finding(
        category=FindingCategory.API,
        title="child",
        parent_id=parent.finding_id,
    )
    assert child.parent_id == parent.finding_id