"""Models: FlowStatus / DataFlowFinding / DataFlowResult serialization."""

from __future__ import annotations

from re_engine.dataflow.models import DataFlowFinding, DataFlowResult, FlowStatus


def _finding(status=FlowStatus.CONFIRMED):
    return DataFlowFinding(
        flow_id="sms|http|mid",
        source="sms",
        source_method="Lcom/app/Main;->onCreate(Landroid/os/Bundle;)V",
        path=["Lcom/app/Main;->onCreate(Landroid/os/Bundle;)V"],
        sink="http",
        sink_method="Lcom/app/Main;->onCreate(Landroid/os/Bundle;)V",
        transformations=["base64"],
        confidence="high",
        evidence_refs=["source:sms@Lcom/app/Main;->onCreate(Landroid/os/Bundle;)V"],
        status=status,
    )


def test_status_values():
    assert FlowStatus.CONFIRMED.value == "CONFIRMED"
    assert str(FlowStatus.PROBABLE) == "PROBABLE"


def test_finding_to_dict():
    data = _finding().to_dict()
    assert data["status"] == "CONFIRMED"
    assert data["transformations"] == ["base64"]
    assert data["flow_id"] == "sms|http|mid"


def test_result_helpers():
    result = DataFlowResult(
        findings=[_finding(), _finding(FlowStatus.PROBABLE)],
        not_established=[_finding(FlowStatus.NOT_ESTABLISHED)],
    )
    assert len(result.by_status(FlowStatus.CONFIRMED)) == 1
    assert result.sink_counts() == {"http": 2}
    assert result.source_counts() == {"sms": 2}
    blended = result.to_dict()
    assert blended["summary"] == ""
    assert "smoking_gun" not in "".join(blended.keys())


def test_result_deterministic_sorted_counts():
    f1 = _finding()
    f1.sink = "http"
    f2 = _finding()
    f2.sink = "http"
    f2.source = "contacts"
    result = DataFlowResult(findings=[f2, f1])
    assert result.sink_counts() == {"http": 2}
    assert result.source_counts() == {"contacts": 1, "sms": 1}