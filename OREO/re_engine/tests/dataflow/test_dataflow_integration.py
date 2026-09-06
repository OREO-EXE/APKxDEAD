"""End-to-end data-flow tests against ``samples/app.apk`` (F-Droid, gated)."""

from pathlib import Path

import pytest

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")

DATAFLOW_OPTIONS = {
    "max_methods": 1500,
    "max_iterations": 6,
    "max_union": 8,
    "max_steps": 24,
    "max_flows_total": 120,
    "include_not_established": False,
    "not_established_cap": 50,
    "track_fields": True,
}


@pytest.fixture(scope="module")
def flow_result():
    pytest.importorskip("androguard")
    from re_engine.dataflow.engine import DataFlowEngine

    from re_engine.apk import ApkAccessor

    accessor = ApkAccessor(SAMPLE_APK)
    assert accessor.dex, "sample APK must contain DEX files"
    try:
        result = DataFlowEngine(
            context=None, dex_files=accessor.dex, options=DATAFLOW_OPTIONS
        ).run()
    finally:
        accessor.close()
    return result


def test_real_sample_runs_bounded(flow_result):
    assert flow_result.stats["methods_scanned"] > 0
    assert flow_result.stats["methods_scanned"] <= DATAFLOW_OPTIONS["max_methods"]
    assert flow_result.stats["iterations_used"] <= DATAFLOW_OPTIONS["max_iterations"]
    assert flow_result.summary.startswith("data flow:")
    assert flow_result.limitations


def test_real_sample_findings_are_evidence_backed(flow_result):
    for finding in flow_result.findings:
        assert finding.path, "findings must carry a reconstructed path"
        assert finding.evidence_refs, "findings must be evidence-backed"
        assert finding.status in (
            "CONFIRMED",
            "PROBABLE",
            "POSSIBLE",
        )
        assert finding.source
        assert finding.sink


def test_real_sample_findings_deterministic_structure(flow_result):
    from re_engine.dataflow.models import FlowStatus

    data = flow_result.to_dict()
    assert data["summary"].startswith("data flow:")
    assert data["stats"]["flows_total"] == len(data["findings"])
    assert all(f["source"] for f in data["findings"])
    assert all(f["sink"] for f in data["findings"])
    assert FlowStatus.NOT_ESTABLISHED.value not in {f["status"] for f in data["findings"]}


def test_real_sample_dataflow_wiring_via_triage():
    pytest.importorskip("androguard")
    from re_engine import triage

    engine = triage.create_triage_engine(
        SAMPLE_APK, dataflow_options=DATAFLOW_OPTIONS
    )
    report = engine.run()

    assert engine.dataflow is not None
    section = next(
        (s for s in report.sections if s.name == "dataflow"), None
    )
    assert section is not None
    assert section.data["summary"].startswith("data flow:")
    assert isinstance(section.data["findings"], list)