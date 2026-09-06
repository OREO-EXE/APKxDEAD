"""End-to-end behavior tests against ``samples/app.apk`` (F-Droid, gated)."""

from pathlib import Path

import pytest

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")

BEHAVIOR_OPTIONS = {
    "max_methods": 1500,
    "ref_cap": 200,
}


@pytest.fixture(scope="module")
def behavior_result():
    pytest.importorskip("androguard")
    from re_engine.apk import ApkAccessor
    from re_engine.behavior.engine import BehaviorEngine
    from re_engine.reconstruct.index import CodeIndex

    accessor = ApkAccessor(SAMPLE_APK)
    assert accessor.dex, "sample APK must contain DEX files"
    try:
        result = BehaviorEngine(
            context=None,
            index=CodeIndex(accessor.dex),
            options=BEHAVIOR_OPTIONS,
        ).run()
    finally:
        accessor.close()
    return result


def test_real_sample_runs_bounded(behavior_result):
    assert behavior_result.stats["methods_scanned"] > 0
    assert behavior_result.stats["methods_scanned"] <= BEHAVIOR_OPTIONS["max_methods"]
    assert behavior_result.stats["behaviors_evaluated"] == 41
    assert behavior_result.summary.startswith("behavior profile:")
    assert behavior_result.limitations


def test_real_sample_findings_are_evidence_backed(behavior_result):
    for finding in behavior_result.findings:
        assert finding.status in ("TRUE", "FALSE", "UNKNOWN")
        assert finding.confidence in {"high", "medium", "low"}
        assert finding.explanation
        assert finding.behavior_id
        assert finding.behavior_name


def test_real_sample_true_findings_have_traceable_evidence(behavior_result):
    for finding in behavior_result.by_status("TRUE"):
        assert finding.evidence_refs, (
            f"{finding.behavior_id} TRUE must cite evidence"
        )
        assert finding.explanation
        assert finding.status.value == "TRUE"


def test_real_sample_deterministic_structure(behavior_result):
    data = behavior_result.to_dict()
    assert data["summary"].startswith("behavior profile:")
    assert len(data["findings"]) == 41
    assert all(f["behavior_id"] for f in data["findings"])


def test_real_sample_behavior_wiring_via_triage():
    pytest.importorskip("androguard")
    from re_engine import triage

    engine = triage.create_triage_engine(
        SAMPLE_APK, behavior_options=BEHAVIOR_OPTIONS
    )
    report = engine.run()

    assert engine.behavior is not None
    assert engine.behavior.summary.startswith("behavior profile:")
    assert report.behavioral is not None
    assert report.behavioral.behaviors
    section = next(
        (s for s in report.sections if s.name == "behavior"), None
    )
    assert section is not None
    assert section.data["summary"].startswith("behavior profile:")
    assert isinstance(section.data["findings"], list)
    assert len(section.data["findings"]) == 41