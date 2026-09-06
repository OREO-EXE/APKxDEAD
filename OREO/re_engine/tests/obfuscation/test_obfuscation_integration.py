"""End-to-end obfuscation analyzer tests against ``samples/app.apk`` (gated)."""

from pathlib import Path

import pytest

from re_engine.models.finding import Confidence

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")

_MODULES = ("dex", "strings", "obfuscation")


def test_real_sample_obfuscation_module_runs():
    pytest.importorskip("androguard")
    from re_engine import triage

    engine = triage.create_triage_engine(SAMPLE_APK)
    report = engine.run()
    context = engine.context

    assert report.errors == []
    names = {m.name for m in context.modules}
    assert "obfuscation" in names
    assert not any("obfuscation" in e for e in report.errors)

    for finding in context.obfuscation:
        assert 0.0 <= finding.score <= 1.0
        assert finding.evidence
        assert finding.target
        assert finding.confidence in Confidence
        assert finding.type.value in {
            "identifier",
            "string",
            "reflection",
            "dynamic_loading",
            "runtime_execution",
            "anti_analysis",
            "control_flow",
        }


def test_real_sample_obfuscation_report_section_well_formed():
    pytest.importorskip("androguard")
    from re_engine import triage

    report = triage.run_triage(SAMPLE_APK)
    section = next((s for s in report.sections if s.name == "obfuscation"), None)
    if section is None:
        pytest.skip("sample APK triggers no obfuscation measurements")
    for entry in section.data:
        assert {"type", "target", "score", "evidence", "confidence"} <= set(entry)
        assert isinstance(entry["score"], (int, float))
        assert isinstance(entry["evidence"], list)
        assert isinstance(entry["confidence"], str)


def test_real_sample_obfuscation_deterministic():
    pytest.importorskip("androguard")
    from re_engine import triage

    reports = []
    for _ in range(2):
        engine = triage.create_triage_engine(SAMPLE_APK)
        report = engine.run()
        reports.append(
            (
                [f.to_dict() for f in engine.context.obfuscation],
                len(report.findings),
                report.sha256,
            )
        )
    assert reports[0] == reports[1]