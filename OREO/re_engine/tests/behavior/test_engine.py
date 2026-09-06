"""BehaviorEngine orchestration, REEngine wiring, and classifier isolation."""

from __future__ import annotations

from pathlib import Path

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.behavior.engine import BEHAVIOR_VERSION
from re_engine.behavior.models import BehaviorStatus
from re_engine.engine import REEngine
from re_engine.tests.triage.fixtures import inject_fakes

from .fixtures import (
    anti_analysis_dex,
    behavior_context,
    empty_dex,
    run_behavior,
    sms_uri_dex,
)


def test_full_scenario_shapes_and_status_counts():
    result = run_behavior(anti_analysis_dex())
    assert result.stats["behaviors_evaluated"] == 41
    assert result.stats["methods_scanned"] >= 2

    counts = result.status_counts()
    assert sum(counts.values()) == 41
    assert counts[BehaviorStatus.TRUE.value] >= 2

    assert result.by_category()
    true = result.true_behaviors()
    assert true
    for finding in true:
        assert finding.status == BehaviorStatus.TRUE
        assert finding.explanation
        assert finding.evidence_refs

    # every finding carries the promised addressing fields
    for finding in result.findings:
        assert finding.behavior_id
        assert finding.behavior_name
        assert finding.category
        assert finding.confidence in {"high", "medium", "low"}
        assert finding.explanation
        assert isinstance(finding.related_classes, list)
        assert isinstance(finding.related_methods, list)


def test_deterministic_across_runs():
    a = run_behavior(sms_uri_dex())
    b = run_behavior(sms_uri_dex())
    assert [f.to_dict() for f in a.findings] == [f.to_dict() for f in b.findings]
    assert a.summary == b.summary
    assert a.stats == b.stats


def test_summary_prefix_and_limitations():
    result = run_behavior(sms_uri_dex())
    assert result.summary.startswith("behavior profile:")
    assert result.limitations
    assert all(isinstance(l, str) for l in result.limitations)


def test_findings_are_sorted_by_default_order():
    from re_engine.behavior.specs import behaviors_in_order

    result = run_behavior(empty_dex())
    ids = [f.behavior_id for f in result.findings]
    expected = [spec.key for spec in behaviors_in_order()]
    assert ids == expected


def test_unknown_never_promoted():
    # A permission-only context must produce UNKNOWN, not TRUE.
    from re_engine.behavior.specs import PERM_READ_SMS

    a = run_behavior(
        empty_dex(),
        context=behavior_context(permissions=[PERM_READ_SMS]),
    )
    sms = next(f for f in a.findings if f.behavior_id == "collection.sms")
    assert sms.status == BehaviorStatus.UNKNOWN
    assert sms.status != BehaviorStatus.TRUE


def test_result_to_dict_round_trip():
    result = run_behavior(sms_uri_dex())
    data = result.to_dict()
    assert data["summary"].startswith("behavior profile:")
    assert len(data["findings"]) == 41
    assert data["stats"]["status_counts"]["TRUE"] >= 1


# ---------------------------------------------------------------------------
# Wiring through REEngine
# ---------------------------------------------------------------------------


class BehaviorSeederAnalyzer(BaseAnalyzer):
    name = "behavior-seeder"
    version = "0.1.0"
    description = "seeds fake DEX so the behavior stage runs hermetic"

    def run(self, context) -> None:
        inject_fakes(context.artifacts, fake_dex=[sms_uri_dex()])
        context.permissions.append("android.permission.READ_SMS")


def test_engine_behavior_stage_and_report_section(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(
        apk_path=apk_path,
        analyzers=[BehaviorSeederAnalyzer()],
        behavior_options={"max_methods": 200},
    )
    report = engine.run()

    assert engine.behavior is not None
    assert engine.behavior.summary.startswith("behavior profile:")
    assert len(engine.behavior.findings) == 41

    section = next((s for s in report.sections if s.name == "behavior"), None)
    assert section is not None
    assert section.data["summary"].startswith("behavior profile:")
    assert isinstance(section.data["findings"], list)
    assert section.data["findings"][0]["status"] in {"TRUE", "FALSE", "UNKNOWN"}

    # backward-compatible behavioral rollup is populated
    assert report.behavioral is not None
    assert report.behavioral.behaviors

    registered = [m for m in engine.context.modules if m.name == "behavior"]
    assert registered and registered[0].version == BEHAVIOR_VERSION


def test_engine_behavior_disabled_by_default(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake")
    engine = REEngine(apk_path=apk_path, analyzers=[BehaviorSeederAnalyzer()])
    report = engine.run()
    assert engine.behavior is None
    assert not [s for s in report.sections if s.name == "behavior"]


class GarbageSeederAnalyzer(BaseAnalyzer):
    name = "garbage-seeder"
    version = "0.1.0"
    description = "injects a non-DEX surface so indexing degrades"

    def run(self, context) -> None:
        inject_fakes(context.artifacts, fake_dex=["not-a-dex"])


def test_engine_behavior_garbage_dex_degrades_gracefully(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(
        apk_path=apk_path,
        analyzers=[GarbageSeederAnalyzer()],
        behavior_options={"max_methods": 200},
    )
    report = engine.run()
    # A garbage DEX surface must not kill the pipeline: every behavior stays
    # FALSE/UNKNOWN (nothing proven) and the stage still produces a result.
    assert engine.behavior is not None
    assert engine.behavior.stats["methods_scanned"] == 0
    assert len(engine.behavior.findings) == 41
    section = next((s for s in report.sections if s.name == "behavior"), None)
    assert section is not None


def test_engine_report_keeps_behavioral_backward_compat_mode(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(
        apk_path=apk_path,
        analyzers=[BehaviorSeederAnalyzer()],
        behavior_options={"max_methods": 200},
    )
    report = engine.run()
    assert report.to_dict()["behavioral"] is not None


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_behavior_does_not_import_classifier():
    from re_engine.behavior import detectors as detectors_module
    from re_engine.behavior import engine as engine_module
    from re_engine.behavior import evidence as evidence_module
    from re_engine.behavior import models as models_module
    from re_engine.behavior import specs as specs_module

    texts = []
    for module in (
        detectors_module,
        engine_module,
        evidence_module,
        models_module,
        specs_module,
    ):
        texts.append(Path(module.__file__).read_text(encoding="utf-8"))
    joined = "\n".join(texts).lower()
    assert "ai.predictor" not in joined
    assert "xgboost" not in joined
    assert "pandas" not in joined