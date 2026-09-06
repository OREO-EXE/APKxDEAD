"""End-to-end scoring tests against ``samples/app.apk`` (F-Droid, gated)."""

from pathlib import Path

import pytest

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")


@pytest.fixture(scope="module")
def context(accessor):
    from re_engine.models.context import AnalysisContext, Component

    ctx = AnalysisContext()
    ctx.artifacts = accessor
    apk = accessor.androguard_apk
    ctx.permissions = list(apk.get_permissions())
    components = []
    for name in apk.get_receivers():
        components.append(Component(name=str(name), kind="receiver", exported=True))
    for name in apk.get_activities():
        components.append(Component(name=str(name), kind="activity", exported=True))
    for name in apk.get_services():
        components.append(Component(name=str(name), kind="service", exported=True))
    for name in apk.get_providers():
        components.append(Component(name=str(name), kind="provider", exported=True))
    ctx.components = components
    yield ctx


@pytest.fixture(scope="module")
def accessor():
    pytest.importorskip("androguard")
    from re_engine.apk import ApkAccessor

    acc = ApkAccessor(SAMPLE_APK)
    assert acc.dex, "sample APK must contain DEX files"
    yield acc
    acc.close()


def test_real_sample_scoring_produces_explainable_ranked_scores(context):
    from re_engine.scoring.scorer import SuspicionScorer

    result = SuspicionScorer().rank(context)

    assert result.scores, "expected a non-empty ranking for the sample"
    assert result.counts()
    for left, right in zip(result.scores, result.scores[1:]):
        if left.score != right.score:
            assert left.score > right.score
        else:
            assert (left.kind.value, left.target) <= (right.kind.value, right.target)
    for score in result.scores:
        assert score.score > 0
        assert score.reasons
        assert score.evidence_refs


def test_real_sample_scoring_is_deterministic(context):
    from re_engine.scoring.scorer import SuspicionScorer

    first = SuspicionScorer(options={"max_per_kind": 25}).rank(context)
    second = SuspicionScorer(options={"max_per_kind": 25}).rank(context)
    assert first.to_dict() == second.to_dict()


def test_real_sample_engine_suspicion_section():
    pytest.importorskip("androguard")
    from re_engine import triage

    engine = triage.create_triage_engine(
        SAMPLE_APK, suspicion_options={"max_per_kind": 10}
    )
    report = engine.run()

    assert engine.suspicion is not None
    assert report.behavioral is not None
    section = next(
        (s for s in report.sections if s.name == "suspicion_ranking"), None
    )
    assert section is not None
    assert isinstance(section.data.get("scores"), list)
    assert section.data["counts"]
    top = section.data["scores"][0]
    assert top["score"] > 0
    assert top["reasons"]
    assert top["evidence_refs"]


def test_real_sample_scoring_does_not_import_classifier(context):
    import re_engine.scoring.scorer
    import sys

    assert "ai" not in sys.modules or all(
        not mod.startswith("ai.predictor") for mod in sys.modules
    )
    source = pathlib_read_text()
    assert "ai.predictor" not in source and "xgboost" not in source.lower()


def pathlib_read_text():
    from re_engine.scoring import scorer

    path = Path(scorer.__file__)
    return path.read_text(encoding="utf-8")