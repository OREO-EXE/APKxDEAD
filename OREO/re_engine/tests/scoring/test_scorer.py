"""Unit tests for the SuspicionScorer (hermetic, no androguard)."""

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.engine import REEngine
from re_engine.models.context import Component
from re_engine.scoring.models import SUSPICION_VERSION, TargetKind
from re_engine.scoring.scorer import SuspicionScorer
from re_engine.tests.scoring.fixtures import (
    C2_IP,
    C2_URL,
    DO_EXFIL_MID,
    ENCODED,
    HANDLE_SMS_MID,
    SHELL_CMD,
    SMS_MESSAGE,
    SMS_SEND,
    SPY_SERVICE_NAME,
    STEAL_RECEIVER_CLASS,
    STEAL_RECEIVER_NAME,
    benign_context,
    build_malicious_dex,
    malicious_context,
)
from re_engine.tests.triage.fixtures import inject_fakes


def rank(context, **options):
    return SuspicionScorer(options=options or None).rank(context)


def test_ranking_is_deterministic():
    first = rank(malicious_context())
    second = rank(malicious_context())
    assert first.to_dict() == second.to_dict()
    assert first.analyzer_version == SUSPICION_VERSION
    assert first.scores
    assert first.summary.startswith("ranked")


def test_scores_are_sorted_high_to_low():
    scores = rank(malicious_context()).scores
    for left, right in zip(scores, scores[1:]):
        if left.score != right.score:
            assert left.score > right.score
        else:
            assert (left.kind.value, left.target) <= (right.kind.value, right.target)


def test_no_score_without_reasons_or_evidence():
    for score in rank(malicious_context()).scores:
        assert score.score > 0
        assert score.reasons
        assert score.evidence_refs
        for reason in score.reasons:
            assert reason.weight > 0
            assert reason.label
            assert reason.evidence


def test_all_six_target_kinds_are_produced():
    result = rank(malicious_context())
    kinds = {score.kind for score in result.scores}
    assert {
        TargetKind.METHOD,
        TargetKind.CLASS,
        TargetKind.COMPONENT,
        TargetKind.API,
        TargetKind.STRING,
        TargetKind.NETWORK,
    } <= kinds


def test_malicious_methods_ranked_and_benign_absent():
    scores = rank(malicious_context()).scores
    method_targets = {s.target for s in result_by_kind(scores, "method")}
    assert HANDLE_SMS_MID in method_targets
    assert DO_EXFIL_MID in method_targets
    assert "Lcom/example/hello/MainActivity;->onCreate(Landroid/os/Bundle;)V" not in method_targets


def test_sms_method_reasons_are_explainable():
    scores = rank(malicious_context()).scores
    handle = next(s for s in scores if s.target == HANDLE_SMS_MID)
    labels = [r.label for r in handle.reasons]

    assert "SmsManager API" in labels
    assert "SmsMessage API" in labels
    assert "called by BOOT_COMPLETED receiver" in labels
    assert "READ_SMS declared with SMS API usage" in labels

    evidence = " ".join(handle.evidence_refs)
    assert "android.permission.READ_SMS" in evidence
    assert SMS_MESSAGE.split("->")[0] in evidence
    assert C2_IP in evidence
    boot_reason = next(r for r in handle.reasons if "BOOT_COMPLETED" in r.label)
    assert "onReceive" in boot_reason.evidence


def test_network_function_projection():
    scores = rank(malicious_context()).scores
    network_targets = {s.target for s in scores if s.kind is TargetKind.NETWORK}
    assert HANDLE_SMS_MID in network_targets
    assert DO_EXFIL_MID in network_targets


def test_api_targets_aggregate_usage():
    scores = rank(malicious_context()).scores
    api_targets = {s.target: s for s in scores if s.kind is TargetKind.API}
    assert SMS_SEND in api_targets
    assert any("Runtime;->exec" in target for target in api_targets)
    used_labels = [r.label for r in api_targets[SMS_SEND].reasons]
    assert "SmsManager API" in used_labels
    assert any(label.startswith("used by ") for label in used_labels)


def test_string_targets_include_indicators():
    scores = rank(malicious_context()).scores
    string_targets = {s.target: s for s in scores if s.kind is TargetKind.STRING}
    assert C2_URL in string_targets
    assert C2_IP in string_targets
    assert SHELL_CMD in string_targets
    assert ENCODED in string_targets
    assert "hardcoded IP address" in {
        r.label for r in string_targets[C2_IP].reasons
    }


def test_component_target_for_boot_receiver():
    scores = rank(malicious_context()).scores
    component = next(
        s for s in scores if s.kind is TargetKind.COMPONENT
        and s.target == STEAL_RECEIVER_NAME
    )
    labels = [r.label for r in component.reasons]
    assert "declared BOOT_COMPLETED receiver" in labels
    assert any("READ_SMS" in label for label in labels)


def test_class_targets_present_and_benign_empty():
    scores = rank(malicious_context()).scores
    class_targets = {s.target for s in scores if s.kind is TargetKind.CLASS}
    assert STEAL_RECEIVER_CLASS in class_targets
    assert "Lcom/example/hello/MainActivity;" not in class_targets

    benign = rank(benign_context()).to_dict()
    assert benign["scores"] == []
    assert benign["counts"] == {}


def test_max_per_kind_cap_is_bounded():
    result = rank(malicious_context(), max_per_kind=2)
    for kind in TargetKind:
        assert len(result.by_kind(kind)) <= 2


def test_score_changes_when_permission_withdrawn():
    with_perms = rank(malicious_context()).scores
    handle_before = next(s for s in with_perms if s.target == HANDLE_SMS_MID).score

    context = malicious_context()
    context.permissions = ["android.permission.INTERNET"]
    without = rank(context).scores
    handle_after = next(s.score for s in without if s.target == HANDLE_SMS_MID)
    assert handle_after < handle_before


class SuspicionSeederAnalyzer(BaseAnalyzer):
    """Injects fake DEX + manifest evidence so the engine rank runs hermetic."""

    name = "seeder"
    version = "0.1.0"
    description = "seeds suspicious evidence"

    def run(self, context) -> None:
        inject_fakes(context.artifacts, fake_dex=[build_malicious_dex()])
        context.package_name = "com.evil.x7g83"
        context.permissions = [
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        ]
        context.components = [
            Component(name=STEAL_RECEIVER_NAME, kind="receiver", exported=True),
            Component(name=SPY_SERVICE_NAME, kind="service", exported=False),
        ]
        context.boot_receivers = [STEAL_RECEIVER_NAME]


def test_engine_suspicion_stage_and_report_section(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(
        apk_path=apk_path,
        analyzers=[SuspicionSeederAnalyzer()],
        suspicion_options={"max_per_kind": 5},
    )
    report = engine.run()

    assert engine.suspicion is not None
    assert engine.suspicion.analyzer_version == SUSPICION_VERSION
    assert engine.suspicion.scores
    assert engine.suspicion.scores[0].target == DO_EXFIL_MID
    section = next(
        (s for s in report.sections if s.name == "suspicion_ranking"), None
    )
    assert section is not None
    assert section.data["analyzer_version"] == SUSPICION_VERSION
    assert section.data["scores"]
    assert any(m.name == "suspicion" for m in engine.context.modules)


def test_engine_skips_suspicion_by_default(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(apk_path=apk_path, analyzers=[SuspicionSeederAnalyzer()])
    engine.run()
    assert engine.suspicion is None
    assert all(
        s.name != "suspicion_ranking" for s in engine.last_report.sections
    )


def result_by_kind(scores, kind):
    return [s for s in scores if s.kind.value == kind]