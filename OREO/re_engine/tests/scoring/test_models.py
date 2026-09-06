"""Unit tests for the scoring data models."""

from re_engine.scoring.models import (
    SUSPICION_VERSION,
    RankingResult,
    ScoringReason,
    SuspicionScore,
    TargetKind,
)


def sample_score() -> SuspicionScore:
    return SuspicionScore(
        target="Lcom/evil/Payload;->send()V",
        kind=TargetKind.METHOD,
        score=87,
        reasons=[
            ScoringReason("READ_SMS", 35, "PERMISSION", "android.permission.READ_SMS"),
            ScoringReason("SmsMessage API", 30, "SMS", "Landroid/telephony/SmsMessage;"),
            ScoringReason(
                "called by BOOT_COMPLETED receiver", 20, "BEHAVIOR", "Lcom/x/R;->onReceive()V"
            ),
        ],
        evidence_refs=["android.permission.READ_SMS", "Landroid/telephony/SmsMessage;"],
    )


def test_score_serializes_required_fields():
    data = sample_score().to_dict()
    assert data["target"] == "Lcom/evil/Payload;->send()V"
    assert data["kind"] == "method"
    assert data["score"] == 87
    assert data["analyzer_version"] == SUSPICION_VERSION
    assert len(data["reasons"]) == 3
    assert data["evidence_refs"] == [
        "android.permission.READ_SMS",
        "Landroid/telephony/SmsMessage;",
    ]
    reason = data["reasons"][0]
    assert reason == {
        "label": "READ_SMS",
        "weight": 35,
        "category": "PERMISSION",
        "evidence": "android.permission.READ_SMS",
    }


def test_rank_result_serializes_and_counts():
    a = sample_score()
    b = SuspicionScore(
        target="com.evil.Payload",
        kind=TargetKind.CLASS,
        score=40,
        reasons=[ScoringReason("suspicious identifier segments", 12, "OBFUSCATION", "evil")],
    )
    result = RankingResult(scores=[a, b], summary="ranked 2 targets")
    data = result.to_dict()
    assert data["summary"] == "ranked 2 targets"
    assert data["counts"] == {"class": 1, "method": 1}
    assert len(data["scores"]) == 2


def test_rank_result_by_kind():
    scores = [
        SuspicionScore(
            "a", TargetKind.METHOD, 1, [ScoringReason("r", 1, "X", "e")]
        ),
        SuspicionScore(
            "b", TargetKind.NETWORK, 1, [ScoringReason("r", 1, "NETWORK", "e")]
        ),
    ]
    result = RankingResult(scores=scores)
    assert [s.target for s in result.by_kind("method")] == ["a"]
    assert [s.target for s in result.by_kind(TargetKind.NETWORK)] == ["b"]
    assert result.by_kind("class") == []