"""Unit tests for the obfuscation / anti-analysis analyzer.

Covers each of the seven technique families plus the anti-overclaim
guardrails (a single short name or a single suspicious string must never
produce a claim), determinism, score bounds and classifier isolation.
"""

from __future__ import annotations

from pathlib import Path

from re_engine.models.finding import Confidence
from re_engine.models.obfuscation import (
    ObfuscationFinding,
    ObfuscationType,
)
from re_engine.output.report import build_re_report

from .fixtures import (
    anti_analysis_dex,
    clean_dex,
    cls,
    control_flow_dex,
    dynamic_loading_dex,
    encoded_literal_heavy_dex,
    finding_of,
    identifier_dex,
    inst,
    mixed_dex,
    reflection_dex,
    run_analyzer,
    runtime_exec_dex,
    string_obfuscation_dex,
)

_ANALYZER_PATH = Path(__file__).resolve().parents[3] / "re_engine" / "analyzers" / "obfuscation_analyzer.py"
_MODEL_PATH = Path(__file__).resolve().parents[3] / "re_engine" / "models" / "obfuscation.py"


# ---------------------------------------------------------------------------
# Identifier obfuscation
# ---------------------------------------------------------------------------


def test_identifier_obfuscation_measured():
    ctx = run_analyzer(identifier_dex())
    finding = finding_of(ctx, "identifier")
    assert finding is not None
    assert finding.score > 0.3
    assert finding.confidence == Confidence.HIGH
    assert any(len(e) > 0 for e in finding.evidence)
    assert finding.metadata["classes_sampled"] >= 8


def test_single_short_class_name_never_claims():
    ctx = run_analyzer(
        [
            cls(
                "La;",
                [
                    ("authenticate", "()V", [inst("return-void", "")]),
                    ("verifySignature", "()Z", [inst("return-object", "v0")]),
                ],
            )
        ]
    )
    assert finding_of(ctx, "identifier") is None


def test_clean_app_produces_no_findings():
    ctx = run_analyzer(clean_dex())
    assert ctx.obfuscation == []


# ---------------------------------------------------------------------------
# String obfuscation
# ---------------------------------------------------------------------------


def test_runtime_string_reconstruction_detected():
    ctx = run_analyzer(string_obfuscation_dex())
    finding = finding_of(ctx, "string")
    assert finding is not None
    assert finding.score > 0.0
    assert any("decoders/encryptors" in e for e in finding.evidence)


def test_encoded_literal_share_measured():
    ctx = run_analyzer(encoded_literal_heavy_dex())
    finding = finding_of(ctx, "string")
    assert finding is not None
    assert finding.score > 0.5
    assert finding.metadata["literals_total"] >= 10


# ---------------------------------------------------------------------------
# Reflection
# ---------------------------------------------------------------------------


def test_reflection_heavy_dispatch_detected():
    ctx = run_analyzer(reflection_dex())
    finding = finding_of(ctx, "reflection")
    assert finding is not None
    assert finding.score > 0.5
    assert finding.confidence == Confidence.HIGH
    assert finding.target.startswith("L")


# ---------------------------------------------------------------------------
# Dynamic loading
# ---------------------------------------------------------------------------


def test_dynamic_loading_detected():
    ctx = run_analyzer(dynamic_loading_dex())
    finding = finding_of(ctx, "dynamic_loading")
    assert finding is not None
    assert finding.score >= 0.5
    assert finding.confidence == Confidence.HIGH
    assert any("native-library loading" in e for e in finding.evidence)


# ---------------------------------------------------------------------------
# Runtime execution
# ---------------------------------------------------------------------------


def test_runtime_execution_with_shell_detected():
    ctx = run_analyzer(runtime_exec_dex())
    finding = finding_of(ctx, "runtime_execution")
    assert finding is not None
    assert finding.score == 1.0
    assert finding.confidence == Confidence.HIGH
    assert "->" in finding.target  # method id target


# ---------------------------------------------------------------------------
# Anti-analysis
# ---------------------------------------------------------------------------


def test_anti_analysis_multiple_categories_detected():
    tokens = ["qemu", "goldfish", "frida", "xposed"]
    ctx = run_analyzer(anti_analysis_dex(tokens))
    finding = finding_of(ctx, "anti_analysis")
    assert finding is not None
    assert finding.score >= 0.6
    assert finding.confidence == Confidence.HIGH
    assert "emulator" in finding.metadata["categories"]
    assert "frida_xposed" in finding.metadata["categories"]


def test_single_weak_token_never_claims_anti_analysis():
    ctx = run_analyzer(anti_analysis_dex(["frida"]))
    assert finding_of(ctx, "anti_analysis") is None


# ---------------------------------------------------------------------------
# Control-flow
# ---------------------------------------------------------------------------


def test_control_flow_switch_heavy_detected():
    ctx = run_analyzer(control_flow_dex())
    finding = finding_of(ctx, "control_flow")
    assert finding is not None
    assert finding.score > 0.5
    assert finding.confidence == Confidence.HIGH
    assert finding.metadata["switch_ops"] >= 20


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


def test_obfuscation_finding_roundtrip():
    original = ObfuscationFinding(
        type=ObfuscationType.IDENTIFIER,
        target="app",
        score=0.75,
        evidence=["class names 9/10 <= 2 chars"],
        confidence=Confidence.HIGH,
        title="Identifier obfuscation",
        analyzer="obfuscation",
        metadata={"classes_sampled": 10},
    )
    restored = ObfuscationFinding.from_dict(original.to_dict())
    assert restored.type == original.type
    assert restored.target == original.target
    assert restored.score == original.score
    assert restored.evidence == original.evidence
    assert restored.confidence == original.confidence
    assert restored.metadata == original.metadata


# ---------------------------------------------------------------------------
# Report section
# ---------------------------------------------------------------------------


def test_report_obfuscation_section():
    ctx = run_analyzer(identifier_dex())
    report = build_re_report(ctx)
    section = next((s for s in report.sections if s.name == "obfuscation"), None)
    assert section is not None
    assert section.data
    for entry in section.data:
        assert {"type", "target", "score", "evidence", "confidence"} <= set(entry)


# ---------------------------------------------------------------------------
# Determinism / bounds / isolation
# ---------------------------------------------------------------------------


def test_repeated_run_is_deterministic():
    ctx_a = run_analyzer(mixed_dex())
    ctx_b = run_analyzer(mixed_dex())
    assert [f.to_dict() for f in ctx_a.obfuscation] == [
        f.to_dict() for f in ctx_b.obfuscation
    ]


def test_scores_constrained_to_unit_interval():
    ctx = run_analyzer(mixed_dex())
    assert ctx.obfuscation
    for finding in ctx.obfuscation:
        assert 0.0 <= finding.score <= 1.0
        assert finding.evidence
        assert finding.target
        assert finding.type in ObfuscationType
        assert finding.confidence in Confidence


def test_summary_finding_emitted():
    ctx = run_analyzer(identifier_dex())
    summary = next(
        f for f in ctx.findings if f.title == "Obfuscation and anti-analysis scan complete"
    )
    assert summary.analyzer == "obfuscation"
    assert summary.category.value == "DEX"
    assert summary.metadata["technique_count"] == len(ctx.obfuscation)


def test_no_classifier_imports_and_no_hardcoded_value():
    for path in (_ANALYZER_PATH, _MODEL_PATH):
        source = path.read_text(encoding="utf-8")
        assert "xgboost" not in source.lower()
        assert "pandas" not in source.lower()
        assert "import ai" not in source
        assert "total_obfuscation" not in source