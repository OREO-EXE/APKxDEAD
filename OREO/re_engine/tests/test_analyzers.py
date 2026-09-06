"""Unit tests for the analyzer framework."""

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)


class ExampleAnalyzer(BaseAnalyzer):
    name = "example"
    version = "1.0.0"
    description = "example analyzer"

    def run(self, context: AnalysisContext) -> None:
        context.add_finding(
            Finding(
                category=FindingCategory.INFORMATION,
                title="example evidence",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                analyzer=self.name,
            )
        )


def test_analyzer_registers_module():
    ctx = AnalysisContext()
    analyzer = ExampleAnalyzer()
    analyzer.register(ctx)
    assert [m.name for m in ctx.modules] == ["example"]


def test_analyzer_run_contributes_finding():
    ctx = AnalysisContext()
    ExampleAnalyzer().run(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].analyzer == "example"


def test_emit_tags_finding_with_analyzer():
    ctx = AnalysisContext()
    analyzer = ExampleAnalyzer()
    finding = Finding(
        category=FindingCategory.BEHAVIOR,
        title="behavior",
        severity=Severity.LOW,
    )
    analyzer.emit(ctx, finding)
    assert finding.analyzer == "example"
    assert len(ctx.findings) == 1


def test_emit_does_not_override_existing_analyzer():
    ctx = AnalysisContext()
    analyzer = ExampleAnalyzer()
    finding = Finding(
        category=FindingCategory.BEHAVIOR,
        title="already tagged",
        analyzer="someone_else",
    )
    analyzer.emit(ctx, finding)
    assert finding.analyzer == "someone_else"


def test_base_is_abstract():
    import pytest

    with pytest.raises(TypeError):
        BaseAnalyzer()