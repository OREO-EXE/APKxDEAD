"""Unit tests for the REEngine orchestration layer."""

import json

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.engine import REEngine, PIPELINE_VERSION
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)
from re_engine.output.report import ReReport


class ManifestAnalyzer(BaseAnalyzer):
    name = "manifest"
    version = "0.1.0"
    description = "manifest extractor"

    def run(self, context: AnalysisContext) -> None:
        context.package_name = "com.example.app"
        context.permissions.append("android.permission.INTERNET")
        context.add_finding(
            Finding(
                category=FindingCategory.MANIFEST,
                title="Manifest parsed",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                analyzer=self.name,
            )
        )


class FailingAnalyzer(BaseAnalyzer):
    name = "boom"

    def run(self, context: AnalysisContext) -> None:
        raise RuntimeError("kaboom")


def write_apk(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    return apk_path


def test_engine_run_pipeline(tmp_path):
    apk_path = write_apk(tmp_path)
    engine = REEngine(apk_path=apk_path, analyzers=[ManifestAnalyzer()])
    report = engine.run()

    assert isinstance(report, ReReport)
    assert report.sha256
    assert report.package_name == "com.example.app"
    assert len(report.findings) == 1
    assert report.architectural is not None
    assert engine.context is not None
    assert engine.context.is_complete()
    assert report.pipeline_version == PIPELINE_VERSION


def test_engine_requires_apk():
    engine = REEngine()
    try:
        engine.run()
    except ValueError as exc:
        assert "No APK path" in str(exc)
    else:
        raise AssertionError("Expected ValueError when no APK path configured")


def test_engine_missing_file(tmp_path):
    engine = REEngine(apk_path=tmp_path / "missing.apk")
    try:
        engine.run()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")


def test_engine_sha256_stable(tmp_path):
    import hashlib

    apk_path = write_apk(tmp_path)
    e1 = REEngine(apk_path=apk_path)
    e2 = REEngine(apk_path=apk_path)
    sha1 = e1.ingest(apk_path).sha256
    sha2 = e2.ingest(apk_path).sha256
    expected = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    assert sha1 == sha2 == expected


def test_engine_report_json(tmp_path):
    apk_path = write_apk(tmp_path)
    engine = REEngine(apk_path=apk_path, analyzers=[ManifestAnalyzer()])
    engine.run()
    payload = json.loads(engine.report_json())
    assert payload["package_name"] == "com.example.app"
    assert isinstance(payload["findings"], list)


def test_engine_isolated_from_classifier(tmp_path):
    """The engine must not import the classifier or feature pipeline."""
    import sys

    apk_path = write_apk(tmp_path)
    engine = REEngine(apk_path=apk_path, analyzers=[ManifestAnalyzer()])
    engine.run()

    assert "ai.predictor" not in sys.modules
    assert "xgboost" not in sys.modules
    assert "pandas" not in sys.modules


def test_engine_recovers_from_analyzer_failure(tmp_path):
    apk_path = write_apk(tmp_path)
    engine = REEngine(apk_path=apk_path, analyzers=[FailingAnalyzer()])
    report = engine.run()

    assert len(report.errors) == 1
    assert "boom" in report.errors[0]
    assert len(report.findings) == 1
    assert report.findings[0]["title"] == "Analyzer failed"


def test_engine_register_analyzer(tmp_path):
    apk_path = write_apk(tmp_path)
    engine = REEngine(apk_path=apk_path)
    engine.register_analyzer(ManifestAnalyzer())
    assert len(engine.analyzers) == 1
    report = engine.run()
    assert report.package_name == "com.example.app"


def test_analyze_runs_analyzers_on_context(tmp_path):
    apk_path = write_apk(tmp_path)
    engine = REEngine(apk_path=apk_path, analyzers=[ManifestAnalyzer()])
    context = engine.ingest(apk_path)
    engine.analyze(context)
    assert len(context.findings) == 1
    assert context.package_name == "com.example.app"