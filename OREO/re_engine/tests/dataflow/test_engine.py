"""Data-flow engine scenarios, wiring through REEngine, and isolation."""

from __future__ import annotations

from pathlib import Path

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.dataflow import DATAFLOW_VERSION, DataFlowEngine
from re_engine.dataflow.models import FlowStatus
from re_engine.engine import REEngine
from re_engine.tests.triage.fixtures import inject_fakes

from .fixtures import (
    call_log_return_dex,
    callback_capture_dex,
    cross_param_dex,
    field_hop_dex,
    no_flow_dex,
    sms_exfil_dex,
)


def _run(dex, **overrides):
    options = {"max_methods": 200, "max_iterations": 8}
    options.update(overrides)
    return DataFlowEngine(dex_files=[dex], options=options).run()


def _by_status(result, status):
    return [f for f in result.findings if f.status == status]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def test_intraprocedural_confirmed_with_transform():
    result = _run(sms_exfil_dex())
    confirmed = _by_status(result, FlowStatus.CONFIRMED)
    assert len(confirmed) >= 1
    sms_http = next(
        f for f in confirmed if f.source == "sms" and f.sink == "http"
    )
    assert sms_http.source_method == sms_http.sink_method
    assert "base64" in sms_http.transformations
    assert sms_http.confidence == "high"
    assert len(sms_http.path) == 1
    # A real established flow was NOT reported as NOT_ESTABLISHED.
    assert not any(
        f.source == "sms"
        and f.sink == "http"
        and f.status == FlowStatus.NOT_ESTABLISHED
        for f in result.not_established
    )


def test_cross_method_param_flow_probable():
    result = _run(cross_param_dex())
    probable = _by_status(result, FlowStatus.PROBABLE)
    sms_http = next(
        f for f in probable if f.source == "sms" and f.sink == "http"
    )
    assert sms_http.path == [
        "Lcom/app/Collect;->collect()V",
        "Lcom/app/Leak;->leak(Ljava/lang/String;)V",
    ]
    assert sms_http.confidence == "medium"


def test_cross_method_return_flow_probable():
    result = _run(call_log_return_dex())
    probable = _by_status(result, FlowStatus.PROBABLE)
    focused = [f for f in probable if f.sink == "exec"]
    assert any(f.source == "call_log" for f in focused)
    assert any(f.source == "content_query" for f in focused)
    for f in focused:
        assert f.path[0] == "Lcom/app/CallLogSource;->get()Ljava/lang/String;"
        assert f.path[-1] == "Lcom/app/CallLogSink;->go()V"


def test_field_hop_probable():
    result = _run(field_hop_dex())
    probable = _by_status(result, FlowStatus.PROBABLE)
    sms_http = next(
        f for f in probable if f.source == "sms" and f.sink == "http"
    )
    assert sms_http.path == [
        "Lcom/app/Hop;->collect()V",
        "Lcom/app/Hop;->flush()V",
    ]


def test_callback_field_capture():
    result = _run(callback_capture_dex())
    probable = _by_status(result, FlowStatus.PROBABLE)
    focused = [f for f in probable if f.sink == "log"]
    assert any(f.source == "call_log" for f in focused)
    for f in focused:
        assert f.path[-1] == "Lcom/app/Leaker;->run()V"
        assert f.sink_method == "Lcom/app/Leaker;->run()V"


def test_no_evidence_yields_not_established_only():
    result = _run(no_flow_dex())
    assert result.findings == []
    assert result.not_established
    assert any(
        f.source_method == "Lcom/app/NoFlow;->grab()V"
        and f.sink == "http"
        for f in result.not_established
    )


def test_not_established_can_be_disabled():
    result = _run(no_flow_dex(), include_not_established=False)
    assert result.findings == []
    assert result.not_established == []


def test_deterministic_across_runs():
    a = _run(sms_exfil_dex())
    b = _run(sms_exfil_dex())
    assert [f.to_dict() for f in a.findings] == [f.to_dict() for f in b.findings]
    assert [f.to_dict() for f in a.not_established] == [
        f.to_dict() for f in b.not_established
    ]


def test_stats_and_summary_present():
    result = _run(sms_exfil_dex())
    assert result.stats["methods_scanned"] >= 1
    assert result.stats["flows_total"] >= 1
    assert result.summary.startswith("data flow:")
    assert result.limitations


# ---------------------------------------------------------------------------
# Wiring through REEngine
# ---------------------------------------------------------------------------


class DataFlowSeederAnalyzer(BaseAnalyzer):
    name = "dataflow-seeder"
    version = "0.1.0"
    description = "seeds fake DEX so the dataflow stage runs hermetic"

    def run(self, context) -> None:
        inject_fakes(context.artifacts, fake_dex=[sms_exfil_dex()])


def test_engine_dataflow_stage_and_report_section(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(
        apk_path=apk_path,
        analyzers=[DataFlowSeederAnalyzer()],
        dataflow_options={
            "max_methods": 200,
            "max_iterations": 8,
            "include_not_established": False,
        },
    )
    report = engine.run()

    assert engine.dataflow is not None
    assert engine.dataflow.summary.startswith("data flow:")
    assert len(engine.dataflow.findings) >= 1
    section = next(
        (s for s in report.sections if s.name == "dataflow"), None
    )
    assert section is not None
    assert section.data["summary"].startswith("data flow:")
    assert isinstance(section.data["findings"], list)
    assert section.data["findings"][0]["status"] == "CONFIRMED"
    registered = [
        m for m in engine.context.modules if m.name == "dataflow"
    ]
    assert registered and registered[0].version == DATAFLOW_VERSION


def test_engine_dataflow_disabled_by_default(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake")
    engine = REEngine(
        apk_path=apk_path, analyzers=[DataFlowSeederAnalyzer()]
    )
    report = engine.run()
    assert engine.dataflow is None
    assert not [s for s in report.sections if s.name == "dataflow"]


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_dataflow_does_not_import_classifier():
    from re_engine.dataflow import engine as engine_module
    from re_engine.dataflow import models as models_module
    from re_engine.dataflow import operands as operands_module
    from re_engine.dataflow import specs as specs_module

    texts = []
    for module in (
        engine_module,
        models_module,
        operands_module,
        specs_module,
    ):
        texts.append(Path(module.__file__).read_text(encoding="utf-8"))
    joined = "\n".join(texts).lower()
    assert "ai.predictor" not in joined
    assert "xgboost" not in joined
    assert "pandas" not in joined