"""Call-graph wiring through REEngine + report section (hermetic)."""

from __future__ import annotations

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.engine import REEngine
from re_engine.tests.triage.fixtures import inject_fakes

from .fixtures import (
    MAIN_ACTIVITY,
    STEAL_RECEIVER,
    build_callgraph_dex,
)


class CallGraphSeederAnalyzer(BaseAnalyzer):
    """Injects the fake DEX + manifest context so the graph stage runs hermetic."""

    name = "callgraph-seeder"
    version = "0.1.0"
    description = "seeds DEX + components for call-graph wiring tests"

    def run(self, context) -> None:
        inject_fakes(context.artifacts, fake_dex=[build_callgraph_dex()])
        context.package_name = "com.app"
        from re_engine.models.context import Component

        context.components = [
            Component(name=MAIN_ACTIVITY, kind="activity", exported=True),
            Component(name=STEAL_RECEIVER, kind="receiver", exported=True),
        ]
        context.boot_receivers = [STEAL_RECEIVER]


def test_engine_callgraph_stage_and_report_section(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"MZ\x90\x00fake-apk-content")
    engine = REEngine(
        apk_path=apk_path,
        analyzers=[CallGraphSeederAnalyzer()],
        callgraph_options={"max_nodes": 400, "max_edges": 2000},
    )
    report = engine.run()

    assert engine.callgraph is not None
    assert engine.callgraph.node_count > 0
    section = next(
        (s for s in report.sections if s.name == "callgraph"), None
    )
    assert section is not None
    assert section.data["summary"].startswith("call graph:")
    assert isinstance(section.data["nodes"], list)
    assert isinstance(section.data["edges"], list)
    assert all("node_id" in n for n in section.data["nodes"])
    assert all("source" in e for e in section.data["edges"])
    roles = {ep["role"] for ep in section.data["entry_points"]}
    assert "activity#onCreate" in roles


def test_engine_callgraph_disabled_by_default(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake")
    engine = REEngine(apk_path=apk_path, analyzers=[CallGraphSeederAnalyzer()])
    report = engine.run()
    assert engine.callgraph is None
    assert not [s for s in report.sections if s.name == "callgraph"]