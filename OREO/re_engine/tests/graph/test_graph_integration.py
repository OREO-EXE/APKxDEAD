"""End-to-end call-graph tests against ``samples/app.apk`` (F-Droid, gated)."""

from pathlib import Path

import pytest

SAMPLE_APK = str(Path(__file__).resolve().parents[3] / "samples" / "app.apk")


@pytest.fixture(scope="module")
def graph():
    pytest.importorskip("androguard")
    from re_engine.graph.builder import CallGraphBuilder

    from re_engine.apk import ApkAccessor
    from re_engine.models.context import AnalysisContext, Component

    accessor = ApkAccessor(SAMPLE_APK)
    assert accessor.dex, "sample APK must contain DEX files"
    try:
        context = AnalysisContext()
        context.artifacts = accessor
        apk = accessor.androguard_apk
        context.components = [
            Component(name=str(name), kind=kind, exported=True)
            for kind, names in (
                ("receiver", apk.get_receivers()),
                ("activity", apk.get_activities()),
                ("service", apk.get_services()),
                ("provider", apk.get_providers()),
            )
            for name in names
        ]
        result = CallGraphBuilder(context=context, options=GRAPH_OPTIONS).build()
    finally:
        accessor.close()
    return result


GRAPH_OPTIONS = {
    "caller_scan_cap": 4000,
    "alarm_scan_cap": 3000,
    "max_nodes": 220,
    "max_external_nodes": 80,
    "max_edges": 3000,
}


def test_real_sample_builds_bounded_callgraph(graph):
    assert graph.node_count > 0
    assert graph.edge_count > 0
    assert graph.node_count <= 220
    assert graph.stats["classes_indexed"] > 0
    assert graph.entry_points()


def test_real_sample_has_resolved_and_inferred_edges(graph):
    from re_engine.graph.models import Resolution

    resolutions = {edge.resolution for edge in graph.edges()}
    assert Resolution.RESOLVED in resolutions
    assert Resolution.INFERRED in resolutions


def test_real_sample_queries_roundtrip(graph):
    from re_engine.graph.models import Resolution

    call_edges = [
        edge
        for edge in graph.edges()
        if edge.metadata.get("kind") == "call" and "method:" in edge.target
    ]
    if call_edges:
        edge = call_edges[0]
        assert graph.node(edge.source) is not None
        assert graph.node(edge.target) is not None
        assert edge.resolution in (Resolution.RESOLVED, Resolution.INFERRED)


def test_real_sample_serialization_roundtrips(graph):
    data = graph.to_dict()
    assert data["summary"].startswith("call graph:")
    assert data["stats"]["nodes_total"] == graph.node_count
    assert len(data["nodes"]) == graph.node_count
    assert len(data["edges"]) == graph.edge_count
    roles = {ep["role"] for ep in data["entry_points"]}
    assert roles, "expected at least one detected entry point"


def test_real_sample_engine_callgraph_section():
    pytest.importorskip("androguard")
    from re_engine import triage

    engine = triage.create_triage_engine(SAMPLE_APK, callgraph_options=GRAPH_OPTIONS)
    report = engine.run()

    assert engine.callgraph is not None
    section = next(
        (s for s in report.sections if s.name == "callgraph"), None
    )
    assert section is not None
    assert section.data["stats"]["nodes_total"] > 0
    assert section.data["entry_points"]