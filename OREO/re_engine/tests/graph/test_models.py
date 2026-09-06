"""Tests for the CallGraph query surface (built directly from synthetic
node/edge maps, no DEX involved)."""

from __future__ import annotations

from re_engine.graph.models import (
    CallEdge,
    CallGraph,
    EntryPoint,
    GraphNode,
    NodeKind,
    Resolution,
)


def build_graph() -> CallGraph:
    app_mids = {"main", "a", "b", "c", "sink"}
    calls = {"main": ["a"], "a": ["b", "c"], "b": ["sink"], "c": ["Lx;->y()V"]}

    class FakeIndex:
        def get_method(self, mid):
            return object() if mid in app_mids else None

        def method_calls(self, mid):
            return list(calls.get(mid, []))

    nodes = {
        "method:main": GraphNode("method:main", "main", NodeKind.METHOD),
        "method:a": GraphNode("method:a", "a", NodeKind.METHOD),
        "method:b": GraphNode("method:b", "b", NodeKind.METHOD),
        "method:c": GraphNode("method:c", "c", NodeKind.METHOD),
        "method:sink": GraphNode("method:sink", "sink", NodeKind.METHOD),
        "framework:x": GraphNode(
            "framework:x", "Lx;->y()V", NodeKind.FRAMEWORK
        ),
    }
    edges = [
        CallEdge("method:main", "method:a", Resolution.RESOLVED, "call a"),
        CallEdge("method:a", "method:b", Resolution.RESOLVED, "call b"),
        CallEdge("method:a", "method:c", Resolution.INFERRED, "dispatch c"),
        CallEdge("method:b", "method:sink", Resolution.RESOLVED, "call sink"),
        CallEdge("method:c", "framework:x", Resolution.UNKNOWN, "external x"),
    ]
    return CallGraph(
        nodes=nodes,
        edges=edges,
        entry_points=[
            EntryPoint("boot_receiver#onReceive", "method:main", "Rx")
        ],
        stats={"nodes_total": 6, "edges_total": 5},
        summary="tiny",
        index=FakeIndex(),
        callers_by_target={
            "a": {"main"},
            "b": {"a"},
            "c": {"a"},
            "sink": {"b"},
        },
        strings_by_text={"secret": {"a", "main"}},
    )


def test_node_and_edge_lookup():
    graph = build_graph()
    assert graph.node("method:a").label == "a"
    assert graph.method_node("a") is not None
    assert graph.method_node("missing") is None
    assert graph.node_count == 6
    assert graph.edge_count == 5
    assert graph.stats["nodes_total"] == 6


def test_get_callers_and_callees():
    graph = build_graph()
    assert graph.get_callers("b") == ["a"]
    assert graph.get_callers("missing") == []


def test_edges_sorted_deterministic():
    graph = build_graph()
    assert graph.edges() == sorted(graph.edges(), key=lambda e: (e.source, e.target))


def test_descendants_traverse_app_methods_only():
    graph = build_graph()
    descendants = graph.descendants("main")
    assert descendants == ["a", "b", "c", "sink"]
    # framework leaves are not included
    assert "Lx;->y()V" not in descendants


def test_ancestors_backwards_closure():
    graph = build_graph()
    assert graph.ancestors("sink") == ["a", "b", "main"]


def test_find_paths_between_source_and_sink():
    graph = build_graph()
    paths = graph.find_paths("main", "sink", max_path_length=5)
    assert ["main", "a", "b", "sink"] in paths
    assert all(path[0] == "main" and path[-1] == "sink" for path in paths)


def test_find_paths_self_and_missing():
    graph = build_graph()
    assert graph.find_paths("main", "main") == [["main"]]
    assert graph.find_paths("main", "nope") == []


def test_component_entry_points_sorted():
    graph = build_graph()
    points = graph.component_entry_points()
    assert [p.role for p in points] == ["boot_receiver#onReceive"]


def test_methods_using_api_tolerates_signatureless_ref():
    graph = build_graph()
    assert graph.methods_using_api("a") == ["main"]
    assert graph.methods_using_api("missing") == []


def test_methods_referencing_string():
    graph = build_graph()
    assert graph.methods_referencing_string("secret") == ["a", "main"]
    assert graph.methods_referencing_string("absent") == []


def test_to_dict_serializable():
    data = build_graph().to_dict()
    assert data["summary"] == "tiny"
    assert len(data["nodes"]) == 6
    assert len(data["edges"]) == 5
    assert data["stats"]["nodes_total"] == 6
    assert data["entry_points"][0]["role"] == "boot_receiver#onReceive"
    assert all("node_id" in n for n in data["nodes"])
    assert all("source" in e for e in data["edges"])