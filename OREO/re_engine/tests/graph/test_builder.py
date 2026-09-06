"""Tests for the deterministic CallGraphBuilder on the hermetic DEX."""

from __future__ import annotations

import pytest

from re_engine.graph.builder import CallGraphBuilder
from re_engine.graph.models import NodeKind, Resolution

from .fixtures import (
    EXFIL_URL,
    MAIN_ACTIVITY,
    MID_APP_CREATE,
    MID_BASE_REPORT,
    MID_BIND_BUTTON,
    MID_EVIL_REPORT,
    MID_FIREBASE,
    MID_IMPLA_ONNOTIFY,
    MID_IMPLB_ONNOTIFY,
    MID_NOTIFY_ONNOTIFY,
    MID_ONCREATE,
    MID_ONRECEIVE_ALARM,
    MID_ONRECEIVE_STEAL,
    MID_PAYLOAD_COLLATERAL,
    MID_PAYLOAD_EXFIL,
    MID_PAYLOAD_RUNTASK,
    MID_PAYLOAD_USEWORKER,
    MID_PROVIDER_QUERY,
    MID_SCHEDULE,
    MID_SPY_CREATE,
    MID_UICLICK,
    MID_WORKER_DOWORK,
    SECRET_STRING,
    STEAL_RECEIVER,
    build_callgraph_dex,
    fake_context,
)


def build(options=None, components=True):
    dex = build_callgraph_dex()
    context = fake_context(dex) if components else None
    return CallGraphBuilder(
        context=context,
        dex_files=[dex],
        options={"max_nodes": 2000, "max_edges": 5000, **(options or {})},
    ).build()


def test_build_structure_has_all_node_kinds():
    graph = build()
    kinds = {node.kind for node in graph.nodes()}
    assert NodeKind.COMPONENT in kinds
    assert NodeKind.CLASS in kinds
    assert NodeKind.METHOD in kinds
    assert NodeKind.ENTRY in kinds
    assert NodeKind.FRAMEWORK in kinds
    assert graph.node_count > 0
    assert graph.edge_count > 0
    assert graph.stats["components"] == 4


def test_component_points_to_class_with_resolved_declaration():
    graph = build()
    component = graph.node(f"component:activity:{MAIN_ACTIVITY}")
    assert component is not None
    declared = [
        e
        for e in graph.edges()
        if e.source == f"component:activity:{MAIN_ACTIVITY}"
    ]
    assert declared
    assert declared[0].resolution == Resolution.RESOLVED
    assert declared[0].target == "class:Lcom/app/MainActivity;"


def test_direct_call_is_resolved():
    graph = build()
    edges = [
        e
        for e in graph.edges()
        if e.source == f"method:{MID_ONCREATE}"
        and e.target == f"method:{MID_PAYLOAD_RUNTASK}"
    ]
    assert edges
    assert all(e.resolution == Resolution.RESOLVED for e in edges)


def test_interface_dispatch_is_inferred_with_multiple_targets():
    graph = build()
    edges = [
        e
        for e in graph.edges()
        if e.source == f"method:{MID_ONCREATE}"
        and e.target == f"method:{MID_NOTIFY_ONNOTIFY}"
    ]
    # The interface dispatcher itself has an abstract decl: skipped.
    assert not edges
    inferred = [
        e
        for e in graph.edges()
        if e.source == f"method:{MID_ONCREATE}"
        and e.target in (f"method:{MID_IMPLA_ONNOTIFY}", f"method:{MID_IMPLB_ONNOTIFY}")
    ]
    assert len(inferred) == 2
    assert all(e.resolution == Resolution.INFERRED for e in inferred)
    assert all(e.metadata.get("dispatch_candidates") == 2 for e in inferred)


def test_invoke_interface_from_concrete_method_is_inferred():
    graph = build()
    inferred = [
        e
        for e in graph.edges()
        if e.source == f"method:{MID_PAYLOAD_EXFIL}"
        and e.target in (f"method:{MID_IMPLA_ONNOTIFY}", f"method:{MID_IMPLB_ONNOTIFY}")
    ]
    assert len(inferred) == 2
    assert all(e.resolution == Resolution.INFERRED for e in inferred)


def test_virtual_dispatch_over_subclass_overrides_is_inferred():
    graph = build()
    use_worker = MID_PAYLOAD_USEWORKER
    inferred = [
        e
        for e in graph.edges()
        if e.source == f"method:{use_worker}"
        and e.target in (f"method:{MID_BASE_REPORT}", f"method:{MID_EVIL_REPORT}")
        and e.resolution == Resolution.INFERRED
    ]
    # virtual report() over BaseWorker -> {BaseWorker, EvilWorker} = INFERRED;
    # direct virtual report() on EvilWorker -> single candidate.
    assert len(inferred) == 2
    assert all(e.metadata.get("dispatch_candidates") == 2 for e in inferred)
    direct_evil = [
        e
        for e in graph.edges()
        if e.source == f"method:{use_worker}"
        and e.target == f"method:{MID_EVIL_REPORT}"
        and e.resolution == Resolution.RESOLVED
    ]
    assert len(direct_evil) == 1


def test_external_calls_become_unknown_framework_edges():
    graph = build()
    external = [
        e
        for e in graph.edges()
        if e.metadata.get("kind") == "call-external"
    ]
    assert external
    assert all(e.resolution == Resolution.UNKNOWN for e in external)
    assert external[0].target.startswith("framework:")
    assert graph.node(external[0].target) is not None


def test_inheritance_edges_resolved():
    graph = build()
    evil_edges = [
        e
        for e in graph.edges()
        if e.source == "class:Lcom/app/EvilWorker;"
        and e.target == "class:Lcom/app/BaseWorker;"
    ]
    assert evil_edges
    assert all(e.resolution == Resolution.RESOLVED for e in evil_edges)
    main_edges = [
        e
        for e in graph.edges()
        if e.source == "class:Lcom/app/MainActivity;"
        and e.target == "framework:Landroid/app/Activity;"
    ]
    assert main_edges
    assert all(e.resolution == Resolution.RESOLVED for e in main_edges)


def test_callback_registration_is_inferred():
    graph = build()
    callback = [
        e
        for e in graph.edges()
        if e.source == f"method:{MID_BIND_BUTTON}"
        and e.target == f"method:{MID_UICLICK}"
    ]
    assert callback
    assert all(e.resolution == Resolution.INFERRED for e in callback)
    assert all(e.metadata.get("kind") == "callback" for e in callback)


def test_alarm_scheduler_links_to_receiver_onReceive():
    graph = build()
    alarm = [
        e
        for e in graph.edges()
        if e.source == f"method:{MID_SCHEDULE}"
        and e.target == f"method:{MID_ONRECEIVE_ALARM}"
    ]
    assert alarm
    assert all(e.resolution == Resolution.INFERRED for e in alarm)
    assert all(e.metadata.get("kind") == "callback" for e in alarm)
    assert all(e.metadata.get("via") == "alarm_manager" for e in alarm)


def test_entry_point_markers_wire_to_methods():
    graph = build()
    markers = [
        e for e in graph.edges()
        if e.source.startswith("entry:") and e.metadata.get("kind") == "entry"
    ]
    assert markers
    assert all(e.resolution == Resolution.INFERRED for e in markers)
    entry_ids = {e.source for e in markers}
    assert all(graph.node(node_id) is not None for node_id in entry_ids)


def test_usage_queries_across_the_whole_scan():
    graph = build()
    assert MID_BIND_BUTTON in graph.methods_referencing_string(SECRET_STRING)
    assert MID_PAYLOAD_EXFIL in graph.methods_referencing_string(EXFIL_URL)
    assert MID_SCHEDULE in graph.methods_using_api(
        "Landroid/app/PendingIntent;->getBroadcast"
    )
    callers = graph.get_callers("Lcom/app/Payload;->runTask()V")
    assert MID_ONCREATE in callers


def test_transitive_descendants_and_paths():
    graph = build()
    descendants = graph.descendants(MID_ONCREATE)
    assert MID_PAYLOAD_RUNTASK in descendants
    assert MID_PAYLOAD_COLLATERAL in descendants
    paths = graph.find_paths(MID_ONCREATE, MID_PAYLOAD_COLLATERAL)
    assert any(
        path == [MID_ONCREATE, MID_PAYLOAD_RUNTASK, MID_PAYLOAD_COLLATERAL]
        for path in paths
    )
    # dispatch resolution is a graph-edge fact, only visible in path search.
    assert any(MID_IMPLA_ONNOTIFY in path for path in paths)


def test_ancestors_of_sink_include_entry_chains():
    graph = build()
    ancestors = graph.ancestors(MID_PAYLOAD_RUNTASK)
    assert MID_ONCREATE in ancestors
    assert MID_ONRECEIVE_ALARM in ancestors
    assert MID_UICLICK in ancestors


def test_build_is_deterministic():
    first = build().to_dict()
    second = build().to_dict()
    assert first == second


def test_node_budget_truncates_but_keeps_entry_points():
    graph = build(options={"max_nodes": 30})
    assert graph.node_count == 30
    # entry markers come before method scanning, so they survive truncation.
    assert any(node.kind == NodeKind.ENTRY for node in graph.nodes())
    assert graph.stats["node_overflow"] >= 1


def test_builder_does_not_import_classifier():
    import re_engine.graph.builder as builder_module
    import re_engine.graph.entrypoints as entrypoints_module
    import re_engine.graph.models as models_module
    from pathlib import Path

    texts = []
    for module in (builder_module, entrypoints_module, models_module):
        texts.append(Path(module.__file__).read_text(encoding="utf-8"))
    joined = "\n".join(texts).lower()
    assert "ai.predictor" not in joined
    assert "xgboost" not in joined


def test_build_without_components_degrades_gracefully():
    graph = build(components=False)
    assert graph.stats["components"] == 0
    assert graph.node_count >= 0
    assert bool(graph.entry_points())