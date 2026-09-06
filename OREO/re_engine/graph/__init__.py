"""Call-graph construction and analysis for the RE engine.

Builds a bounded, deterministic interprocedural call graph from DEX bytecode
and manifest context, and exposes graph queries to later stages (behavioral
reconstruction, intelligence):

    CallGraphBuilder  builds the graph (components, classes, methods, edges)
    CallGraph         query surface (callers, callees, paths, entry points...)
    EntryPoint        a triggerable Android entry (lifecycle / callback)

Relationships carry an explicit Resolution (RESOLVED / INFERRED / UNKNOWN) so
later stages know how much to trust a link. Deterministic only.
"""

from re_engine.graph.builder import CallGraphBuilder, GRAPH_VERSION
from re_engine.graph.entrypoints import (
    ALARM_MANAGER_ROLE,
    BOOT_RECEIVER_ROLE,
    CALLBACK_RULES,
)  # role constants
from re_engine.graph.models import (
    DEFAULT_MAX_PATH_LENGTH,
    DEFAULT_MAX_TRAVERSAL,
    DEFAULT_MAX_USAGE_MATCHES,
    DEFAULT_PATH_CAP,
    CallEdge,
    CallGraph,
    EntryPoint,
    GraphNode,
    NodeKind,
    Resolution,
)

__all__ = [
    "CallGraphBuilder",
    "GRAPH_VERSION",
    "CallGraph",
    "GraphNode",
    "CallEdge",
    "EntryPoint",
    "NodeKind",
    "Resolution",
    "DEFAULT_MAX_TRAVERSAL",
    "DEFAULT_PATH_CAP",
    "DEFAULT_MAX_PATH_LENGTH",
    "DEFAULT_MAX_USAGE_MATCHES",
    "BOOT_RECEIVER_ROLE",
    "ALARM_MANAGER_ROLE",
    "CALLBACK_RULES",
]