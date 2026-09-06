"""Deterministic models for the APK call graph.

The call graph answers "how are important code paths connected?" by linking
manifest components to classes, classes to their declared methods, and methods
to the methods they invoke (and their transitive downstream / upstream code).

Resolution honesty
------------------
Static analysis cannot perfectly resolve dynamic dispatch. Every edge carries
one of three resolutions:

    RESOLVED    directly observed (a concrete DEX call / manifest declaration)
    INFERRED    derived from patterns (lifecycle triggers, callbacks, or
                dispatch to one of several possible implementations)
    UNKNOWN     the target cannot be determined statically (external/framework
                code, reflection, unresolved dispatch)

The :class:`CallGraph` container exposes the query surface:

    get_callers / get_callees
    descendants / ancestors / find_paths
    component_entry_points
    methods_using_api / methods_referencing_string

Queries answer with method ids (``Lcom/x/Y;->foo()V``) so results stay
deterministic, app-wide and serializable. Nodes/edges are the evidence-rich
snapshot; :meth:`CallGraph.node` / :meth:`CallGraph.method_node` map ids back
to nodes.

Nothing here imports the malware-family classifier or runs an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

# --- Resolution / kind enums -------------------------------------------------


class Resolution(str, Enum):
    """How trustworthy a relationship is."""

    RESOLVED = "RESOLVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class NodeKind(str, Enum):
    """The kind of entity a graph node represents."""

    COMPONENT = "component"
    CLASS = "class"
    METHOD = "method"
    FRAMEWORK = "framework"  # external callee / superclass (android.*, libs not in DEX)
    ENTRY = "entry"  # synthetic entry-point marker (lifecycle / callback trigger)


# --- Node / edge records ------------------------------------------------------


@dataclass
class GraphNode:
    """A single call-graph node carrying its evidence references."""

    node_id: str
    label: str
    kind: NodeKind
    evidence_refs: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "kind": self.kind.value,
            "evidence_refs": self.evidence_refs,
            "metadata": self.metadata,
        }


@dataclass
class CallEdge:
    """A directed relationship between two graph nodes."""

    source: str
    target: str
    resolution: Resolution
    evidence: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "resolution": self.resolution.value,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class EntryPoint:
    """An Android execution entry that can be reached from outside the app."""

    role: str
    method_mid: str
    component: str
    resolution: Resolution = Resolution.INFERRED
    evidence_refs: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "method_mid": self.method_mid,
            "component": self.component,
            "resolution": self.resolution.value,
            "evidence_refs": self.evidence_refs,
            "metadata": self.metadata,
        }


# --- Query caps ---------------------------------------------------------------

DEFAULT_MAX_TRAVERSAL = 5000
DEFAULT_PATH_CAP = 25
DEFAULT_MAX_PATH_LENGTH = 12
DEFAULT_MAX_USAGE_MATCHES = 500


class CallGraph:
    """An interprocedural call graph for one APK.

    The ``nodes`` / ``edges`` fields form the evidence-rich, bounded snapshot.
    Query methods answer over the full bounded caller/callee indexes so they
    cover the whole scanned app, not just the serialized snapshot.
    """

    def __init__(
        self,
        nodes: Optional[Dict[str, GraphNode]] = None,
        edges: Optional[List[CallEdge]] = None,
        entry_points: Optional[List[EntryPoint]] = None,
        stats: Optional[Dict[str, int]] = None,
        summary: str = "",
        index=None,
        callers_by_target: Optional[Dict[str, Set[str]]] = None,
        strings_by_text: Optional[Dict[str, Set[str]]] = None,
    ) -> None:
        self._nodes: Dict[str, GraphNode] = dict(nodes or {})
        self._edges: List[CallEdge] = list(edges or [])
        self._entry_points: List[EntryPoint] = list(entry_points or [])
        self._stats: Dict[str, int] = dict(stats or {})
        self.summary = summary or ""
        self._index = index
        self._callers_by_target: Dict[str, Set[str]] = {
            k: set(v) for k, v in (callers_by_target or {}).items()
        }
        self._strings_by_text: Dict[str, Set[str]] = {
            k: set(v) for k, v in (strings_by_text or {}).items()
        }
        self._adj_out: Dict[str, Set[str]] = {}
        self._adj_in: Dict[str, Set[str]] = {}
        for edge in self._edges:
            self._adj_out.setdefault(edge.source, set()).add(edge.target)
            self._adj_in.setdefault(edge.target, set()).add(edge.source)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    def nodes(self) -> List[GraphNode]:
        return sorted(self._nodes.values(), key=lambda n: n.node_id)

    def edges(self) -> List[CallEdge]:
        return sorted(
            self._edges, key=lambda e: (e.source, e.target, e.resolution.value, e.evidence)
        )

    def entry_points(self) -> List[EntryPoint]:
        return sorted(self._entry_points, key=lambda e: (e.role, e.method_mid))

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def method_node(self, mid: str) -> Optional[GraphNode]:
        return self._nodes.get(f"method:{mid}")

    # ------------------------------------------------------------------
    # Caller / callee queries
    # ------------------------------------------------------------------
    def get_callers(self, mid: str) -> List[str]:
        """Methods (or call refs) that call ``mid``, sorted and deduplicated."""
        return sorted(self._callers_by_target.get(mid, set()), key=str.lower)

    def get_callees(self, mid: str, index=None) -> List[str]:
        """Call-site targets of ``mid`` (direct observed callees), sorted."""
        source = index if index is not None else self._index
        if source is None:
            return []
        return _sorted_uniq(source.method_calls(mid))

    # ------------------------------------------------------------------
    # Transitive queries (app-defined methods only for traversal)
    # ------------------------------------------------------------------
    def descendants(self, mid: str, cap: int = DEFAULT_MAX_TRAVERSAL) -> List[str]:
        """App-defined methods reachable from ``mid`` through call edges."""
        index = self._index
        if index is None:
            return []
        seen: Set[str] = set()
        queue = [callee for callee in self.get_callees(mid) if _is_app_mid(index, callee)]
        while queue and len(seen) < cap:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            for callee in self.get_callees(current):
                if not _is_app_mid(index, callee):
                    continue
                if callee not in seen:
                    queue.append(callee)
        return sorted(seen, key=str.lower)

    def ancestors(self, mid: str, cap: int = DEFAULT_MAX_TRAVERSAL) -> List[str]:
        """App-defined methods that can reach ``mid`` via call edges."""
        seen: Set[str] = set()
        queue = list(self.get_callers(mid))
        while queue and len(seen) < cap:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            for caller in self.get_callers(current):
                if caller not in seen:
                    queue.append(caller)
        return sorted(seen, key=str.lower)

    # ------------------------------------------------------------------
    # Path queries
    # ------------------------------------------------------------------
    def find_paths(
        self,
        source: str,
        sink: str,
        max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
        path_cap: int = DEFAULT_PATH_CAP,
    ) -> List[List[str]]:
        """Up to ``path_cap`` simple paths from ``source`` to ``sink``.

        Paths are returned as lists of method mids. Traversal only follows
        app-defined methods; external (framework) callees are leaves.
        Deterministic: DFS over lexicographically sorted adjacency.
        """
        if source == sink:
            return [[source]]
        start = self._adj_out.get(f"method:{source}")
        end = f"method:{sink}"
        if start is None or self.node(end) is None:
            return []
        results: List[List[str]] = []
        self._dfs(
            f"method:{source}", end, [source], {f"method:{source}"}, results,
            path_cap, max_path_length,
        )
        return sorted(results, key=lambda path: [node.lower() for node in path])

    def _dfs(
        self,
        node: str,
        sink: str,
        path: List[str],
        visited: Set[str],
        results: List[List[str]],
        path_cap: int,
        max_path_length: int,
    ) -> None:
        if len(results) >= path_cap or len(path) > max_path_length:
            return
        for nxt in sorted(self._adj_out.get(node, set())):
            if nxt in visited:
                continue
            if not _is_app_mid(self._index, nxt[len("method:"):] if nxt.startswith("method:") else nxt):
                continue
            candidate = path + [_mid_of(nxt)]
            if nxt == sink:
                results.append(candidate)
                if len(results) >= path_cap:
                    return
                continue
            visited.add(nxt)
            self._dfs(
                nxt, sink, candidate, visited, results, path_cap, max_path_length
            )
            visited.discard(nxt)

    # ------------------------------------------------------------------
    # Entry point / usage queries
    # ------------------------------------------------------------------
    def component_entry_points(self) -> List[EntryPoint]:
        """Every detected Android entry point, deterministically sorted."""
        return self.entry_points()

    def methods_using_api(
        self, api_ref: str, cap: int = DEFAULT_MAX_USAGE_MATCHES
    ) -> List[str]:
        """App methods whose call sites reference ``api_ref``.

        Matching tolerates a missing signature (``Lx/y;->exec`` matches
        ``Lx/y;->exec(Ljava/lang/String;)Ljava/lang/Process;``).
        """
        wanted = _api_key(api_ref)
        matched: Set[str] = set()
        for ref, callers in self._callers_by_target.items():
            if _api_key(ref) != wanted:
                continue
            matched.update(callers)
            if len(matched) >= cap:
                break
        return sorted(matched, key=str.lower)[:cap]

    def methods_referencing_string(
        self, text: str, cap: int = DEFAULT_MAX_USAGE_MATCHES
    ) -> List[str]:
        """App methods whose instructions contain the exact string ``text``."""
        callers = self._strings_by_text.get(text, set())
        return sorted(callers, key=str.lower)[:cap]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "stats": dict(self._stats),
            "entry_points": [e.to_dict() for e in self.entry_points()],
            "nodes": [n.to_dict() for n in self.nodes()],
            "edges": [e.to_dict() for e in self.edges()],
        }


# --- Helpers ------------------------------------------------------------------


def _sorted_uniq(values) -> List[str]:
    return sorted(set(values), key=str.lower)


def _is_app_mid(index, mid: str) -> bool:
    if index is None:
        return False
    return index.get_method(mid) is not None


def _mid_of(node_id: str) -> str:
    """Strip a ``method:`` node-id prefix back to the method mid."""
    return node_id[len("method:"):] if node_id.startswith("method:") else node_id


def _api_key(ref: str) -> str:
    """Normalize a call reference to its ``Lclass;->name`` prefix."""
    ref = str(ref).strip().strip('"')
    head, sep, tail = ref.partition("->")
    if not sep:
        return ref
    name = tail.split("(", 1)[0].rstrip(";")
    return f"{head}->{name}"