"""Call-graph construction for the RE engine.

:class:`CallGraphBuilder` turns one APK's DEX files (via a :class:`CodeIndex`)
plus its manifest context into a bounded, deterministic :class:`CallGraph`:

    component -class-> class -declares-> method -calls-> ... -calls-> method

Relationships modeled:

    component -> class                  (RESOLVED, manifest declaration)
    class -> superclass                 (RESOLVED, DEX)
    class -> interface                  (RESOLVED, DEX)
    class -> declared method            (RESOLVED, DEX)
    method -> invoked method            (RESOLVED single concrete target,
                                         INFERRED for virtual/interface dispatch
                                         with multiple implementations)
    method -> external method           (UNKNOWN, framework / library not in DEX)
    entry point -> lifecycle method     (INFERRED, framework trigger)
    register-API -> callback method     (INFERRED, runtime wiring)

Everything is deterministic: classes and methods are visited in sorted order,
sets are emitted sorted, and both nodes and edges are bounded by hard caps.
Nothing here imports ``ai.*`` or runs an LLM.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from re_engine.graph.entrypoints import (
    ALARM_MANAGER_ROLE,
    CALLBACK_RULES,
    PENDING_INTENT_GET_BROADCAST,
    _api_key,
    detect_entry_points,
)
from re_engine.graph.models import (
    CallEdge,
    CallGraph,
    EntryPoint,
    GraphNode,
    NodeKind,
    Resolution,
)
from re_engine.reconstruct.index import CodeIndex
from re_engine.reconstruct.smali import extract_call_sites

GRAPH_VERSION = "0.1.0"

_DIRECT_INVOKES = {"invoke-direct", "invoke-static", "invoke-super"}
_VIRTUAL_INVOKES = {"invoke-virtual", "invoke-interface"}

_CALL_EVIDENCE_CAP = 60
_STRING_EVIDENCE_CAP = 30


class CallGraphBuilder:
    """Bounded, deterministic call-graph builder over one APK's DEX files."""

    def __init__(
        self,
        context: Optional[object] = None,
        dex_files: Optional[list] = None,
        options: Optional[Dict[str, object]] = None,
    ) -> None:
        self.context = context
        self.options = {**self._default_options(), **(options or {})}
        if dex_files is None and context is not None:
            artifacts = getattr(context, "artifacts", None)
            dex_files = getattr(artifacts, "dex", None) or []
        self.index = CodeIndex(
            list(dex_files or []),
            caller_scan_cap=int(self.options["caller_scan_cap"]),
        )

        # Build-time state (reset on every build()).
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[CallEdge] = []
        self._stats: Dict[str, int] = {}
        self._entry_points: List[EntryPoint] = []
        self._sites: Dict[str, list] = {}
        self._refs: Dict[str, dict] = {}

        # Lazy (memoized) closure structures.
        self._transitive_subclasses: Optional[Dict[str, Set[str]]] = None
        self._implementors: Optional[Dict[str, Set[str]]] = None

    @staticmethod
    def _default_options() -> Dict[str, object]:
        return {
            "caller_scan_cap": 15000,
            "alarm_scan_cap": 10000,
            "ref_cap": 200,
            "max_nodes": 2500,
            "max_external_nodes": 500,
            "max_edges": 40000,
        }

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------
    def build(self, entry_points: Optional[List[EntryPoint]] = None) -> CallGraph:
        index = self.index
        index._ensure_index()

        self._nodes = {}
        self._edges = []
        self._stats = self._fresh_stats(index)
        self._entry_points = list(entry_points or [])
        if not self._entry_points:
            self._entry_points = detect_entry_points(
                index,
                self.context,
                alarm_scan_cap=int(self.options["alarm_scan_cap"]),
            )

        scan_mids = self._scan_mids()
        self._stats["caller_scan_truncated"] = int(
            len(scan_mids) >= int(self.options["caller_scan_cap"])
        )

        # Phase A: full bounded usage scan (callers / strings), cached.
        callers_by_target, strings_by_text = self._usage_scan(scan_mids)

        # Phase B: bounded node / edge construction.
        self._component_nodes()
        self._entry_markers()
        node_overflow = self._method_scan(scan_mids)
        self._callback_edges(scan_mids)
        self._alarm_edges()

        self._stats["node_overflow"] = node_overflow
        self._stats["frameworks"] = self._stats[f"nodes_{NodeKind.FRAMEWORK.value}"]
        self._stats["edges_total"] = len(self._edges)

        summary = (
            f"call graph: {len(self._nodes)} nodes / {len(self._edges)} edges / "
            f"{len(self._entry_points)} entry points from "
            f"{self._stats['classes_indexed']} classes"
        )
        return CallGraph(
            nodes=self._nodes,
            edges=self._edges,
            entry_points=self._entry_points,
            stats=self._stats,
            summary=summary,
            index=index,
            callers_by_target=callers_by_target,
            strings_by_text=strings_by_text,
        )

    def _fresh_stats(self, index: CodeIndex) -> Dict[str, int]:
        stats: Dict[str, int] = {
            "dex_count": index.stats.get("dex_count", 0),
            "classes_indexed": index.stats.get("classes_indexed", 0),
            "methods_indexed": index.stats.get("methods_indexed", 0),
            "caller_scan_truncated": 0,
            "methods_scanned": 0,
            "callers_indexed": 0,
            "strings_indexed": 0,
            "components": 0,
            "nodes_total": 0,
            "edges_total": 0,
            "frameworks": 0,
            "entry_points": len(self._entry_points),
            "node_overflow": 0,
            "edge_truncated": 0,
            "external_truncated": 0,
            "unresolved_app_calls": 0,
        }
        for kind in NodeKind:
            stats[f"nodes_{kind.value}"] = 0
        return stats

    # ------------------------------------------------------------------
    # Node / edge bookkeeping
    # ------------------------------------------------------------------
    def _add_node(self, node: GraphNode) -> bool:
        if node.node_id in self._nodes:
            return True
        if len(self._nodes) >= int(self.options["max_nodes"]):
            return False
        self._nodes[node.node_id] = node
        self._stats[f"nodes_{node.kind.value}"] += 1
        self._stats["nodes_total"] = len(self._nodes)
        return True

    def _add_edge(
        self,
        source: str,
        target: str,
        resolution: Resolution,
        evidence: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if len(self._edges) >= int(self.options["max_edges"]):
            self._stats["edge_truncated"] = 1
            return False
        self._edges.append(
            CallEdge(source, target, resolution, evidence, dict(metadata or {}))
        )
        return True

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    def _scan_mids(self) -> List[str]:
        index = self.index
        index._ensure_index()
        cap = int(self.options["caller_scan_cap"])
        mids: List[str] = []
        for descriptor in sorted(index._class_by_desc.keys(), key=str.lower):
            for method in index._class_by_desc[descriptor].methods():
                if method.mid:
                    mids.append(method.mid)
                if cap and len(mids) >= cap:
                    return mids
        return mids

    def _usage_scan(
        self, scan_mids: List[str],
    ) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        index = self.index
        ref_cap = int(self.options["ref_cap"])
        callers_by_target: Dict[str, Set[str]] = {}
        strings_by_text: Dict[str, Set[str]] = {}
        self._sites = {}
        self._refs = {}
        for mid in scan_mids:
            entry = index.get_method(mid)
            if entry is None:
                continue
            try:
                sites = list(extract_call_sites(entry.method))
            except Exception:
                sites = []
            refs = entry.references(ref_cap=ref_cap)
            self._sites[mid] = sites
            self._refs[mid] = refs
            for call in refs["calls"]:
                callers_by_target.setdefault(call, set()).add(mid)
            for text in refs["strings"]:
                strings_by_text.setdefault(text, set()).add(mid)
        self._stats["methods_scanned"] = len(scan_mids)
        self._stats["callers_indexed"] = len(callers_by_target)
        self._stats["strings_indexed"] = len(strings_by_text)
        return callers_by_target, strings_by_text

    # ------------------------------------------------------------------
    # Phase B phases
    # ------------------------------------------------------------------
    def _component_nodes(self) -> None:
        index = self.index
        components = sorted(
            list(getattr(self.context, "components", None) or []),
            key=lambda c: (
                str(getattr(c, "kind", "") or ""),
                str(getattr(c, "name", "") or ""),
            ),
        )
        boot = set(getattr(self.context, "boot_receivers", None) or [])
        foreground = set(getattr(self.context, "foreground_services", None) or [])
        count = 0
        for component in components:
            name = str(getattr(component, "name", "") or "")
            kind = str(getattr(component, "kind", "") or "component")
            if not name:
                continue
            class_entry = index.find_class(name)
            if class_entry is None:
                continue
            node_id = f"component:{kind}:{name}"
            filters = sorted(
                str(f) for f in getattr(component, "intent_filters", None) or []
            )
            node = GraphNode(
                node_id=node_id,
                label=f"{name} ({kind})",
                kind=NodeKind.COMPONENT,
                evidence_refs=[
                    {"kind": "manifest", "ref": f"{kind}:{name}"},
                    {"kind": "class", "ref": class_entry.descriptor},
                ],
                metadata={
                    "kind": kind,
                    "exported": bool(getattr(component, "exported", False)),
                    "intent_filters": filters,
                    "boot": name in boot,
                    "foreground": name in foreground,
                    "descriptor": class_entry.descriptor,
                },
            )
            if not self._add_node(node):
                continue
            count += 1
            class_node = self._ensure_class_node(class_entry.descriptor)
            if class_node is not None:
                self._add_edge(
                    node_id,
                    class_node.node_id,
                    Resolution.RESOLVED,
                    f"declared in manifest: {name}",
                    {"kind": "declaration"},
                )
        self._stats["components"] = count

    def _entry_markers(self) -> None:
        for ep in self._entry_points:
            entry_id = f"entry:{ep.role}:{ep.method_mid}"
            node = GraphNode(
                node_id=entry_id,
                label=ep.role,
                kind=NodeKind.ENTRY,
                evidence_refs=[
                    {"kind": "entry", "ref": ep.role},
                    {"kind": "component", "ref": ep.component},
                ],
                metadata={
                    "component": ep.component,
                    "resolution": ep.resolution.value,
                },
            )
            if not self._add_node(node):
                continue
            method_node = self._ensure_method_node(ep.method_mid)
            if method_node is not None:
                self._add_edge(
                    entry_id,
                    method_node.node_id,
                    Resolution.INFERRED,
                    f"entry {ep.role} triggers {ep.method_mid}",
                    {"kind": "entry", "via": ep.role},
                )

    def _method_scan(self, scan_mids: List[str]) -> int:
        max_nodes = int(self.options["max_nodes"])
        overflow = 0
        for mid in scan_mids:
            if len(self._nodes) >= max_nodes:
                overflow = 1
                break
            method_node = self._ensure_method_node(mid)
            if method_node is None:
                continue
            class_node = self._ensure_class_node(
                method_node.metadata.get("class", "")
            )
            if class_node is not None:
                self._add_edge(
                    class_node.node_id,
                    method_node.node_id,
                    Resolution.RESOLVED,
                    f"declares {mid}",
                    {"kind": "declaration"},
                )
            self._call_edges_for(mid, method_node)
        return overflow

    def _callback_edges(self, scan_mids: List[str]) -> None:
        index = self.index
        for mid in scan_mids:
            class_desc = mid.partition("->")[0]
            sites = self._sites.get(mid)
            if not sites:
                continue
            registered = {_api_key(target) for _, target in sites}
            for prefix, callback_name in CALLBACK_RULES:
                if _api_key(prefix) not in registered:
                    continue
                caller_node = self._nodes.get(f"method:{mid}")
                if caller_node is None:
                    continue
                for candidate in index.methods_named(class_desc, callback_name):
                    candidate_node = self._ensure_method_node(candidate.mid)
                    if candidate_node is None:
                        continue
                    self._add_edge(
                        caller_node.node_id,
                        candidate_node.node_id,
                        Resolution.INFERRED,
                        f"registers {callback_name} via {prefix}",
                        {"kind": "callback", "via": prefix},
                    )

    def _alarm_edges(self) -> None:
        index = self.index
        for ep in self._entry_points:
            if ep.role != ALARM_MANAGER_ROLE:
                continue
            receiver = ep.component or ep.method_mid.partition("->")[0]
            target = index.find_method(receiver, "onReceive")
            if target is None or not target.mid:
                continue
            source = self._nodes.get(f"method:{ep.method_mid}")
            if source is None:
                continue
            target_node = self._ensure_method_node(target.mid)
            if target_node is None:
                continue
            self._add_edge(
                source.node_id,
                target_node.node_id,
                Resolution.INFERRED,
                f"{PENDING_INTENT_GET_BROADCAST} -> {target.mid}",
                {"kind": "callback", "via": "alarm_manager"},
            )

    # ------------------------------------------------------------------
    # Node materialization
    # ------------------------------------------------------------------
    def _ensure_method_node(self, mid: str) -> Optional[GraphNode]:
        node_id = f"method:{mid}"
        existing = self._nodes.get(node_id)
        if existing is not None:
            return existing
        entry = self.index.get_method(mid)
        if entry is None:
            return None
        sites = self._sites.get(mid)
        if sites is None:
            sites = self._parse_sites(entry)
            refs = entry.references(ref_cap=int(self.options["ref_cap"]))
            self._sites[mid] = sites
            self._refs[mid] = refs
        refs = self._refs.get(mid)
        if refs is None:
            refs = entry.references(ref_cap=int(self.options["ref_cap"]))
            self._refs[mid] = refs
        evidence: List[Dict[str, str]] = [
            {
                "kind": "source",
                "ref": f"{getattr(entry.class_entry, 'dex_label', '?')}:{mid}",
            }
        ]
        evidence.extend(
            {"kind": "calls", "ref": target}
            for _, target in sites[: _CALL_EVIDENCE_CAP]
        )
        evidence.extend(
            {"kind": "strings", "ref": text}
            for text in refs["strings"][: _STRING_EVIDENCE_CAP]
        )
        roles = sorted(
            ep.role for ep in self._entry_points if ep.method_mid == mid
        )
        node = GraphNode(
            node_id=node_id,
            label=mid,
            kind=NodeKind.METHOD,
            evidence_refs=evidence,
            metadata={
                "class": entry.class_descriptor,
                "access_flags": entry.access_flags,
                "dex": getattr(entry.class_entry, "dex_label", "?"),
                "calls_count": len(sites),
                "strings_count": len(refs["strings"]),
                "entry_roles": roles,
            },
        )
        if self._add_node(node):
            return node
        return None

    def _ensure_class_node(self, descriptor: str) -> Optional[GraphNode]:
        if not descriptor:
            return None
        node_id = f"class:{descriptor}"
        existing = self._nodes.get(node_id)
        if existing is not None:
            return existing
        class_entry = self.index.find_class(descriptor)
        if class_entry is None:
            return None
        superclass = (class_entry.superclass() or "").strip()
        interfaces = sorted(
            str(i) for i in class_entry.interfaces() if str(i).startswith("L")
        )
        evidence: List[Dict[str, str]] = []
        if superclass:
            evidence.append({"kind": "superclass", "ref": superclass})
        evidence.extend({"kind": "interface", "ref": iface} for iface in interfaces)
        node = GraphNode(
            node_id=node_id,
            label=descriptor,
            kind=NodeKind.CLASS,
            evidence_refs=evidence,
            metadata={
                "descriptor": descriptor,
                "dotted": class_entry.dotted,
                "superclass": superclass,
                "interfaces": interfaces,
            },
        )
        if not self._add_node(node):
            return None
        self._relationship_edges(descriptor, superclass, interfaces)
        return node

    def _framework_node(self, target: str) -> Optional[GraphNode]:
        node_id = f"framework:{target}"
        existing = self._nodes.get(node_id)
        if existing is not None:
            return existing
        if self._stats[f"nodes_{NodeKind.FRAMEWORK.value}"] >= int(
            self.options["max_external_nodes"]
        ):
            self._stats["external_truncated"] = 1
            return None
        node = GraphNode(
            node_id=node_id,
            label=target,
            kind=NodeKind.FRAMEWORK,
            evidence_refs=[{"kind": "framework", "ref": target}],
            metadata={"external": True},
        )
        if self._add_node(node):
            return node
        return None

    def _relationship_edges(
        self, descriptor: str, superclass: str, interfaces: List[str]
    ) -> None:
        for parent in [superclass] + list(interfaces):
            if not parent:
                continue
            if self.index.class_exists(parent):
                target = self._ensure_class_node(parent)
            else:
                target = self._framework_node(parent)
            if target is None:
                continue
            kind = "superclass" if parent == superclass else "implements"
            self._add_edge(
                f"class:{descriptor}",
                target.node_id,
                Resolution.RESOLVED,
                f"{kind} {parent}",
                {"kind": kind},
            )

    # ------------------------------------------------------------------
    # Call resolution
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_sites(entry) -> List[Tuple[str, str]]:
        try:
            return list(extract_call_sites(entry.method))
        except Exception:
            return []

    def _call_edges_for(self, mid: str, method_node: GraphNode) -> None:
        sites = self._sites.get(mid) or []
        for opcode, target in sites:
            target_class, sep, _ = target.partition("->")
            if not sep:
                continue
            if not self.index.class_exists(target_class):
                target_node = self._framework_node(target)
                if target_node is not None:
                    self._add_edge(
                        method_node.node_id,
                        target_node.node_id,
                        Resolution.UNKNOWN,
                        f"call {target} ({opcode})",
                        {"kind": "call-external", "opcode": opcode},
                    )
                continue
            candidates = self._dispatch_candidates(target, opcode)
            if not candidates:
                self._stats["unresolved_app_calls"] += 1
                continue
            resolution = (
                Resolution.INFERRED if len(candidates) > 1 else Resolution.RESOLVED
            )
            for candidate in candidates:
                candidate_node = self._ensure_method_node(candidate)
                if candidate_node is None:
                    self._stats["node_overflow"] += 1
                    continue
                metadata: Dict[str, Any] = {
                    "kind": "call",
                    "opcode": opcode,
                    "dispatch_candidates": len(candidates),
                }
                if len(candidates) > 1:
                    metadata["dispatch"] = "virtual"
                self._add_edge(
                    method_node.node_id,
                    candidate_node.node_id,
                    resolution,
                    f"call {target} ({opcode})",
                    metadata,
                )

    def _dispatch_candidates(self, target: str, opcode: str) -> List[str]:
        class_desc, sep, rest = target.partition("->")
        if not sep:
            return []
        index = self.index
        name = rest.split("(", 1)[0]
        _, paren, tail = rest.partition("(")
        signature = ("(" + tail) if paren else None
        if not class_desc.endswith(";"):
            class_desc += ";"
        candidates: Set[str] = set()

        def consider(cls_desc: str) -> None:
            entry = index.find_method(cls_desc, name, signature)
            if entry is None or not entry.mid:
                return
            if "abstract" in (entry.access_flags or ""):
                return
            candidates.add(entry.mid)

        if opcode == "invoke-super":
            for ancestor in self._super_chain(class_desc):
                consider(ancestor)
        elif opcode in _DIRECT_INVOKES:
            consider(class_desc)
        else:
            consider(class_desc)
            for sub in self._subclass_closure().get(class_desc, set()):
                consider(sub)
            for impl in self._implementors_closure().get(class_desc, set()):
                consider(impl)
        return sorted(candidates, key=str.lower)

    def _super_chain(self, descriptor: str) -> List[str]:
        chain: List[str] = []
        cursor = descriptor
        while True:
            entry = self.index._class_by_desc.get(cursor)
            if entry is None:
                break
            parent = (entry.superclass() or "").strip()
            if not parent or not self.index.class_exists(parent):
                break
            chain.append(parent)
            cursor = parent
        return chain

    # ------------------------------------------------------------------
    # Closure helpers (memoized).
    # ------------------------------------------------------------------
    def _subclass_closure(self) -> Dict[str, Set[str]]:
        if self._transitive_subclasses is not None:
            return self._transitive_subclasses
        index = self.index
        children: Dict[str, Set[str]] = {}
        for descriptor in index._class_by_desc:
            parent = (index._class_by_desc[descriptor].superclass() or "").strip()
            if parent and index.class_exists(parent):
                children.setdefault(parent, set()).add(descriptor)
        closure: Dict[str, Set[str]] = {}
        for descriptor in index._class_by_desc:
            seen: Set[str] = set()
            queue = list(children.get(descriptor, set()))
            while queue:
                current = queue.pop()
                if current in seen:
                    continue
                seen.add(current)
                queue.extend(
                    child for child in children.get(current, set()) if child not in seen
                )
            closure[descriptor] = seen
        self._transitive_subclasses = closure
        return closure

    def _implementors_closure(self) -> Dict[str, Set[str]]:
        if self._implementors is not None:
            return self._implementors
        index = self.index
        index._ensure_index()
        direct: Dict[str, Set[str]] = {}
        for descriptor in index._class_by_desc:
            entry = index._class_by_desc[descriptor]
            seen: Set[str] = {
                str(i) for i in entry.interfaces() if str(i).startswith("L")
            }
            stack = list(seen)
            visited = set(seen)
            while stack:
                current = stack.pop()
                centry = index._class_by_desc.get(current)
                if centry is None:
                    continue
                for extra in (
                    str(i) for i in centry.interfaces() if str(i).startswith("L")
                ):
                    if extra not in visited:
                        visited.add(extra)
                        stack.append(extra)
            direct[descriptor] = visited
        full: Dict[str, Set[str]] = {}
        for descriptor in index._class_by_desc:
            merged = set(direct.get(descriptor, set()))
            parent = (index._class_by_desc[descriptor].superclass() or "").strip()
            visited = set()
            pending = [parent] if parent else []
            while pending:
                ancestor = pending.pop()
                if not ancestor or ancestor in visited:
                    continue
                visited.add(ancestor)
                aentry = index._class_by_desc.get(ancestor)
                if aentry is None:
                    continue
                merged.update(direct.get(ancestor, set()))
                grandparent = (aentry.superclass() or "").strip()
                if grandparent:
                    pending.append(grandparent)
            full[descriptor] = merged
        implementors: Dict[str, Set[str]] = {}
        for descriptor, ifaces in full.items():
            for iface in ifaces:
                implementors.setdefault(iface, set()).add(descriptor)
        self._implementors = implementors
        return implementors