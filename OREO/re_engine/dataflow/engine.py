"""Bounded, deterministic source-to-sink data-flow analysis.

:class:`DataFlowEngine` performs a register-level taint analysis over one
APK's DEX files and emits :class:`DataFlowFinding` records from sensitive
sources to sinks. It never claims a flow merely because the same source and
sink APIs appear in the app: every finding is backed by a concrete data-flow
path reconstructed from the bytecode.

Approach
--------
* **Intraprocedural:** each method's instructions are processed linearly with a
  register -> taint map. Sources create taint, transformations annotate it,
  propagators and container reads carry it, and sink calls that receive a
  tainted register record a sink observation. ``move``/``return``/array/field
  ops move taint around.
* **Interprocedural:** a fixed-point loop recomputes per-method results while
  propagating (a) taint passed into parameters by callers and (b) taint read
  back from instance/static fields that earlier iterations wrote. Callee return
  taints flow back into each caller's ``move-result`` register.
* **Callbacks:** asynchronous capture (``Handler.post`` / ``Thread.start``
  runnables) is modeled through the captured instance/static fields; a
  Runnable's ``run()`` that reads a tainted field is linked to the writer.
  Register-level closure capture is deliberately not traced.

Everything is deterministic: methods are visited in sorted order, per-register
taint sets and unions are capped, and results are deduplicated and sorted.
Nothing here imports the malware-family classifier or runs an LLM.

Limitations (documented, honest)
--------------------------------
* Register analysis is linear and does not model control-flow branches or
  loop-carried values precisely (over-approximated where cheap).
* Call-argument-to-parameter mapping is positional and does not expand wide
  registers, so the upstream taint of a parameter is approximate.
* Field taint is a whole-program union (no write-to-read ordering), and
  dynamic dispatch may over-approximate callee taint.
* Static analysis cannot know what the runtime actually does; statuses
  (CONFIRMED/PROBABLE/POSSIBLE/NOT_ESTABLISHED) convey confidence, and
  ``NOT_ESTABLISHED`` records (optional, capped) say "both sides exist but no
  path was proven."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from re_engine.dataflow.models import DataFlowFinding, DataFlowResult, FlowStatus
from re_engine.dataflow.operands import (
    extract_refs,
    instruction_info,
    registers_in,
    split_ref,
)
from re_engine.dataflow.specs import (
    is_propagator,
    is_stream_marker,
    match_sinks,
    match_sources,
    match_transforms,
    match_uri_source,
)
from re_engine.reconstruct.index import CodeIndex

DATAFLOW_VERSION = "0.1.0"

_INVOKE_NAMES = {
    "invoke-direct",
    "invoke-static",
    "invoke-virtual",
    "invoke-interface",
    "invoke-super",
    "invoke-direct/range",
    "invoke-static/range",
    "invoke-virtual/range",
    "invoke-interface/range",
    "invoke-super/range",
}
_MOVE_RESULT = {"move-result", "move-result-object", "move-result-wide"}
_MOVE_OPS = {
    "move",
    "move-object",
    "move-wide",
    "move/from16",
    "move-object/from16",
    "move-wide/from16",
    "move-object/16",
    "move-wide/16",
}
_FIELD_READ = {"iget", "iget-object", "iget-boolean", "iget-byte",
               "iget-char", "iget-short", "iget-wide",
               "sget", "sget-object", "sget-boolean", "sget-byte",
               "sget-char", "sget-short", "sget-wide"}
_FIELD_WRITE = {"iput", "iput-object", "iput-boolean", "iput-byte",
                "iput-char", "iput-short", "iput-wide",
                "sput", "sput-object", "sput-boolean", "sput-byte",
                "sput-char", "sput-short", "sput-wide"}
_ARRAY_READ = {"aget", "aget-object", "aget-boolean", "aget-byte",
               "aget-char", "aget-short", "aget-wide"}
_ARRAY_WRITE = {"aput", "aput-object", "aput-boolean", "aput-byte",
                "aput-char", "aput-short", "aput-wide"}
_RETURN_OPS = {"return", "return-object", "return-wide"}
_CALLBACK_POST = {"Landroid/os/Handler;->post", "Landroid/os/Handler;->postDelayed"}
_CALLBACK_THREAD = {"Ljava/lang/Thread;->start"}


# ---------------------------------------------------------------------------
# Taint representation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Tag:
    """One tracked taint value flowing through registers.

    ``sources`` is a tuple of ``(category, source_method_mid)`` pairs carrying
    the sensitive origin(s). ``transforms`` are sorted labels applied along the
    way. ``path`` is the ordered sequence of method mids the taint has traveled
    through (the origin method first), used to render the finding path.
    """

    sources: Tuple[Tuple[str, str], ...] = ()
    transforms: Tuple[str, ...] = ()
    path: Tuple[str, ...] = ()

    def with_transform(self, label: str) -> "Tag":
        if label in self.transforms:
            return self
        return Tag(self.sources, tuple(sorted(set(self.transforms) | {label})), self.path)

    def via(self, mid: str) -> "Tag":
        if mid in self.path:
            return self
        return Tag(self.sources, self.transforms, self.path + (mid,))

    def add_source(self, category: str, source_mid: str) -> "Tag":
        merged = tuple(sorted(set(self.sources) | {(category, source_mid)}))
        return Tag(merged, self.transforms, self.path)

    @property
    def is_tainted(self) -> bool:
        return bool(self.sources)


EMPTY_TAG = Tag()


@dataclass
class MethodResult:
    """Result of analyzing a single method in one pass."""

    mid: str = ""
    sinks: List[Tuple[str, Tag]] = field(default_factory=list)  # (label, tag)
    reterns: List[Tag] = field(default_factory=list)
    field_writes: Dict[str, Set[Tag]] = field(default_factory=dict)
    field_reads: Set[str] = field(default_factory=set)
    param_sinks: Dict[int, List[Tuple[str, Tag]]] = field(default_factory=dict)
    param_reterns: Dict[int, Set[Tag]] = field(default_factory=dict)
    has_native: bool = False


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class DataFlowEngine:
    """Bounded, deterministic taint data-flow engine for one APK."""

    def __init__(
        self,
        context: Optional[object] = None,
        dex_files: Optional[list] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.context = context
        self.options = {**self._default_options(), **(options or {})}
        if dex_files is None and context is not None:
            artifacts = getattr(context, "artifacts", None)
            dex_files = getattr(artifacts, "dex", None) or []
        self.index = CodeIndex(list(dex_files or []))
        self._findings_raw: List[DataFlowFinding] = []
        self._not_established: List[DataFlowFinding] = []
        self._limitations: List[str] = []
        self._stats: Dict[str, int] = {}
        self._field_taints: Dict[str, Set[Tag]] = {}
        self._field_readers: Dict[str, Set[str]] = {}
        self._field_writers: Dict[str, Set[str]] = {}
        self._param_taints: Dict[str, Dict[int, Set[Tag]]] = {}
        self._last_incoming: Dict[str, tuple] = {}
        self._method_results: Dict[str, MethodResult] = {}
        self._all_sources: Set[Tuple[str, str]] = set()
        self._all_sinks: Set[str] = set()

    @staticmethod
    def _default_options() -> Dict[str, Any]:
        return {
            "max_methods": 6000,
            "max_iterations": 6,
            "max_union": 8,
            "max_steps": 24,
            "max_flows_total": 800,
            "include_not_established": True,
            "not_established_cap": 100,
            "track_fields": True,
            "callbacks": True,
        }

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    def run(self) -> DataFlowResult:
        self.index._ensure_index()
        mids = self._scan_mids()
        self._stats["methods_scanned"] = len(mids)
        max_iters = int(self.options["max_iterations"])
        iterations = 0
        for _iteration in range(max_iters):
            iterations += 1
            moved = self._pass_(mids)
            if not moved:
                break
        self._stats["iterations_used"] = iterations
        self._limitations = [
            "Data-flow is register-level over a linear instruction scan; "
            "control-flow branches and loop-carried values are over-approximated.",
            "Argument-to-parameter mapping is positional and does not expand wide "
            "(long/double) registers; parameter taint is approximate.",
            "Field taint is a whole-program union (no write/read ordering); "
            "callback capture is modeled only through instance/static fields "
            "(Runnable/Thread closures are not register-traced).",
            "Native and reflective dispatch cannot be resolved statically and may "
            "under-report sinks.",
        ]
        self._emit_findings(mids)
        result = DataFlowResult(
            findings=self._findings_raw,
            not_established=self._not_established,
            stats=self._stats,
            limitations=self._limitations,
            summary=self._summary(mids),
        )
        return result

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _scan_mids(self) -> List[str]:
        cap = int(self.options["max_methods"])
        mids: List[str] = []
        for descriptor in sorted(self.index._class_by_desc.keys(), key=str.lower):
            for method in self.index._class_by_desc[descriptor].methods():
                if method.mid:
                    mids.append(method.mid)
                if cap and len(mids) >= cap:
                    return mids
        return mids

    def _pass_(self, mids: List[str]) -> bool:
        """One fixed-point pass. Returns True if field/param state changed."""
        changed = False
        for mid in mids:
            entry = self.index.get_method(mid)
            if entry is None:
                continue
            incoming = self._param_taints.get(mid, {})
            sig = self._incoming_signature(incoming)
            if sig != self._last_incoming.get(mid):
                changed = True
                self._last_incoming[mid] = sig
            result = self._analyze_method(mid, entry, incoming)
            # Merge field writes.
            for field_ref, tags in result.field_writes.items():
                if not self.options["track_fields"]:
                    break
                prior = self._field_taints.get(field_ref, set())
                merged = prior | tags
                if merged != prior:
                    self._field_taints[field_ref] = merged
                    changed = True
                self._field_writers.setdefault(field_ref, set()).add(mid)
            for field_ref in result.field_reads:
                self._field_readers.setdefault(field_ref, set()).add(mid)
            self._method_results[mid] = result
            if result.has_native:
                self._all_sinks.add("native")
            for sink_label, _ in result.sinks:
                self._all_sinks.add(sink_label)
            for cat, src_mid in self._sources_of(result):
                self._all_sources.add((cat, src_mid))
        return changed

    @staticmethod
    def _incoming_signature(incoming: Dict[int, Set[Tag]]) -> tuple:
        """A hashable fingerprint of the param taint a method receives."""
        return tuple(
            sorted(
                (pidx, tuple(sorted(tags))) for pidx, tags in incoming.items()
            )
        )

    def _sources_of(self, result: MethodResult) -> Set[Tuple[str, str]]:
        sources: Set[Tuple[str, str]] = set()
        for _, tag in result.sinks:
            for cat, src in tag.sources:
                sources.add((cat, src))
        for tags in result.field_writes.values():
            for tag in tags:
                for cat, src in tag.sources:
                    sources.add((cat, src))
        for tag in result.reterns:
            for cat, src in tag.sources:
                sources.add((cat, src))
        return sources

    # ------------------------------------------------------------------
    # Intraprocedural analysis
    # ------------------------------------------------------------------
    def _analyze_method(
        self, mid: str, entry, incoming: Dict[int, Set[Tag]]
    ) -> MethodResult:
        result = MethodResult(mid=mid)
        access = entry.access_flags or ""
        if "native" in access:
            result.has_native = True

        regs: Dict[str, List[Tag]] = {}
        reg_params: Dict[str, Set[int]] = {}
        consts: Dict[str, str] = {}
        pending_result: Optional[List[Tag]] = None
        pending_param_idx: Optional[Set[int]] = None
        params = self._param_registers(entry)
        self._seed_params(regs, reg_params, params, incoming, mid)

        try:
            instructions = list(entry.method.get_code().get_bc().get_instructions())
        except Exception:
            instructions = []

        for ins in instructions:
            try:
                name, operands = instruction_info(ins)
            except Exception:
                continue
            if name in _MOVE_RESULT:
                reg = registers_in(operands)[0] if registers_in(operands) else None
                if reg is not None and pending_result is not None:
                    regs[reg] = self._merge(pending_result, regs.get(reg, []))
                    if pending_param_idx:
                        reg_params[reg] = set(pending_param_idx)
                pending_result = None
                pending_param_idx = None
                continue
            if name in _INVOKE_NAMES:
                pending_result, pending_param_idx = self._handle_invoke(
                    mid, entry, name, operands, regs, reg_params, result, consts
                )
                continue
            if name in _MOVE_OPS:
                r = registers_in(operands)
                if len(r) == 2:
                    regs[r[0]] = self._merge(list(regs.get(r[1], [])), [])
                    if r[1] in reg_params:
                        reg_params[r[0]] = set(reg_params[r[1]])
                    elif r[1] in consts:
                        consts[r[0]] = consts[r[1]]
                    else:
                        reg_params.pop(r[0], None)
                        consts.pop(r[0], None)
                continue
            if name in _FIELD_READ:
                operands = operands or []
                refs = extract_refs(operands)
                dest = registers_in(operands)[0] if registers_in(operands) else None
                if dest is not None and refs:
                    fref = refs[0]
                    result.field_reads.add(fref)
                    tags = self._field_read(fref, mid)
                    regs[dest] = self._merge(tags, regs.get(dest, []))
                    reg_params.pop(dest, None)
                    consts.pop(dest, None)
                continue
            if name in _FIELD_WRITE:
                operands = operands or []
                refs = extract_refs(operands)
                r = registers_in(operands)
                value_reg = r[0] if r else None
                if refs and value_reg is not None:
                    fref = refs[0]
                    result.field_writes.setdefault(fref, set()).update(regs.get(value_reg, []))
                continue
            if name in _ARRAY_READ:
                r = registers_in(operands)
                if r:
                    src_reg = r[2] if len(r) == 3 else r[1]
                    regs[r[0]] = self._merge(list(regs.get(src_reg, [])), [])
                    if src_reg in reg_params:
                        reg_params[r[0]] = set(reg_params[src_reg])
                    else:
                        reg_params.pop(r[0], None)
                    consts.pop(r[0], None)
                continue
            if name in _ARRAY_WRITE:
                continue
            if name.startswith("const-string"):
                reg = registers_in(operands)[0] if registers_in(operands) else None
                if reg is not None:
                    regs[reg] = []
                    reg_params.pop(reg, None)
                    sval = self._const_string(ins)
                    if sval:
                        consts[reg] = sval
                continue
            if name.startswith("const"):
                reg = registers_in(operands)[0] if registers_in(operands) else None
                if reg is not None:
                    regs[reg] = []
                    reg_params.pop(reg, None)
                    consts.pop(reg, None)
                continue
            if name == "new-instance":
                r = registers_in(operands)
                if r:
                    regs[r[0]] = []
                    reg_params.pop(r[0], None)
                    consts.pop(r[0], None)
                continue
            if name.startswith("int-to") or name.startswith("long-to") or \
               name.startswith("float-to") or name.startswith("double-to"):
                r = registers_in(operands)
                if r and len(r) >= 2:
                    regs[r[0]] = self._merge(list(regs.get(r[1], [])), [])
                    if r[1] in reg_params:
                        reg_params[r[0]] = set(reg_params[r[1]])
                    else:
                        reg_params.pop(r[0], None)
                continue
            if name in _RETURN_OPS:
                r = registers_in(operands)
                if r:
                    returned = self._merge(list(regs.get(r[0], [])), [])
                    result.reterns.extend(returned)
                    for pidx in reg_params.get(r[0], set()):
                        result.param_reterns.setdefault(pidx, set()).update(returned)
                continue
            # instance-of / check-cast / monitor / labels: no taint change.
        return result

    def _handle_invoke(
        self,
        mid: str,
        entry,
        name: str,
        operands: List[str],
        regs: Dict[str, List[Tag]],
        reg_params: Dict[str, Set[int]],
        result: MethodResult,
        consts: Dict[str, str],
    ) -> Tuple[Optional[List[Tag]], Optional[Set[int]]]:
        refs = extract_refs(operands)
        if not refs:
            return None, None
        target = refs[0]
        is_static = "static" in name
        arg_regs = self._ordered_args(operands, is_static)
        tainted_args = [rg for rg in arg_regs if regs.get(rg)]

        # --- Sinks -----------------------------------------------------
        sink_labels = match_sinks(target)
        if sink_labels:
            for rg in arg_regs:
                for tag in regs.get(rg, []):
                    for label, _ in sink_labels:
                        result.sinks.append((label, tag.via(mid)))
                        for pidx in reg_params.get(rg, set()):
                            result.param_sinks.setdefault(
                                pidx, []
                            ).append((label, tag.via(mid)))
            return None, None

        # --- Sources ---------------------------------------------------
        src_labels = list(match_sources(target))
        # URI-literal source rules: ContentResolver.query with a const-string
        # URI naming contacts / call log / sms becomes a specific source.
        if target.startswith("Landroid/content/ContentResolver;->query"):
            for rg in arg_regs:
                uri = consts.get(rg)
                if uri:
                    for label in match_uri_source(uri):
                        src_labels.append((label, "Landroid/content/ContentResolver;->query"))
        if src_labels:
            source_tag = Tag(
                sources=tuple(sorted((label, mid) for label, _ in src_labels)),
                path=(mid,),
            )
            # A reference can be both a source and a propagator (e.g.
            # Bundle.getString reads back what putString stored). When any
            # receiver/argument already carries taint, fold that lineage in.
            param_idx: Set[int] = set()
            if is_propagator(target):
                for rg in registers_in(operands):
                    if regs.get(rg):
                        source_tag = self._merge_tag_paths(
                            source_tag, regs[rg][0], mid
                        )
                    param_idx |= reg_params.get(rg, set())
            # The produced value lands in the following move-result register.
            return [source_tag], (param_idx or None)

        # --- Transforms -------------------------------------------------
        transforms = match_transforms(target)
        if transforms:
            new_tags: List[Tag] = []
            param_idx: Set[int] = set()
            for rg in tainted_args:
                for tag in regs.get(rg, []):
                    t = tag
                    for label, _ in transforms:
                        t = t.with_transform(label)
                    new_tags.append(t)
                param_idx |= reg_params.get(rg, set())
            return self._merge(new_tags, []), (param_idx or None)

        # --- Propagators -------------------------------------------------
        if is_propagator(target):
            new_tags: List[Tag] = []
            param_idx: Set[int] = set()
            # Propagators read taint from the receiver (Cursor/ClipData/etc.)
            # or from an argument (putExtra/getItemAt). Consider all registers.
            for rg in registers_in(operands):
                new_tags.extend(regs.get(rg, []))
                param_idx |= reg_params.get(rg, set())
            return self._merge(new_tags, []), (param_idx or None)

        # --- Stream markers / stream constructors ------------------------
        if is_stream_marker(target):
            return [], None

        # --- App-defined callee ----------------------------------------
        callee_mid = self._resolve_app_mid(target)
        if callee_mid is None:
            return None, None
        callee_entry = self.index.get_method(callee_mid)
        if callee_entry is not None:
            pproto = self._param_indexes(callee_entry)
            incoming = self._param_taints.setdefault(callee_mid, {})
            for idx, rg in enumerate(arg_regs):
                if idx in pproto and regs.get(rg):
                    prev = incoming.get(idx, set())
                    merged = prev | set(regs.get(rg, []))
                    if merged != prev:
                        incoming[idx] = merged
        callee_result = self._method_results.get(callee_mid)
        if callee_result is None:
            return None, None
        ret_tags: List[Tag] = []
        ret_param_idx: Set[int] = set()
        for tag in callee_result.reterns:
            if tag.sources:
                ret_tags.append(tag)
        for idx, rg in enumerate(arg_regs):
            if idx in callee_result.param_reterns and regs.get(rg):
                for ptag in callee_result.param_reterns[idx]:
                    for base in regs.get(rg, []):
                        ret_tags.append(self._merge_tag_paths(base, ptag, callee_mid))
                ret_param_idx |= reg_params.get(rg, set())
        if not ret_tags:
            return None, None
        return self._merge(ret_tags, []), (ret_param_idx or None)

    def _ordered_args(self, operands: List[str], is_static: bool) -> List[str]:
        """Return the argument registers in declared order.

        For instance invokes the first operand is the receiver (``this``);
        the remaining operands are the arguments. Range forms may expand to a
        ``v0 ... v5`` pair which we expand in ``registers_in`` order.
        """
        regs = registers_in(operands)
        if not is_static and regs:
            return regs[1:]
        return regs

    def _resolve_app_mid(self, target: str) -> Optional[str]:
        class_desc, mname, sig = split_ref(target)
        if not class_desc.endswith(";"):
            class_desc += ";"
        entry = self.index.find_method(class_desc, mname, sig or None)
        if entry is None or not entry.mid:
            return None
        return entry.mid

    # ------------------------------------------------------------------
    # Register / param helpers
    # ------------------------------------------------------------------
    def _param_registers(self, entry) -> List[Tuple[int, int]]:
        """Return [(reg_index, param_index)] for parameter registers."""
        try:
            code = entry.method.get_code()
            regs_size = code.get_registers_size()
        except Exception:
            return []
        desc = entry.signature or ""
        n = self._register_param_count(desc)
        total = n
        out = []
        base = regs_size - total
        pidx = 0
        for i, t in enumerate(self._desc_params(desc)):
            out.append((base + i, pidx))
            pidx += 1
        return out

    @staticmethod
    def _desc_params(desc: str) -> List[str]:
        if not desc.startswith("("):
            return []
        end = desc.find(")")
        if end == -1:
            return []
        body = desc[1:end]
        params: List[str] = []
        i = 0
        n = len(body)
        while i < n:
            if body[i] == "[":
                j = i
                while j < n and body[j] == "[":
                    j += 1
                # element type
                if j < n and body[j] == "L":
                    while j < n and body[j] != ";":
                        j += 1
                    j += 1
                    params.append(body[i:j])
                    i = j
                    continue
                else:
                    j += 1
                    params.append(body[i:j])
                    i = j
                    continue
            if body[i] == "L":
                j = i
                while j < n and body[j] != ";":
                    j += 1
                j += 1
                params.append(body[i:j])
                i = j
            else:
                params.append(body[i])
                i += 1
        return params

    @staticmethod
    def _register_param_count(desc: str) -> int:
        count = 0
        for t in DataFlowEngine._desc_params(desc):
            if t in ("J", "D"):
                count += 2
            else:
                count += 1
        return count

    def _param_indexes(self, entry) -> set:
        """Set of param positional indexes (for arg->param mapping)."""
        return set(range(len(self._desc_params(entry.signature or ""))))

    def _seed_params(self, regs, reg_params, params, incoming, mid) -> None:
        for reg_index, pidx in params:
            tags = incoming.get(pidx, set())
            if tags:
                key = f"v{reg_index}"
                via_tags = [t.via(mid) for t in tags]
                regs[key] = self._merge(list(via_tags), [])
                reg_params[key] = {pidx}

    def _field_read(self, fref: str, mid: str) -> List[Tag]:
        if not self.options["track_fields"]:
            return []
        base = list(self._field_taints.get(fref, set()))
        return [t.via(mid) for t in base]

    # ------------------------------------------------------------------
    # Merging / capping
    # ------------------------------------------------------------------
    def _merge(self, tags: List[Tag], existing: List[Tag]) -> List[Tag]:
        combined = list(existing)
        seen = {t for t in combined}
        cap = int(self.options["max_union"])
        for t in tags:
            if t in seen:
                continue
            if len(combined) >= cap:
                break
            combined.append(t)
            seen.add(t)
        return combined

    def _merge_tag_paths(self, base: Tag, ptag: Tag, callee_mid: str) -> Tag:
        sources = tuple(sorted(set(base.sources) | set(ptag.sources)))
        transforms = tuple(sorted(set(base.transforms) | set(ptag.transforms)))
        path = tuple(dict.fromkeys(list(base.path) + list(ptag.path) + [callee_mid]))
        return Tag(sources, transforms, path)

    def _const_string(self, ins) -> Optional[str]:
        try:
            value = getattr(ins, "get_string", lambda: None)()
            if value is not None and not isinstance(value, (list, tuple, bytes)):
                return str(value)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def _emit_findings(self, mids: List[str]) -> None:
        cap = int(self.options["max_flows_total"])
        emitted = set()
        for mid in mids:
            result = self._method_results.get(mid)
            if result is None:
                continue
            for sink_label, tag in result.sinks:
                if not tag.sources:
                    continue
                for cat, src_mid in tag.sources:
                    key = (cat, sink_label, tag.path, tag.transforms)
                    if key in emitted:
                        continue
                    if len(emitted) >= cap:
                        break
                    emitted.add(key)
                    finding = self._build_finding(cat, src_mid, sink_label, mid, tag)
                    if finding is not None:
                        self._findings_raw.append(finding)
                if len(emitted) >= cap:
                    break
            if len(emitted) >= cap:
                break
        self._stats["flows_total"] = len(self._findings_raw)
        self._emit_not_established(mids)

    def _build_finding(
        self, cat: str, src_mid: str, sink_label: str, sink_mid: str, tag: Tag
    ) -> Optional[DataFlowFinding]:
        status = self._status_for(tag, sink_mid, cat)
        path = list(tag.path)
        if not path:
            path = [src_mid]
        if sink_mid not in path:
            path = path + [sink_mid]
        path = path[ : int(self.options["max_steps"]) ]
        evidence = self._evidence_for(cat, src_mid, sink_label, sink_mid)
        flow_id = self._flow_id(cat, sink_label, path, tag.transforms)
        return DataFlowFinding(
            flow_id=flow_id,
            source=cat,
            source_method=src_mid,
            path=path,
            transformations=list(tag.transforms) if tag.transforms else [],
            sink=sink_label,
            sink_method=sink_mid,
            confidence=self._confidence(status),
            evidence_refs=evidence,
            status=status,
        )

    def _status_for(self, tag: Tag, sink_mid: str, cat: str) -> FlowStatus:
        # If the whole path is contained in the sink method and the source was
        # created there -> CONFIRMED (intra-procedural direct hop).
        src_mid = None
        for c, s in tag.sources:
            if c == cat:
                src_mid = s
                break
        if src_mid == sink_mid and set(tag.path) == {sink_mid}:
            return FlowStatus.CONFIRMED
        # Field hop or single cross-method hop -> PROBABLE.
        if len(set(tag.path)) <= 2 and set(tag.path) <= {src_mid, sink_mid}:
            return FlowStatus.PROBABLE
        return FlowStatus.POSSIBLE

    def _confidence(self, status: FlowStatus) -> str:
        return {
            FlowStatus.CONFIRMED: "high",
            FlowStatus.PROBABLE: "medium",
            FlowStatus.POSSIBLE: "low",
            FlowStatus.NOT_ESTABLISHED: "none",
        }[status]

    def _evidence_for(
        self, cat: str, src_mid: str, sink_label: str, sink_mid: str
    ) -> List[str]:
        return [
            f"source:{cat}@{src_mid}",
            f"sink:{sink_label}@{sink_mid}",
        ]

    def _flow_id(self, cat, sink_label, path, transforms) -> str:
        return "|".join(
            [
                cat,
                sink_label,
                "/".join(path),
                "/".join(sorted(transforms)),
            ]
        )

    # ------------------------------------------------------------------
    # NOT_ESTABLISHED (optional)
    # ------------------------------------------------------------------
    def _emit_not_established(self, mids: List[str]) -> None:
        if not self.options["include_not_established"]:
            return
        cap = int(self.options["not_established_cap"])
        # Attendance: which analyzed methods contain a source API / a sink API.
        source_by_mid: Dict[str, str] = {}
        sink_by_mid: Dict[str, str] = {}
        for mid in mids:
            cat = self._category_of(mid)
            if cat:
                source_by_mid[mid] = cat
            label = self._sink_label_of(mid)
            if label and label != "unknown":
                sink_by_mid[mid] = label
        connected: Set[Tuple[str, str]] = {
            (f.source_method, f.sink_method) for f in self._findings_raw
        }
        count = 0
        emitted: Set[Tuple[str, str, str]] = set()
        for src in sorted(source_by_mid, key=str.lower):
            for sink_mid in sorted(sink_by_mid, key=str.lower):
                if (src, sink_mid) in connected:
                    continue
                key = (source_by_mid[src], sink_by_mid[sink_mid], sink_mid)
                if key in emitted:
                    continue
                if count >= cap:
                    self._stats["not_established"] = count
                    return
                count += 1
                emitted.add(key)
                cat = source_by_mid[src]
                sink_label = sink_by_mid[sink_mid]
                self._not_established.append(
                    DataFlowFinding(
                        flow_id=f"not-established:{cat}:{src}->{sink_mid}",
                        source=cat,
                        source_method=src,
                        path=[src, sink_mid],
                        transformations=[],
                        sink=sink_label,
                        sink_method=sink_mid,
                        confidence="none",
                        evidence_refs=[
                            f"source:{cat}@{src}",
                            f"sink:{sink_label}@{sink_mid}",
                        ],
                        status=FlowStatus.NOT_ESTABLISHED,
                    )
                )
        self._stats["not_established"] = len(self._not_established)

    def _category_of(self, mid: str) -> Optional[str]:
        entry = self.index.get_method(mid)
        if entry is None:
            return None
        try:
            instructions = list(entry.method.get_code().get_bc().get_instructions())
        except Exception:
            instructions = []
        for ins in instructions:
            try:
                name, operands = instruction_info(ins)
            except Exception:
                continue
            if name in _INVOKE_NAMES:
                for ref in extract_refs(operands):
                    hits = match_sources(ref)
                    if hits:
                        return hits[0][0]
        return None

    def _sink_label_of(self, mid: str) -> str:
        entry = self.index.get_method(mid)
        if entry is None:
            return "unknown"
        try:
            instructions = list(entry.method.get_code().get_bc().get_instructions())
        except Exception:
            instructions = []
        for ins in instructions:
            try:
                name, operands = instruction_info(ins)
            except Exception:
                continue
            if name in _INVOKE_NAMES:
                for ref in extract_refs(operands):
                    hits = match_sinks(ref)
                    if hits:
                        return hits[0][0]
        return "unknown"

    def _summary(self, mids: List[str]) -> str:
        confirmed = sum(
            1 for f in self._findings_raw if f.status == FlowStatus.CONFIRMED
        )
        probable = sum(1 for f in self._findings_raw if f.status == FlowStatus.PROBABLE)
        possible = sum(1 for f in self._findings_raw if f.status == FlowStatus.POSSIBLE)
        return (
            f"data flow: {len(self._findings_raw)} findings "
            f"({confirmed} confirmed / {probable} probable / {possible} possible) "
            f"from {len(self._all_sources)} sources to {len(self._all_sinks)} sinks"
        )
