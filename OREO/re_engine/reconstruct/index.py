"""Code index: deterministic lookups over one or more DEX files.

The :class:`CodeIndex` wraps the DEX objects exposed by the accessor (real
androguard ``DEX`` objects or duck-typed fakes) and provides:
    - class lookups by descriptor (``Lcom/x/Main;``) or dotted name
    - method lookups by class + name (+ optional signature) or by method id
    - package-level lookups
    - per-method reference extraction (calls, strings, classes, fields)
    - a bounded caller index (methods that call a given method)

Nothing here executes APK code or touches the network. Real DEX parsing is
deferred to the accessor; every accessor call is wrapped defensively so the
index degrades gracefully on malformed input.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from re_engine.reconstruct.smali import extract_references, render_method_smali

_METHOD_MAP_CAP = 20000
_CALLER_SCAN_CAP = 15000


def normalize_class_name(name: str) -> Optional[str]:
    """Normalize a class name to dotted form (``com.x.Main``).

    Accepts descriptors (``Lcom/x/Main;``), bare slashed names
    (``com/x/Main``) and dotted names, and clears relative manifest
    components (``.Main``), returning None for those.
    """
    if not name:
        return None
    value = str(name).strip()
    if value.startswith("."):
        return None
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1].replace("/", ".")
    if value.endswith(";"):
        return value[:-1].replace("/", ".")
    if "/" in value:
        return value.replace("/", ".")
    return value


def descriptor_to_dotted(descriptor: str) -> str:
    value = descriptor if descriptor.endswith(";") else descriptor
    return value[1:-1].replace("/", ".")


class ClassEntry:
    """A thin, lazy view over one class in the index."""

    def __init__(self, index: "CodeIndex", dex_idx: int, cls) -> None:
        self._index = index
        self._dex_idx = dex_idx
        self.cls = cls

    @property
    def descriptor(self) -> str:
        return _safe_str(getattr(self.cls, "get_name", None)) or ""

    @property
    def dotted(self) -> str:
        desc = self.descriptor
        return descriptor_to_dotted(desc) if desc else ""

    @property
    def dex_label(self) -> str:
        return self._index.dex_label(self._dex_idx)

    def methods(self) -> List["MethodEntry"]:
        entries: List[MethodEntry] = []
        for method in _safe_iter(getattr(self.cls, "get_methods", None)):
            entry = MethodEntry(self._index, self, method)
            if entry.mid:
                entries.append(entry)
        return entries

    def superclass(self) -> Optional[str]:
        return _safe_str(getattr(self.cls, "get_superclassname", None))

    def interfaces(self) -> List[str]:
        return _safe_str_list(getattr(self.cls, "get_interfaces", None))

    def fields(self) -> List[str]:
        result = []
        for field in _safe_iter(getattr(self.cls, "get_fields", None)):
            name = _safe_str(getattr(field, "get_name", None))
            desc = _safe_str(getattr(field, "get_descriptor", None)) or ""
            if name:
                result.append(f"{name}:{desc}")
        return result


class MethodEntry:
    """A thin, lazy view over one method in the index."""

    def __init__(
        self, index: "CodeIndex", class_entry: ClassEntry, method
    ) -> None:
        self._index = index
        self.class_entry = class_entry
        self.method = method
        self.mid = self._build_mid()
        self._references_cache: Optional[Dict[str, List[str]]] = None

    def _build_mid(self) -> str:
        class_desc = self.class_entry.descriptor
        name = _safe_str(getattr(self.method, "get_name", None))
        signature = _safe_str(getattr(self.method, "get_descriptor", None))
        if not class_desc or not name or signature is None:
            return ""
        return f"{class_desc}->{name}{signature}"

    @property
    def name(self) -> str:
        return _safe_str(getattr(self.method, "get_name", None)) or ""

    @property
    def signature(self) -> str:
        return _safe_str(getattr(self.method, "get_descriptor", None)) or ""

    @property
    def class_descriptor(self) -> str:
        return self.class_entry.descriptor

    @property
    def class_dotted(self) -> str:
        return self.class_entry.dotted

    @property
    def access_flags(self) -> str:
        return _safe_str(getattr(self.method, "get_access_flags_string", None)) or ""

    @property
    def instruction_count(self) -> int:
        return len(list(self._instructions()))

    def instructions(self):
        return list(self._instructions())

    def references(self, ref_cap: int = 200) -> Dict[str, List[str]]:
        if self._references_cache is None:
            self._references_cache = extract_references(self.method, ref_cap=ref_cap)
        return self._references_cache

    def smali(self) -> str:
        return render_method_smali(self.method)

    def _instructions(self):
        try:
            code = getattr(self.method, "get_code", lambda: None)()
            if code is None:
                return []
            return code.get_bc().get_instructions()
        except Exception:
            return []


class CodeIndex:
    """Bounded, lazy index over a list of DEX objects."""

    def __init__(
        self,
        dex_files=None,
        dex_labels: Optional[List[str]] = None,
        caller_scan_cap: int = _CALLER_SCAN_CAP,
    ) -> None:
        self._dex_files = list(dex_files or [])
        length = len(self._dex_files)
        self._dex_labels = dex_labels or [f"dex[{i}]" for i in range(length)]
        if len(self._dex_labels) != length:
            self._dex_labels = [f"dex[{i}]" for i in range(length)]
        self._caller_scan_cap = caller_scan_cap

        self._class_by_desc: Optional[Dict[str, ClassEntry]] = None
        self._desc_by_dotted: Dict[str, str] = {}
        self._callers: Optional[Dict[str, Set[str]]] = None
        self._method_cache: Dict[str, MethodEntry] = {}
        self.stats: Dict[str, int] = {
            "dex_count": length,
            "classes_indexed": 0,
            "methods_indexed": 0,
            "callers_indexed": 0,
            "caller_scan_truncated": 0,
        }

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------
    def _ensure_index(self) -> None:
        if self._class_by_desc is not None:
            return
        class_map: Dict[str, ClassEntry] = {}
        method_count = 0
        for dex_idx, dex in enumerate(self._dex_files):
            for cls in self._classes_of(dex):
                entry = ClassEntry(self, dex_idx, cls)
                descriptor = entry.descriptor
                if not descriptor:
                    continue
                if descriptor not in class_map:
                    class_map[descriptor] = entry
                    dotted = entry.dotted
                    if dotted and dotted not in self._desc_by_dotted:
                        self._desc_by_dotted[dotted] = descriptor
                method_count += cls_methods_of(cls)
        self._class_by_desc = class_map
        self.stats["classes_indexed"] = len(class_map)
        self.stats["methods_indexed"] = method_count

    def _classes_of(self, dex):
        try:
            return list(dex.get_classes())
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Class lookups
    # ------------------------------------------------------------------
    def classes_count(self) -> int:
        self._ensure_index()
        return self.stats["classes_indexed"]

    def methods_count(self) -> int:
        self._ensure_index()
        return self.stats["methods_indexed"]

    def dex_label(self, dex_idx: int) -> str:
        if 0 <= dex_idx < len(self._dex_labels):
            return self._dex_labels[dex_idx]
        return f"dex[{dex_idx}]"

    def find_class(self, name: str) -> Optional[ClassEntry]:
        self._ensure_index()
        if not name:
            return None
        descriptor = self._resolve_descriptor(name)
        return self._class_by_desc.get(descriptor) if descriptor else None

    def class_exists(self, name: str) -> bool:
        return self.find_class(name) is not None

    def get_class(self, name: str) -> Optional[ClassEntry]:
        return self.find_class(name)

    def classes_in_package(self, package: str) -> List[ClassEntry]:
        self._ensure_index()
        prefix = package.strip() + "."
        matched = [
            entry
            for entry in self._class_by_desc.values()
            if entry.dotted == package or entry.dotted.startswith(prefix)
        ]
        return sorted(matched, key=lambda entry: entry.dotted)

    def packages(self, prefix_only: bool = True) -> List[str]:
        self._ensure_index()
        packages = set()
        for entry in self._class_by_desc.values():
            parts = entry.dotted.split(".")
            if len(parts) >= 2:
                packages.add(".".join(parts[:2]))
            elif parts and parts[0]:
                packages.add(parts[0])
        return sorted(packages)

    def descriptors_matching(self, dotted_prefix: str) -> List[str]:
        self._ensure_index()
        prefix = dotted_prefix.strip()
        matched = [
            entry.descriptor
            for entry in self._class_by_desc.values()
            if entry.dotted.startswith(prefix)
        ]
        return sorted(matched)

    # ------------------------------------------------------------------
    # Method lookups
    # ------------------------------------------------------------------
    def find_method(
        self,
        class_name: str,
        method_name: str,
        signature: Optional[str] = None,
    ) -> Optional[MethodEntry]:
        class_entry = self.find_class(class_name)
        if class_entry is None:
            return None
        for candidate in class_entry.methods():
            if candidate.name != method_name:
                continue
            if signature is not None and candidate.signature != signature:
                continue
            return candidate
        return None

    def methods_named(
        self, class_name: str, method_name: str
    ) -> List[MethodEntry]:
        class_entry = self.find_class(class_name)
        if class_entry is None:
            return []
        return [
            candidate
            for candidate in class_entry.methods()
            if candidate.name == method_name
        ]

    def get_method(self, mid: str) -> Optional[MethodEntry]:
        if not mid:
            return None
        self._ensure_index()
        cached = self._method_cache.get(mid)
        if cached is not None:
            return cached
        class_desc, sep, tail = mid.partition("->")
        if not sep:
            return None
        name, sep2, signature = tail.partition("(")
        if not sep2:
            return None
        signature = "(" + signature
        entry = self.find_method(class_desc, name, signature)
        if entry is not None and len(self._method_cache) < _METHOD_MAP_CAP:
            self._method_cache[mid] = entry
        return entry

    # ------------------------------------------------------------------
    # Per-method references / smali
    # ------------------------------------------------------------------
    def method_calls(self, mid: str) -> List[str]:
        entry = self.get_method(mid)
        if entry is None:
            return []
        return entry.references().get("calls", [])

    def method_references(self, mid: str, ref_cap: int = 200) -> Dict[str, List[str]]:
        entry = self.get_method(mid)
        if entry is None:
            return {"calls": [], "strings": [], "classes": [], "fields": []}
        return entry.references(ref_cap=ref_cap)

    def method_smali(self, mid: str) -> Optional[str]:
        entry = self.get_method(mid)
        if entry is None:
            return None
        return entry.smali()

    # ------------------------------------------------------------------
    # Caller index (bounded full scan)
    # ------------------------------------------------------------------
    def _ensure_callers(self, cap: Optional[int] = None) -> None:
        if self._callers is not None:
            return
        scan_cap = cap if cap is not None else self._caller_scan_cap
        self._callers = {}
        scanned = 0
        truncated = 0
        self._ensure_index()
        for descriptor in sorted(
            self._class_by_desc.keys(), key=lambda d: d.lower()
        ):
            class_entry = self._class_by_desc[descriptor]
            for method_entry in class_entry.methods():
                if scanned >= scan_cap:
                    truncated = 1
                    break
                scanned += 1
                target = method_entry.mid
                if not target:
                    continue
                for call in method_entry.references().get("calls", []):
                    self._callers.setdefault(call, set()).add(target)
            if truncated:
                break
        self.stats["callers_indexed"] = scanned
        self.stats["caller_scan_truncated"] = truncated

    def callers_of(
        self, mid: str, cap: Optional[int] = None
    ) -> List[str]:
        self._ensure_callers(cap=cap)
        return sorted(self._callers.get(mid, set()))

    def callees_of(self, mid: str) -> List[str]:
        return sorted(set(self.method_calls(mid)))

    def caller_analysis(
        self, mid: str, cap: Optional[int] = None
    ) -> Dict[str, List[str]]:
        return {
            "target": mid,
            "callers": self.callers_of(mid, cap=cap),
            "callees": self.callees_of(mid),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _resolve_descriptor(self, name: str) -> Optional[str]:
        dotted = normalize_class_name(name)
        if not dotted:
            return None
        if dotted in self._desc_by_dotted:
            return self._desc_by_dotted[dotted]
        slashed = dotted.replace(".", "/")
        descriptor = f"L{slashed};"
        if descriptor in self._class_by_desc:
            return descriptor
        return None


def _safe_str(getter) -> Optional[str]:
    try:
        value = getter()
        return str(value) if value else None
    except Exception:
        return None


def _safe_str_list(getter) -> List[str]:
    try:
        values = getter()
        if not values:
            return []
        return [str(v) for v in values if str(v)]
    except Exception:
        return []


def _safe_iter(getter):
    try:
        return list(getter())
    except Exception:
        return []


def cls_methods_of(cls) -> int:
    try:
        return len(list(cls.get_methods()))
    except Exception:
        return 0