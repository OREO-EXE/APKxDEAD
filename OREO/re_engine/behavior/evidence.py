"""Bounded, deterministic evidence index over an APK's DEX surface.

The behavior engine consumes the same low-level evidence as every other stage:
directly *observed* bytecode references. This module builds a queryable index
from one :class:`~re_engine.reconstruct.index.CodeIndex`:

    api_callers      normalized ``Lclass;->name`` key -> calling method mids
    string_callers   exact string literal -> referencing method mids
    class_usage      class reference -> referencing method mids
    per-method maps  the same sets bucketed by method (for same-method
                     co-occurrence queries used by chained-behavior detectors)

``EvidenceContext`` wraps the index plus the manifest context and the optional
call-graph / data-flow outputs so a detector can answer "who calls X with a
reference to Y in the same method" and "did collected data reach a sink".

All iteration is sorted; every cap is deterministic. No classifier imports.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from re_engine.reconstruct.index import CodeIndex, MethodEntry

_DEFAULT_MAX_METHODS = 6000
_DEFAULT_REF_CAP = 200


def api_key(ref: str) -> str:
    """Normalize a method reference to its ``Lclass;->name`` identity."""
    ref = str(ref).strip().strip('"')
    head, sep, tail = ref.partition("->")
    if not sep:
        return ref
    name = tail.split("(", 1)[0].rstrip(";")
    return f"{head}->{name}"


def class_desc_of(mid: str) -> Optional[str]:
    """The ``L...;`` descriptor for a method mid (best effort)."""
    class_part, sep, _rest = mid.partition("->")
    if not sep:
        return None
    if class_part.endswith(";"):
        return class_part
    return class_part + ";"


class EvidenceIndex:
    """One-pass, bounded method-evidence index."""

    def __init__(
        self,
        index: CodeIndex,
        max_methods: int = _DEFAULT_MAX_METHODS,
        ref_cap: int = _DEFAULT_REF_CAP,
    ) -> None:
        self.index = index
        self.max_methods = max_methods
        self.api_callers: Dict[str, Set[str]] = {}
        self.field_callers: Dict[str, Set[str]] = {}
        self.string_callers: Dict[str, Set[str]] = {}
        self.class_usage: Dict[str, Set[str]] = {}
        self.method_call_keys: Dict[str, Set[str]] = {}
        self.method_fields: Dict[str, Set[str]] = {}
        self.method_strings: Dict[str, Set[str]] = {}
        self.method_classes: Dict[str, Set[str]] = {}
        self.method_instruction_count: Dict[str, int] = {}
        self.native_mids: List[str] = []
        self.method_order: List[str] = []
        self.distinct_strings: List[str] = []
        self._build()

    def _build(self) -> None:
        self.index._ensure_index()
        seen_strings: Set[str] = set()
        method_count = 0
        for descriptor in sorted(
            self.index._class_by_desc.keys(), key=str.lower
        ):
            class_entry = self.index._class_by_desc[descriptor]
            for entry in class_entry.methods():
                mid = entry.mid
                if not mid:
                    continue
                if method_count >= self.max_methods:
                    return
                method_count += 1
                self.method_order.append(mid)

                access = (entry.access_flags or "").lower()
                if "native" in access:
                    self.native_mids.append(mid)

                refs = entry.references(ref_cap=_DEFAULT_REF_CAP)
                call_keys: Set[str] = set()
                for ref in refs.get("calls", []):
                    key = api_key(ref)
                    call_keys.add(key)
                    self.api_callers.setdefault(key, set()).add(mid)
                if call_keys:
                    self.method_call_keys[mid] = call_keys

                fields: Set[str] = set()
                for ref in refs.get("fields", []):
                    key = api_key(ref)
                    fields.add(key)
                    self.field_callers.setdefault(key, set()).add(mid)
                if fields:
                    self.method_fields[mid] = fields

                strings: Set[str] = set()
                for text in refs.get("strings", []):
                    strings.add(text)
                    if text not in seen_strings:
                        seen_strings.add(text)
                        self.distinct_strings.append(text)
                    self.string_callers.setdefault(text, set()).add(mid)
                if strings:
                    self.method_strings[mid] = strings

                classes: Set[str] = set()
                for cls in refs.get("classes", []):
                    classes.add(cls)
                    self.class_usage.setdefault(cls, set()).add(mid)
                if classes:
                    self.method_classes[mid] = classes

                try:
                    self.method_instruction_count[mid] = entry.instruction_count
                except Exception:
                    self.method_instruction_count[mid] = 0

        self.distinct_strings = sorted(self.distinct_strings)


class EvidenceContext:
    """Query surface over ``EvidenceIndex`` + manifest + graph/data-flow."""

    def __init__(
        self,
        context,
        evidence: EvidenceIndex,
        dataflow=None,
        graph=None,
    ) -> None:
        self.context = context
        self.evidence = evidence
        self.dataflow = dataflow
        self.graph = graph

    # ------------------------------------------------------------------
    # API / class / string membership
    # ------------------------------------------------------------------
    def api_mids(self, prefix: str) -> List[str]:
        """Methods calling an API whose ``Lclass;->name`` starts with prefix."""
        found: Set[str] = set()
        for key, mids in self.evidence.api_callers.items():
            if key.startswith(prefix):
                found.update(mids)
        return sorted(found, key=str.lower)

    def field_mids(self, prefix: str) -> List[str]:
        """Methods referencing a field whose ``Lclass;->name`` starts with prefix."""
        found: Set[str] = set()
        for key, mids in self.evidence.field_callers.items():
            if key.startswith(prefix):
                found.update(mids)
        return sorted(found, key=str.lower)

    def class_mids(self, prefix: str) -> List[str]:
        found: Set[str] = set()
        for cls, mids in self.evidence.class_usage.items():
            if cls.startswith(prefix):
                found.update(mids)
        return sorted(found, key=str.lower)

    def string_mids(self, text: str) -> List[str]:
        return sorted(self.evidence.string_callers.get(text, set()), key=str.lower)

    def substring_mids(self, substring: str) -> List[str]:
        found: Set[str] = set()
        for text in self.evidence.distinct_strings:
            if substring in text:
                found.update(self.evidence.string_callers.get(text, set()))
        return sorted(found, key=str.lower)

    def methods_with(
        self,
        call_prefix: Optional[str] = None,
        field_prefix: Optional[str] = None,
        string: Optional[str] = None,
        class_prefix: Optional[str] = None,
    ) -> Set[str]:
        """Methods directly evidencing all of the given observations."""
        if call_prefix:
            subset = set(self.api_mids(call_prefix))
        elif field_prefix:
            subset = set(self.field_mids(field_prefix))
        elif class_prefix:
            subset = set(self.class_mids(class_prefix))
        elif string:
            subset = set(self.string_mids(string))
        else:
            return set()
        if string:
            subset &= set(self.string_mids(string))
        if class_prefix:
            subset &= set(self.class_mids(class_prefix))
        if call_prefix:
            subset &= set(self.api_mids(call_prefix))
        if field_prefix:
            subset &= set(self.field_mids(field_prefix))
        return subset

    # ------------------------------------------------------------------
    # Same-method co-occurrence
    # ------------------------------------------------------------------
    def same_method(
        self,
        call_prefixes=(),
        field_prefixes=(),
        class_prefixes=(),
        strings=(),
    ) -> Set[str]:
        """Methods that individually contain evidence from every bucket."""
        if not (call_prefixes or field_prefixes or class_prefixes or strings):
            return set()
        candidates: Optional[Set[str]] = None
        if call_prefixes:
            any_call: Set[str] = set()
            for prefix in call_prefixes:
                any_call |= set(self.api_mids(prefix))
            candidates = any_call if candidates is None else (candidates & any_call)
        if field_prefixes:
            any_field: Set[str] = set()
            for prefix in field_prefixes:
                any_field |= set(self.field_mids(prefix))
            candidates = any_field if candidates is None else (candidates & any_field)
        if class_prefixes:
            any_class: Set[str] = set()
            for prefix in class_prefixes:
                any_class |= set(self.class_mids(prefix))
            candidates = any_class if candidates is None else (candidates & any_class)
        if strings:
            any_string: Set[str] = set()
            for text in strings:
                any_string |= set(self.string_mids(text))
            candidates = any_string if candidates is None else (candidates & any_string)
        return candidates or set()

    def cipher_init_literals(self, mid: str) -> Set[int]:
        """Const literals observed in a method that calls Cipher.init.

        Coarse but evidence-grounded: ENCRYPT_MODE==1 / DECRYPT_MODE==2 are
        usually inlined as a nearby ``const`` in the same method.
        """
        entry = self.evidence.index.get_method(mid)
        if entry is None:
            return set()
        from re_engine.dataflow.operands import instruction_info

        literals: Set[int] = set()
        try:
            instructions = list(entry.method.get_code().get_bc().get_instructions())
        except Exception:
            return literals
        for instruction in instructions:
            try:
                name, operands = instruction_info(instruction)
            except Exception:
                continue
            if not (name.startswith("const") and not name.startswith("const-string")):
                continue
            if len(operands) < 2:
                continue
            value = _parse_literal(operands[-1])
            if value is not None:
                literals.add(value)
        return literals

    # ------------------------------------------------------------------
    # Manifest-derived facts
    # ------------------------------------------------------------------
    @property
    def boot_receivers(self) -> List[str]:
        return sorted(getattr(self.context, "boot_receivers", []) or [], key=str.lower)

    @property
    def foreground_services(self) -> List[str]:
        return sorted(
            getattr(self.context, "foreground_services", []) or [], key=str.lower
        )

    @property
    def accessibility_components(self) -> List[str]:
        return sorted(
            getattr(self.context, "accessibility_components", []) or [], key=str.lower
        )

    @property
    def device_admin_components(self) -> List[str]:
        return sorted(
            getattr(self.context, "device_admin_components", []) or [], key=str.lower
        )

    @property
    def services(self) -> List[str]:
        components = getattr(self.context, "components", ()) or ()
        return sorted(
            (c.name for c in components if getattr(c, "kind", None) == "service"),
            key=str.lower,
        )

    @property
    def debuggable(self) -> bool:
        flags = getattr(self.context, "application_flags", None) or {}
        return bool(flags.get("debuggable") or flags.get("debuggableFlag"))

    @property
    def shell_commands(self) -> List[str]:
        return list(getattr(self.context, "shell_commands", None) or [])

    @property
    def urls(self) -> List[str]:
        return list(getattr(self.context, "urls", None) or [])

    @property
    def encoded_strings(self) -> List[str]:
        return list(getattr(self.context, "encoded_strings", None) or [])

    @property
    def native_libraries(self) -> List[str]:
        return list(getattr(self.context, "native_libraries", None) or [])

    def has_permission(self, permission: str) -> bool:
        if self.context is None:
            return False
        return bool(self.context.has_permission(permission))

    def present_permissions(self, permissions) -> List[str]:
        if self.context is None:
            return []
        return [p for p in permissions if self.context.has_permission(p)]

    # ------------------------------------------------------------------
    # Data-flow linkage
    # ------------------------------------------------------------------
    def linked_data_flows(self, source_labels) -> List[str]:
        if self.dataflow is None:
            return []
        labels = set(source_labels)
        out: Set[str] = set()
        for finding in self.dataflow.findings:
            if finding.source in labels:
                out.add(
                    f"{finding.source}->{finding.sink}"
                    f"@{finding.sink_method}"
                )
        return sorted(out)

    # ------------------------------------------------------------------
    # Shape helpers
    # ------------------------------------------------------------------
    def method_class(self, mid: str) -> Optional[str]:
        return class_desc_of(mid)

    def related_classes(self, mids) -> List[str]:
        out: Set[str] = set()
        for mid in mids:
            desc = class_desc_of(mid)
            if desc:
                out.add(desc)
        return sorted(out)

    def method_entry(self, mid: str) -> Optional[MethodEntry]:
        return self.evidence.index.get_method(mid)


def _parse_literal(token: str) -> Optional[int]:
    """Parse a DEX literal token (hex or decimal) to an int."""
    token = str(token).strip()
    if not token:
        return None
    try:
        if token.lower().startswith("0x"):
            return int(token, 16)
        if token.endswith(("T", "J", "f", "F")):
            token = token[:-1]
        if "." in token:
            return None
        return int(token, 10)
    except (ValueError, TypeError):
        return None