"""Deterministic Smali rendering and per-method reference extraction.

The rendered Smali is rebuilt directly from the instruction stream exposed by
the DEX parser (androguard ``Instruction`` objects), which makes it
authoritative low-level evidence - not a decompiler guess. Reference
extraction (called methods, strings, class and field references) is performed
in the same single pass over the instructions.

The module only relies on a small duck-typed instruction surface:
    ``get_name()``, ``get_output()`` (or ``str()``), optionally ``get_string()``
for string constants. This keeps it testable without androguard.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

_CALL_REF = re.compile(
    r"L[^;\s]+;->[^;\s()]+\([^)]*\)[^,\s]*|L[^;\s]+;->[^;\s()]+"
)
_CLASS_REF = re.compile(r"L[^;\s]+;")
_STRING_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')

_CLASS_OPS = {
    "new-instance",
    "const-class",
    "check-cast",
    "instance-of",
    "new-array",
}
_FIELD_OPS_PREFIXES = ("sget", "sput", "iget", "iput")


def instruction_text(instruction) -> str:
    """Best-effort human text for one instruction (opcode included)."""
    try:
        value = str(instruction)
        if value and not value.startswith("<"):
            return value.rstrip()
    except Exception:
        pass
    try:
        name = str(getattr(instruction, "get_name", lambda: None)() or "")
        output = getattr(instruction, "get_output", lambda: None)()
        if isinstance(output, (list, tuple)):
            pieces = [str(part) for part in output if str(part)]
        elif output is not None:
            pieces = [str(output)]
        else:
            pieces = []
        joined = " ".join(p for p in pieces if p)
        return f"{name} {joined}".rstrip()
    except Exception:
        return ""


def _safe_instr_text(instruction) -> str:
    return instruction_text(instruction).rstrip()


def _instruction_name(instruction) -> str:
    try:
        return str(instruction.get_name() or "")
    except Exception:
        return ""


def _string_of(instruction, text: str) -> Optional[str]:
    try:
        value = getattr(instruction, "get_string", lambda: None)()
        if value is not None and not isinstance(value, (list, tuple, bytes)):
            return str(value)
    except Exception:
        pass
    match = _STRING_LITERAL.search(text)
    if match:
        return match.group(1)
    return None


def render_method_smali(method) -> str:
    """Render one method as deterministic Smali text."""
    access = _safe_str(getattr(method, "get_access_flags_string", None))
    name = _safe_str(getattr(method, "get_name", None))
    desc = _safe_str(getattr(method, "get_descriptor", None)) or ""
    if access:
        header = f".method {access} {name}{desc}"
    else:
        header = f".method {name}{desc}"

    lines: List[str] = [header]
    registers = _registers_of(method)
    if registers is not None:
        lines.append(f"    .registers {registers}")

    for instruction in _instructions_of(method):
        text = _safe_instr_text(instruction)
        if text:
            lines.append(f"    {text}")

    lines.append(".end method")
    return "\n".join(lines)


def render_class_smali(cls) -> str:
    """Render one class as deterministic Smali-like text.

    This is a readable reconstruction (header, superclass, interfaces, fields
    and each method body) - not a verbatim baksmali dump.
    """
    name = _safe_str(getattr(cls, "get_name", None)) or ""
    superclass = _safe_str(getattr(cls, "get_superclassname", None))
    interfaces = _safe_list(getattr(cls, "get_interfaces", None))

    lines: List[str] = []
    if name:
        lines.append(f".class {name}")
    if superclass:
        lines.append(f".super {superclass}")
    for iface in interfaces:
        if iface:
            lines.append(f".implements {iface}")

    for field in _safe_iter(getattr(cls, "get_fields", None)):
        fname = _safe_str(getattr(field, "get_name", None))
        fdesc = _safe_str(getattr(field, "get_descriptor", None)) or ""
        if fname:
            lines.append(f".field {fname}:{fdesc}")

    for method in _safe_iter(getattr(cls, "get_methods", None)):
        rendered = render_method_smali(method)
        lines.append(_indent(rendered))

    return "\n".join(lines)


def extract_references(
    method, ref_cap: int = 200
) -> Dict[str, List[str]]:
    """Collect references observed inside a method's own instructions.

    Returns a dict with sorted lists under the keys ``calls``, ``strings``,
    ``classes`` and ``fields``. Every entry was directly observed in the
    bytecode of this method - nothing is inferred.
    """
    calls: Set[str] = set()
    strings: Set[str] = set()
    classes: Set[str] = set()
    fields: Set[str] = set()

    for instruction in _instructions_of(method):
        name = _instruction_name(instruction)
        text = _safe_instr_text(instruction)
        if not text:
            continue

        if name.startswith("invoke"):
            calls.update(_CALL_REF.findall(text))
        elif name.startswith("const-string"):
            value = _string_of(instruction, text)
            if value is not None and value:
                strings.add(value)
        elif name in _CLASS_OPS:
            classes.update(_CLASS_REF.findall(text))
        elif name.startswith(_FIELD_OPS_PREFIXES):
            fields.update(_CALL_REF.findall(text))

    return {
        "calls": _sorted_capped(calls, ref_cap),
        "strings": _sorted_capped(strings, ref_cap),
        "classes": _sorted_capped(classes, ref_cap),
        "fields": _sorted_capped(fields, ref_cap),
    }


def extract_call_sites(method) -> List[tuple]:
    """Return the sorted unique ``(opcode, target)`` call sites of a method.

    Unlike :func:`extract_references` (which keeps only the target), this
    preserves the invoke kind (``invoke-direct``, ``invoke-virtual``,
    ``invoke-interface``, ...) so dispatch resolution can stay honest about
    whether a call is statically resolvable. Deterministic: sorted by
    ``(opcode, target)``.
    """
    sites: Set[tuple] = set()
    for instruction in _instructions_of(method):
        name = _instruction_name(instruction)
        if not name.startswith("invoke"):
            continue
        text = _safe_instr_text(instruction)
        if not text:
            continue
        for target in _CALL_REF.findall(text):
            sites.add((name, target))
    return sorted(sites)


def _instructions_of(method):
    try:
        code = method.get_code()
        if code is None:
            return []
        return code.get_bc().get_instructions()
    except Exception:
        return []


def _registers_of(method) -> Optional[int]:
    try:
        code = method.get_code()
        if code is None:
            return None
        return code.get_registers_size()
    except Exception:
        return None


def _safe_str(getter) -> Optional[str]:
    try:
        value = getter()
        return str(value) if value else None
    except Exception:
        return None


def _safe_list(getter) -> List[str]:
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


def _indent(text: str) -> str:
    return "\n".join(f"    {line}" for line in text.splitlines())


def _sorted_capped(values: Set[str], cap: int) -> List[str]:
    ordered = sorted(values)
    if len(ordered) <= cap:
        return ordered
    return ordered[:cap]