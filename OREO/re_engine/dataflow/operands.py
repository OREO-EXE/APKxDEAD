"""Deterministic instruction / operand normalization for the data-flow engine.

The data-flow engine consumes the same small duck-typed instruction surface as
the rest of the RE engine (``get_name()`` + ``get_output()``, optionally
``get_string()``). This module turns that output into a uniform, parseable form:

    ``instruction_info(ins) -> (name, operands)``

where ``operands`` is a flat list of operand tokens. It also classifies each
token as a register, a method/field reference, a string literal or a numeric
literal so the engine can reason about taint movement without depending on
androguard's exact output layout.

Two output layouts occur in the wild and both are handled:

    * androguard real output: ``"v1, v2, Lx;->foo(Ljava/lang/String;)V"``
      (registers first, reference last) and fields like
      ``"v1, v0, Lx;->f Ljava/lang/String;"``.
    * synthetic fixture output: ``"Lx;->foo()V, v0"`` (reference may appear
      anywhere among the tokens).

Tokenization therefore splits on commas (never inside a descriptor) and each
token is classified independently, so ordering never matters.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_REG_RE = re.compile(r"^[vp]\d+$")
_RANGE_RE = re.compile(r"^([vp]\d+)\s*\.\.\.\s*([vp]\d+)$")
_STRING_RE = re.compile(r'^"(?:[^"\\]|\\.)*"$')
_INT_RE = re.compile(r"^[+-]?\d+$")
_LONG_RE = re.compile(r"^[+-]?\d+L$")
_FLOAT_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?[fF]$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def instruction_info(instruction) -> Tuple[str, List[str]]:
    """Return ``(name, operands)`` for one instruction.

    ``name`` is the opcode string; ``operands`` is the flat token list parsed
    from the instruction text. Deterministic and order-robust.
    """
    name = _name_of(instruction)
    text = _text_of(instruction)
    return name, _tokenize(text)


def operand_kind(operand: str) -> str:
    """Classify a single operand token as register/ref/string/int/other."""
    operand = operand.strip()
    if not operand:
        return "other"
    if _RANGE_RE.match(operand) or _REG_RE.match(operand):
        return "reg"
    if _looks_like_ref(operand):
        return "ref"
    if _STRING_RE.match(operand):
        return "string"
    if _INT_RE.match(operand) or _LONG_RE.match(operand) or _FLOAT_RE.match(operand) or _HEX_RE.match(operand):
        return "int"
    return "other"


def _looks_like_ref(token: str) -> bool:
    """True if a token looks like a method/field reference (``L...;->...``).

    Deliberately loose: real descriptors may embed commas/spaces, so we only
    require the leading descriptor marker and the ``->`` separator.
    """
    token = token.strip()
    return token.startswith("L") and "->" in token and ";" in token


def is_register(operand: str) -> bool:
    return operand_kind(operand) == "reg"


def registers_in(operands: List[str]) -> List[str]:
    """Registers (or range endpoints) present across the operands, in order."""
    result: List[str] = []
    for op in operands:
        if _REG_RE.match(op):
            result.append(op)
        else:
            m = _RANGE_RE.match(op)
            if m:
                result.append(m.group(1))
                result.append(m.group(2))
    return result


def split_ref(operand: str) -> Tuple[str, str, str]:
    """Split a reference token into ``(class_desc, method_name, signature)``.

    Accepts both a bare call ref ``Lx;->foo()V`` and a field ref
    ``Lx;->f Ljava/lang/String;``. The signature is returned as ``None`` (the
    empty string) when absent. Always returns three strings.
    """
    norm = operand.strip()
    head, sep, tail = norm.partition("->")
    if not sep:
        return norm, "", ""
    name_part = tail.strip()
    # Field refs have a trailing type: "name Ljava/lang/String;"
    name = name_part
    signature = ""
    space = name_part.find(" ")
    if space != -1 and "(" not in name_part[:space]:
        head_field, rest = name_part[:space], name_part[space + 1 :].strip()
        return head, head_field, rest or ""
    paren = name_part.find("(")
    if paren != -1:
        name = name_part[:paren]
        signature = name_part[paren:]
    else:
        name = name_part.rstrip(";")
    return head, name, signature


def extract_refs(operands: List[str]) -> List[str]:
    """All reference tokens among the operands (in order)."""
    return [op for op in operands if operand_kind(op) == "ref"]

def _name_of(instruction) -> str:
    try:
        value = str(instruction.get_name() or "")
        return value
    except Exception:
        return ""


def _text_of(instruction) -> str:
    # Prefer get_output(); the ``str()`` form may drop registers (const-string).
    try:
        value = getattr(instruction, "get_output", lambda: None)()
    except Exception:
        value = None
    if value is not None:
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value if str(v))
        return str(value)
    try:
        return str(instruction)
    except Exception:
        return ""


def _tokenize(text: str) -> List[str]:
    """Split instruction text into top-level operand tokens.

    Commas inside a method descriptor (``(LA;B;I)V``) or a field ref are NOT
    separators. Strategy:

        * split on top-level commas;
        * a token that carries an open parenthesis is the start of a method
          reference -- subsequent chunks are swallowed until the reference's
          parentheses balance and a trailing return type is absorbed.
    """
    text = str(text).strip()
    if not text:
        return []
    chunks = [tok.strip() for tok in text.split(",")]
    tokens: List[str] = []
    buffer = ""
    depth = 0
    for chunk in chunks:
        if not chunk:
            continue
        if buffer:
            buffer += ", " + chunk
        else:
            buffer = chunk
        depth += chunk.count("(") - chunk.count(")")
        # Absorb a trailing return-type fragment after a balanced signature.
        if depth < 0:
            depth = 0
        if depth == 0:
            tokens.append(buffer)
            buffer = ""
    if buffer:
        tokens.append(buffer)
    return tokens
