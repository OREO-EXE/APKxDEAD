"""DEX/bytecode triage analyzer.

Loads every ``classes*.dex`` and records classes, packages, methods, fields,
method signatures, inheritance, interfaces and API references. API
classification reuses the repository's ``api_classifier`` and mirrors the
noise-filtering approach of ``ai.feature_extraction.dex_extractor``.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)

try:
    from ai.feature_extraction.api_classifier import classify_api
except Exception:  # pragma: no cover - repo layout unchanged
    classify_api = lambda api: "OTHER"  # type: ignore[assignment]

try:
    from ai.feature_extraction.dex_extractor import NOISE_APIS
except Exception:  # pragma: no cover
    NOISE_APIS = set()

_METHOD_CAP = 2000
_FIELD_CAP = 2000
_API_CAP = 500


class DexAnalyzer(BaseAnalyzer):
    """Bytecode-level triage over all DEX files."""

    name = "dex"
    version = "0.1.0"
    description = "DEX classes, methods, fields, inheritance, interfaces, API refs"

    def run(self, context: AnalysisContext) -> None:
        dex_files = context.artifacts.dex if context.artifacts else []

        classes: List[str] = []
        packages: set = set()
        method_signatures: List[str] = []
        fields: List[str] = []
        inheritance: Dict[str, str] = {}
        interfaces: Dict[str, List[str]] = {}
        api_counts: Counter = Counter()
        api_detail: Counter = Counter()
        method_count = 0
        field_count = 0

        for dex in dex_files:
            for cls in dex.get_classes():
                class_name = _safe(cls.get_name)
                classes.append(class_name)
                packages.add(_package_of(class_name))

                try:
                    super_name = cls.get_superclassname()
                    if super_name:
                        inheritance[class_name] = super_name
                    iface = [i for i in (cls.get_interfaces() or []) if i]
                    if iface:
                        interfaces[class_name] = iface
                except Exception:
                    pass

                for fld in cls.get_fields():
                    field_count += 1
                    if len(fields) >= _FIELD_CAP:
                        continue
                    try:
                        fields.append(
                            f"{fld.get_name()}:{fld.get_descriptor()}"
                        )
                    except Exception:
                        continue

                for method in cls.get_methods():
                    method_count += 1
                    if len(method_signatures) >= _METHOD_CAP:
                        continue
                    try:
                        access = method.get_access_flags_string() or ""
                        method_signatures.append(
                            f"{access} {method.get_name()}{method.get_descriptor()}"
                        )
                    except Exception:
                        method_signatures.append(
                            f"{method.get_name()}{method.get_descriptor()}"
                        )

        # API references (invoke instructions) -- mirror existing DexExtractor
        for dex in dex_files:
            for cls in dex.get_classes():
                for method in cls.get_methods():
                    code = _safe_code(method)
                    if code is None:
                        continue
                    try:
                        bc = code.get_bc()
                    except Exception:
                        continue
                    for instruction in bc.get_instructions():
                        if not instruction.get_name().startswith("invoke"):
                            continue
                        api = _safe_output(instruction)
                        if not api:
                            continue
                        if any(noise in api for noise in NOISE_APIS):
                            continue
                        api_counts[classify_api(api)] += 1
                        key = _api_key(api)
                        if key:
                            api_detail[key] += 1

        context.dex.dex_count = len(dex_files)
        context.dex.total_classes = len(classes)
        context.dex.total_methods = method_count
        context.dex.api_counts = dict(api_counts)
        context.classes = sorted(set(classes))
        context.packages = sorted(packages)
        context.method_signatures = _stable_truncate(
            method_signatures, _METHOD_CAP
        )
        context.fields = _stable_truncate(fields, _FIELD_CAP)
        context.inheritance = inheritance
        context.interfaces = interfaces
        context.api_references = [
            key for key, _ in api_detail.most_common(_API_CAP)
        ]

        self.emit(
            context,
            Finding(
                category=FindingCategory.DEX,
                title="DEX analysis complete",
                description=(
                    f"dex={len(dex_files)} classes={len(classes)} "
                    f"methods={method_count} "
                    f"api_categories={len(api_counts)}"
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.DEX,
                source_file="classes*.dex",
                supporting_string=_observed_string(
                    context, f"dex={len(dex_files)}"
                ),
            ),
        )


def _safe(getter):
    try:
        return getter()
    except Exception:
        return None


def _safe_output(instruction) -> str:
    try:
        value = instruction.get_output()
        if isinstance(value, (list, tuple)):
            return " ".join(str(v) for v in value)
        return str(value)
    except Exception:
        return ""


def _safe_code(method):
    try:
        return method.get_code()
    except Exception:
        return None


def _package_of(class_name: str) -> str:
    if not class_name:
        return ""
    stripped = class_name.lstrip("L").rstrip(";")
    parts = stripped.split("/")
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return parts[0] if parts else ""


def _api_key(api: str) -> str:
    if ";->" in api:
        return api.split(";->", 1)[1].split("(", 1)[0]
    return api.strip()


def _stable_truncate(items: List[str], cap: int) -> List[str]:
    seen = {}
    ordered = []
    for item in items:
        if item not in seen:
            seen[item] = True
            ordered.append(item)
        if len(ordered) >= cap:
            break
    return ordered


def _observed_string(context, value: str):
    return value if value in context.strings else None