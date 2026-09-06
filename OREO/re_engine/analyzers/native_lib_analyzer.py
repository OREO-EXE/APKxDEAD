"""Native library triage analyzer.

Parses ``lib/<abi>/*.so`` entries with the shared ELF utilities. Pure-zip +
bytes parsing; no androguard required and no code execution.
"""

from __future__ import annotations

import re

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext, NativeLibrary
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)
from re_engine.utils.elfutil import elf_info

_ABI_DIRS = {
    "armeabi-v7a", "arm64-v8a", "armeabi",
    "x86", "x86_64", "mips", "mips64",
    "riscv64",
}
_SUSPICIOUS_NAME_TOKENS = (
    "hook", "inject", "payload", "frida", "dropper", "exploit",
    "xposed", "substrate",
)
_SYMBOL_TOKENS = (
    "system", "ptrace", "getenv", "execv", "dlopen", "dlsym",
    "mmap", "socket", "connect",
)


class NativeLibAnalyzer(BaseAnalyzer):
    """Inspect native libraries for ABI, architecture and exported symbols."""

    name = "native_lib"
    version = "0.1.0"
    description = "Native library parsing: ABI, architecture, exported symbols"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts

        lib_to_abi: dict = {}
        for entry in accessor.entries():
            parts = entry.name.split("/")
            if len(parts) >= 3 and entry.name.startswith("lib/"):
                abi = parts[1]
                if abi in _ABI_DIRS:
                    lib_to_abi.setdefault(parts[-1], abi)

        context.native_libraries = sorted(lib_to_abi)
        context.native_lib_details = []

        for lib_name, abi in sorted(lib_to_abi.items()):
            detail = NativeLibrary(name=lib_name, abi=abi)

            matched = [
                e for e in accessor.entries()
                if e.name.split("/")[-1] == lib_name and "/" in e.name
            ]
            if matched:
                detail.size = matched[0].size

            for entry in matched:
                blob = accessor.read(entry.name, cap=6_000_000)
                info = elf_info(blob) if blob else None
                if info is None:
                    continue
                detail.architecture = info.get("architecture")
                detail.exported_symbols = info.get("symbols", [])
                break

            for reason in _suspicious_name_reasons(lib_name):
                detail.suspicious_reasons.append(reason)
            for entry in matched:
                important = _import_symbols(
                    accessor.read(entry.name, cap=6_000_000)
                )
                if important:
                    detail.suspicious_reasons.append(
                        "imports: " + ", ".join(important[:8])
                    )
                break

            context.native_lib_details.append(detail)

            if detail.suspicious_reasons:
                self.emit(
                    context,
                    Finding(
                        category=FindingCategory.NATIVE_LIB,
                        title="Native library warrants review",
                        description=(
                            f"lib/{abi}/{lib_name} "
                            f"({detail.architecture or 'unknown'}, "
                            f"{detail.size} bytes)"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence_type=EvidenceType.OBSERVED,
                        source_file=f"lib/{abi}/{lib_name}",
                        metadata={
                            "reasons": detail.suspicious_reasons,
                            "abi": abi,
                            "architecture": detail.architecture,
                        },
                    ),
                )


def _suspicious_name_reasons(lib_name: str) -> list:
    lower = lib_name.lower()
    reasons = []
    for token in _SUSPICIOUS_NAME_TOKENS:
        if token in lower:
            reasons.append(f"name contains '{token}'")
    return reasons


def _import_symbols(blob) -> list:
    if not blob:
        return []
    info = elf_info(blob)
    if info is None:
        return []
    imports = info.get("imports", [])
    return [
        name for name in imports
        if any(token in name.lower() for token in _SYMBOL_TOKENS)
    ][:12]