"""APK structural triage analyzer.

Operates purely on the ZIP container (deterministic, no androguard required):
manifest, dex files, resources, assets, ``lib/``, ``META-INF/``, suspicious
files and embedded archives.
"""

from __future__ import annotations

import zipfile
from typing import Dict, List, Optional

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)

ARCHIVE_MAGICS = {
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip",
    b"\x1f\x8b": "gzip",
    b"7z\xbc\xaf\x27": "7zip",
    b"Rar!\x1a\x07": "rar",
    b"\xfd7zXZ": "xz",
    b"dex\n": "dex",
}

ARCHIVE_EXTS = (".apk", ".zip", ".jar", ".dex", ".gz", ".7z", ".rar", ".xz")

SUSPICIOUS_PATH_TOKENS = (
    "payload",
    "exploit",
    "inject",
    "frida",
    "keylog",
    "botnet",
    "backdoor",
    "trojan",
    "steal",
    "cryptominer",
    "minergrate",
    "hook",
    "superuser",
)
SUSPICIOUS_NAMES = ("su", "rootshell", "cmd.apk", "shizuku")


class StructureAnalyzer(BaseAnalyzer):
    """Container-level structure triage."""

    name = "structure"
    version = "0.1.0"
    description = "APK container structure: entries, resources, embedded payloads"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts
        entries = accessor.entries()

        dex_files = [e.name for e in entries if _is_root_dex(e.name)]
        res_entries = [e.name for e in entries if e.name.startswith("res/")]
        asset_entries = [e.name for e in entries if e.name.startswith("assets/")]
        lib_entries = [e.name for e in entries if e.name.startswith("lib/")]
        meta_entries = [e.name for e in entries if e.name.startswith("META-INF/")]
        root_files = [
            e.name for e in entries
            if "/" not in e.name.rstrip("/") and not e.name.endswith("/")
        ]

        manifest_entry = next(
            (e for e in entries if e.name == "AndroidManifest.xml"), None
        )

        suspicious_files: List[str] = []
        embedded_archives: List[str] = []

        for entry in entries:
            name = entry.name
            if name.endswith("/"):
                continue
            reason = _suspicious_reason(name)
            if reason:
                suspicious_files.append(f"{name} ({reason})")
            if _is_embedded_archive(accessor, entry):
                embedded_archives.append(name)

        context.structure = {
            "manifest": {
                "present": manifest_entry is not None,
                "name": "AndroidManifest.xml",
                "size": manifest_entry.size if manifest_entry else 0,
                "compression": (
                    manifest_entry.compression if manifest_entry else None
                ),
            },
            "dex_files": dex_files,
            "resources": {
                "resource_dir_entries": len(res_entries),
                "resources_arsc_present": accessor.has("resources.arsc"),
                "resources_arsc_size": _size_of(accessor, "resources.arsc"),
            },
            "assets": {
                "entry_count": len(asset_entries),
                "names": asset_entries[:100],
            },
            "lib": {"entry_count": len(lib_entries)},
            "meta_inf": {
                "entry_count": len(meta_entries),
                "signature_files": [
                    n for n in meta_entries
                    if n.lower().endswith((".rsa", ".dsa", ".ec", ".sf"))
                ],
                "manifest_mf": accessor.has("META-INF/MANIFEST.MF"),
            },
            "root_files": root_files,
            "total_entries": len(entries),
        }
        context.suspicious_files = suspicious_files[:100]
        context.embedded_archives = embedded_archives[:100]

        if manifest_entry is None:
            self.emit(
                context,
                Finding(
                    category=FindingCategory.MANIFEST,
                    title="Missing AndroidManifest.xml",
                    description="No AndroidManifest.xml entry in the APK.",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.OBSERVED,
                ),
            )

        for label in suspicious_files[:50]:
            detail = label.split(" (", 1)[1][:-1] if " (" in label else ""
            self.emit(
                context,
                Finding(
                    category=FindingCategory.INFORMATION,
                    title="File warrants review",
                    description=f"APK entry: {label}",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    evidence_type=EvidenceType.OBSERVED,
                    source_file=label.split(" (", 1)[0],
                    metadata={"reason": detail},
                ),
            )

        for name in embedded_archives[:50]:
            kind = _archive_kind(accessor, name)
            base = name.split("/")[-1]
            self.emit(
                context,
                Finding(
                    category=FindingCategory.INFORMATION,
                    title="Embedded archive detected",
                    description=(
                        f"Embedded payload container ({kind}): {name}"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.OBSERVED,
                    source_file=name,
                    supporting_string=_observed_string(context, base),
                ),
            )

        self.emit(
            context,
            Finding(
                category=FindingCategory.INFORMATION,
                title="APK structure analyzed",
                description=(
                    f"entries={len(entries)} dex={len(dex_files)} "
                    f"resources={len(res_entries)} assets={len(asset_entries)} "
                    f"native_lib_entries={len(lib_entries)} "
                    f"suspicious={len(suspicious_files)} "
                    f"embedded={len(embedded_archives)}"
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.OBSERVED,
                source_file=context.apk_path,
            ),
        )


def _is_root_dex(name: str) -> bool:
    base = name.split("/")[-1]
    return name == base and base.startswith("classes") and base.endswith(".dex")


def _size_of(accessor, name: str) -> int:
    for entry in accessor.entries():
        if entry.name == name:
            return entry.size
    return 0


def _suspicious_reason(name: str) -> Optional[str]:
    """Deterministic heuristic label for an APK entry; None if benign."""
    lower = name.lower()
    base = lower.split("/")[-1]
    if base.startswith("."):
        return "hidden file"
    for token in SUSPICIOUS_PATH_TOKENS:
        if token in lower:
            return f"name contains '{token}'"
    if base in SUSPICIOUS_NAMES:
        return "unusual standalone binary"
    if "/" not in name.rstrip("/") and lower.endswith(".dex") \
            and not lower.startswith("classes"):
        return "non-standard dex in root"
    if name.lower().startswith("classes") and base.count(".") > 1:
        return "odd classes file name"
    return None


def _is_embedded_archive(accessor, entry) -> bool:
    if entry.name.endswith("/"):
        return False
    base = entry.name.split("/")[-1].lower()
    if base.endswith(".dex"):
        # first-class dex files (classes*.dex) are reported as structure,
        # not as embedded payloads
        if entry.name.startswith("classes"):
            return False
        return True
    if base in (".apk", ".zip", ".jar", ".dex"):
        return True
    if base.endswith(ARCHIVE_EXTS):
        return True
    head = accessor.read_head(entry.name, size=8)
    return head in ARCHIVE_MAGICS


def _archive_kind(accessor, name: str) -> str:
    base = name.split("/")[-1].lower()
    if base.endswith(".apk"):
        return "apk"
    if base.endswith(".zip"):
        return "zip"
    if base.endswith(".jar"):
        return "jar"
    if base.endswith(".dex"):
        return "dex"
    if base.endswith((".gz", ".gzip")):
        return "gzip"
    head = accessor.read_head(name, size=8)
    return ARCHIVE_MAGICS.get(head, "archive")


def _observed_string(context: AnalysisContext, value: str) -> Optional[str]:
    return value if value in context.strings else None