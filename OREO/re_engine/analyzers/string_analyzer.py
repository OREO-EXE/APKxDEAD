"""String triage analyzer.

Raw-byte scanning over non-archive entries and decompressed scanning over
DEX payloads. Regexes and keywords are shared in ``strings_patterns``.
"""

from __future__ import annotations

import re

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.analyzers.strings_patterns import (
    BASE64_LIKE_RE,
    DOMAIN_RE,
    EMAIL_RE,
    FILE_PATH_RE,
    HEX_LIKE_RE,
    IPV4_RE,
    IPV6_RE,
    SHELL_CMD_RE,
    SUSPICIOUS_KEYWORDS,
    URL_RE,
)
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)

_MATCH_CAP = 4000
_ENTRY_CAP = 120
_CAPTURE_CAP = 400

# (regex, context_field, finding_category, severity)
_PATTERNS = [
    (URL_RE, "urls", FindingCategory.NETWORK, Severity.MEDIUM),
    (DOMAIN_RE, "domains", FindingCategory.NETWORK, Severity.LOW),
    (IPV4_RE, "ipv4", FindingCategory.NETWORK, Severity.MEDIUM),
    (IPV6_RE, "ipv6", FindingCategory.NETWORK, Severity.LOW),
    (EMAIL_RE, "emails", FindingCategory.INFORMATION, Severity.LOW),
    (FILE_PATH_RE, "file_paths", FindingCategory.INFORMATION, Severity.LOW),
    (SHELL_CMD_RE, "shell_commands", FindingCategory.INFORMATION, Severity.MEDIUM),
]


class StringAnalyzer(BaseAnalyzer):
    """Extract URLs, IPs, emails, paths, shell commands and encoded strings."""

    name = "strings"
    version = "0.1.0"
    description = "Byte-level string extraction across APK entries and DEX"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts
        seen_evidence = set()

        scanned = 0
        for entry in accessor.entries():
            if entry.name.endswith("/") or entry.name.split("/")[-1].startswith("."):
                continue
            raw = accessor.read(entry.name, cap=8_000_000)
            if raw:
                self._scan(context, raw, source=entry.name, seen=seen_evidence)
                scanned += 1
            if scanned >= _ENTRY_CAP:
                break

        for index, (dex_name, dex_bytes) in enumerate(accessor.dex_bytes()):
            self._scan(context, dex_bytes, source=dex_name, seen=seen_evidence)
            if index >= 20:
                break

        if len(context.strings) > _MATCH_CAP:
            context.strings = list(dict.fromkeys(context.strings))[:_MATCH_CAP]

        self.emit(
            context,
            Finding(
                category=FindingCategory.STRING,
                title="Strings extracted",
                description=(
                    f"urls={len(context.urls)} ipv4={len(context.ipv4)} "
                    f"ipv6={len(context.ipv6)} emails={len(context.emails)} "
                    f"paths={len(context.file_paths)} "
                    f"shell_cmds={len(context.shell_commands)} "
                    f"encoded={len(context.encoded_strings)}"
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.STRING,
                source_file="*",
                supporting_string=_observed_string(
                    context, "strings extracted"
                ),
            ),
        )

    # ------------------------------------------------------------------
    def _scan(
        self,
        context: AnalysisContext,
        blob: bytes,
        source: str,
        seen: set,
    ) -> None:
        text = _decode_blob(blob)
        if not text:
            return

        for chunk in _ascii_strings(text):
            context.strings.append(chunk)
        if len(context.strings) > _MATCH_CAP * 2:
            return

        for pattern, field, category, severity in _PATTERNS:
            target = getattr(context, field)
            for match in pattern.finditer(text):
                found = match.group(0)
                if found in seen:
                    continue
                seen.add(found)
                target.append(found)
                self.emit(
                    context,
                    Finding(
                        category=category,
                        title=category.name.replace("_", " ").title(),
                        description=f"Discovered: {found} (in: {source}).",
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        evidence_type=EvidenceType.STRING,
                        source_file=source,
                        supporting_string=_observed_string(context, found),
                        metadata={"value": found},
                    ),
                )
                if len(target) >= _CAPTURE_CAP:
                    break

        _scan_keywords(context, text, source, seen)
        _scan_encoded(context, text, source, seen)


# ----------------------------------------------------------------------
_PRINTABLE_RUN = re.compile(r"[ -~]{4,}")


def _decode_blob(blob: bytes) -> str:
    return blob.decode("utf-8", errors="ignore")


def _ascii_strings(text: str):
    """Yield continuous printable-ASCII runs (>= 4 chars) as extracted strings."""
    for match in _PRINTABLE_RUN.finditer(text):
        yield match.group(0)


def _scan_keywords(context, text, source, seen) -> None:
    lower = text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword not in lower:
            continue
        key = ("kw", keyword)
        if key in seen:
            continue
        seen.add(key)
        context.suspicious_keywords.append(keyword)
        context.strings.append(f"suspicious_keyword:{keyword}")


def _scan_encoded(context, text, source, seen) -> None:
    for pattern in (BASE64_LIKE_RE, HEX_LIKE_RE):
        for match in pattern.finditer(text):
            value = match.group(0)
            key = ("enc", pattern is BASE64_LIKE_RE, value)
            if key in seen:
                continue
            seen.add(key)
            context.encoded_strings.append(value)
            if len(context.encoded_strings) >= _CAPTURE_CAP:
                return


def _observed_string(context, value: str):
    return value if value in context.strings else None