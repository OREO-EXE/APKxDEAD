"""Evidence validation: keep findings honest.

An analyzer (or future AI stage) must never claim supporting evidence that was
not actually observed. ``validate_finding_support`` cross-checks a finding's
supporting references against the observable content of the AnalysisContext
(strings, URLs, domains, IPs, classes, methods, permissions, components).
"""

from __future__ import annotations

from typing import List

from re_engine.models.context import AnalysisContext
from re_engine.models.finding import EvidenceType, Finding


def _looks_like_permission(value: str) -> bool:
    """A permission name is dotted and space-free; descriptive titles are not."""
    return (
        bool(value)
        and "." in value
        and " " not in value
        and value[0].isalnum()
    )


def validate_finding_support(
    context: AnalysisContext, finding: Finding
) -> List[str]:
    """Return a list of violated support claims (empty means honest).

    Checks performed:
      - finding.supporting_string must appear among context.strings
      - finding.supporting_url must appear among context.urls
      - finding.supporting_api must be mentioned by a DEX class/method name
      - a PERMISSION-category finding must name a declared permission when it
        references one
    """
    violations: List[str] = []

    if finding.supporting_string is not None:
        if finding.supporting_string not in context.strings:
            violations.append(
                f"supporting_string not found: {finding.supporting_string}"
            )

    if finding.supporting_url is not None:
        if finding.supporting_url not in context.urls:
            violations.append(
                f"supporting_url not found: {finding.supporting_url}"
            )

    if finding.supporting_api is not None:
        haystack = [
            *context.classes,
            *context.methods,
            *context.dex.api_counts.keys(),
        ]
        if not any(finding.supporting_api in item for item in haystack):
            violations.append(
                f"supporting_api not found: {finding.supporting_api}"
            )

    if finding.evidence_type == EvidenceType.PERMISSION:
        referenced = finding.metadata.get("permission")
        if referenced is None and _looks_like_permission(finding.title):
            referenced = finding.title
        if referenced is not None and referenced not in context.permissions:
            violations.append(f"permission not declared: {referenced}")

    return violations