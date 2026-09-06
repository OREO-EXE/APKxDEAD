"""Base class for RE engine analyzers.

An analyzer inspects some portion of the APK (or the accumulated
:class:`~re_engine.models.context.AnalysisContext`) and contributes
:class:`~re_engine.models.finding.Finding` records back into the context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from re_engine.models.context import AnalysisContext
from re_engine.models.finding import Finding


class BaseAnalyzer(ABC):
    """Interface every analyzer must implement.

    Attribute contract:
        name:      stable identifier used for ``finding.analyzer``
        version:   analyzer version string
        stages:    pipeline stages this analyzer participates in
    """

    name: str = "base"
    version: str = "0.1.0"
    description: str = ""

    @abstractmethod
    def run(self, context: AnalysisContext) -> None:
        """Analyze the context and add findings to it."""

    def register(self, context: AnalysisContext) -> None:
        context.register_module(self.name, self.version, self.description)

    def emit(self, context: AnalysisContext, finding: Finding) -> None:
        """Add a finding to the context, tagging it with this analyzer."""
        if finding.analyzer is None:
            finding.analyzer = self.name
        context.add_finding(finding)
