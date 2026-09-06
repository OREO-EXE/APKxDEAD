"""REEngine - orchestration layer for the APK reverse-engineering pipeline.

Pipeline stages:

    ingest          load + hash the APK, capture raw bytes and basic identity
    analyze         run registered analyzers; each contributes findings to the
                    shared AnalysisContext
    reconstruct     behavioral reconstruction (call-graph / flow analysis)
    report          assemble the structured RE report

The engine is intentionally decoupled from the malware-family classifier.
Nothing in this module imports ``ai.predictor``, XGBoost, or the feature
vector builder.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, Optional

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.apk import ApkAccessor
from re_engine.behavior.engine import BEHAVIOR_VERSION
from re_engine.behavior.engine import BehaviorEngine
from re_engine.dataflow.engine import DATAFLOW_VERSION
from re_engine.dataflow.engine import DataFlowEngine
from re_engine.models.context import AnalysisContext, Submission
from re_engine.models.finding import (
    Finding,
    FindingCategory,
    FindingStatus,
    Severity,
)
from re_engine.graph.builder import GRAPH_VERSION as CALLGRAPH_VERSION
from re_engine.graph.builder import CallGraphBuilder
from re_engine.output.report import ReReport, build_re_report, serialize_json
from re_engine.reconstruct.models import ReconstructionResult
from re_engine.reconstruct.reconstructor import CodeReconstructor
from re_engine.scoring.models import SUSPICION_VERSION, RankingResult
from re_engine.scoring.scorer import SuspicionScorer

PIPELINE_VERSION = "0.1.0"
RECONSTRUCT_VERSION = "0.1.0"


class REEngine:
    """Runs the APK -> evidence -> analysis -> report pipeline."""

    def __init__(
        self,
        apk_path: Optional[str | Path] = None,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        submission: Optional[Submission] = None,
        reconstruction_options: Optional[dict] = None,
        suspicion_options: Optional[dict] = None,
        callgraph_options: Optional[dict] = None,
        dataflow_options: Optional[dict] = None,
        behavior_options: Optional[dict] = None,
    ) -> None:
        self.apk_path = Path(apk_path) if apk_path else None
        self.analyzers: List[BaseAnalyzer] = list(analyzers or [])
        self._submission = submission or Submission()
        self._context: Optional[AnalysisContext] = None
        self._last_report: Optional[ReReport] = None
        self._reconstruction: Optional[ReconstructionResult] = None
        self._suspicion: Optional[RankingResult] = None
        self._callgraph = None
        self._dataflow = None
        self._behavior = None
        self.reconstruction_options: dict = dict(reconstruction_options or {})
        self.suspicion_options: Optional[dict] = None
        if suspicion_options is not None:
            self.suspicion_options = dict(suspicion_options)
        self.callgraph_options: Optional[dict] = None
        if callgraph_options is not None:
            self.callgraph_options = dict(callgraph_options)
        self.dataflow_options: Optional[dict] = None
        if dataflow_options is not None:
            self.dataflow_options = dict(dataflow_options)
        self.behavior_options: Optional[dict] = None
        if behavior_options is not None:
            self.behavior_options = dict(behavior_options)

    # ------------------------------------------------------------------
    # Analyzer registration
    # ------------------------------------------------------------------
    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        self.analyzers.append(analyzer)

    def register_analyzers(self, analyzers: List[BaseAnalyzer]) -> None:
        self.analyzers.extend(analyzers)

    @property
    def analyzers(self) -> List[BaseAnalyzer]:
        return self._analyzers

    @analyzers.setter
    def analyzers(self, value: List[BaseAnalyzer]) -> None:
        self._analyzers = value

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------
    def run(self) -> ReReport:
        """Execute the full pipeline and return the structured RE report."""
        if self.apk_path is None:
            raise ValueError("No APK path configured for the engine.")

        self._context = self.ingest(self.apk_path)
        self.analyze(self._context)
        self._reconstruction = self.reconstruct(self._context)
        if self.suspicion_options is not None:
            try:
                self._suspicion = SuspicionScorer(
                    options=self.suspicion_options
                ).rank(self._context)
                self._context.register_module(
                    "suspicion", SUSPICION_VERSION, "suspicious-code ranking"
                )
            except Exception as exc:
                self._context.error(f"suspicion ranking failed: {exc}")
        if self.callgraph_options is not None:
            try:
                self._callgraph = CallGraphBuilder(
                    context=self._context, options=self.callgraph_options
                ).build()
                self._context.register_module(
                    "callgraph", CALLGRAPH_VERSION, "APK call-graph construction"
                )
            except Exception as exc:
                self._context.error(f"callgraph construction failed: {exc}")
        if self.dataflow_options is not None:
            try:
                self._dataflow = DataFlowEngine(
                    context=self._context, options=self.dataflow_options
                ).run()
                self._context.register_module(
                    "dataflow", DATAFLOW_VERSION, "source-to-sink data-flow analysis"
                )
            except Exception as exc:
                self._context.error(f"dataflow analysis failed: {exc}")
        if self.behavior_options is not None:
            try:
                self._behavior = BehaviorEngine(
                    context=self._context,
                    dataflow=self._dataflow,
                    graph=self._callgraph,
                    options=self.behavior_options,
                ).run()
                self._context.register_module(
                    "behavior", BEHAVIOR_VERSION, "evidence-backed behavior profile"
                )
            except Exception as exc:
                self._context.error(f"behavior reconstruction failed: {exc}")
        self._last_report = self.report(
            self._context,
            self._reconstruction,
            suspicion_ranking=self._suspicion,
            callgraph=self._callgraph,
            dataflow=self._dataflow,
            behavior=self._behavior,
        )
        return self._last_report

    def ingest(self, apk_path: Path) -> AnalysisContext:
        """Create the AnalysisContext and capture basic APK identity."""
        path = Path(apk_path)
        if not path.exists():
            raise FileNotFoundError(f"APK not found: {path}")

        context = AnalysisContext(
            apk_path=str(path),
            apk_size=path.stat().st_size,
            sha256=_sha256_of(path),
            md5=_md5_of(path),
            submission=self._submission,
        )
        context.artifacts = ApkAccessor(path)
        context.register_module("REEngine", PIPELINE_VERSION, "Orchestration layer")
        if context.artifacts.androguard_apk is not None:
            context.register_module(
                "androguard", "4.1.4", "APK/DEX/cert parsing"
            )
        return context

    def analyze(self, context: AnalysisContext) -> None:
        """Run all registered analyzers against the context."""
        for analyzer in self.analyzers:
            try:
                analyzer.register(context)
                analyzer.run(context)
            except Exception as exc:  # analyzers must never kill the run
                context.error(f"[{analyzer.name}] analyzer failed: {exc}")
                context.add_finding(
                    Finding(
                        category=FindingCategory.ERROR,
                        title="Analyzer failed",
                        description=str(exc),
                        severity=Severity.MEDIUM,
                        analyzer=analyzer.name,
                        status=FindingStatus.OPEN,
                    )
                )

    def reconstruct(self, context: AnalysisContext):
        """Code-reconstruction stage.

        Converts the APK's DEX files into a bounded set of evidence-backed
        ``CodeArtifact`` records (Smali authoritative representation plus
        best-effort Java). Returns a :class:`ReconstructionResult` (a
        possibly-empty result on no DEX content) or None when the stage is
        skipped. Subclasses may override this hook.
        """
        if context.artifacts is None:
            return None
        try:
            reconstructor = CodeReconstructor(
                context, options=self.reconstruction_options
            )
            result = reconstructor.run()
        except Exception as exc:
            context.error(f"reconstruct stage failed: {exc}")
            return None
        context.register_module(
            "reconstruct", RECONSTRUCT_VERSION, "DEX -> code artifacts"
        )
        return result

    def report(
        self,
        context: AnalysisContext,
        behavioral=None,
        suspicion_ranking: Optional[RankingResult] = None,
        callgraph=None,
        dataflow=None,
        behavior=None,
    ) -> ReReport:
        context.mark_completed()
        code_reconstruction = None
        if isinstance(behavioral, ReconstructionResult):
            code_reconstruction = behavioral.to_dict()
            behavioral = behavioral.to_behavioral()
        behavior_data = None
        if behavior is not None and hasattr(behavior, "to_dict"):
            behavior_data = behavior.to_dict()
        if behavior is not None and hasattr(behavior, "to_behavioral_reconstruction"):
            behavioral = behavior.to_behavioral_reconstruction()
        ranking_data = None
        if isinstance(suspicion_ranking, RankingResult):
            ranking_data = suspicion_ranking.to_dict()
        callgraph_data = None
        if callgraph is not None and hasattr(callgraph, "to_dict"):
            callgraph_data = callgraph.to_dict()
        dataflow_data = None
        if dataflow is not None and hasattr(dataflow, "to_dict"):
            dataflow_data = dataflow.to_dict()
        return build_re_report(
            context,
            behavioral,
            code_reconstruction=code_reconstruction,
            suspicion_ranking=ranking_data,
            callgraph=callgraph_data,
            dataflow=dataflow_data,
            behavior=behavior_data,
        )

    def report_json(self, pretty: bool = True) -> str:
        """Serialize the last produced report to JSON."""
        if self._last_report is None:
            raise RuntimeError("No report produced yet; call run() first.")
        return serialize_json(self._last_report, pretty=pretty)

    @property
    def context(self) -> Optional[AnalysisContext]:
        return self._context

    @property
    def last_report(self) -> Optional[ReReport]:
        return self._last_report

    @property
    def reconstruction(self) -> Optional[ReconstructionResult]:
        return self._reconstruction

    @property
    def suspicion(self) -> Optional[RankingResult]:
        return self._suspicion

    @property
    def callgraph(self):
        return self._callgraph

    @property
    def dataflow(self):
        return self._dataflow

    @property
    def behavior(self):
        return self._behavior


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _md5_of(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()