"""
RE Engine - Android APK Reverse Engineering orchestration layer.

Pipeline: APK -> evidence -> technical analysis -> behavioral reconstruction
          -> structured RE report.

This package is exclusively for reverse engineering. It MUST NOT connect to,
modify, or depend on the malware-family classifier (XGBoost/predictor) or the
feature-engineering pipeline.

Public API:
    REEngine
    AnalysisContext
    Finding
    Confidence
    Severity
    FindingCategory
    EvidenceType
    FindingStatus
"""

from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingStatus,
    Severity,
)
from re_engine.engine import REEngine
from re_engine.behavior.engine import BEHAVIOR_VERSION, BehaviorEngine
from re_engine.behavior.models import (
    BehaviorFinding,
    BehaviorResult,
    BehaviorStatus,
)
from re_engine.dataflow.engine import DataFlowEngine
from re_engine.dataflow.models import (
    DataFlowFinding,
    DataFlowResult,
    FlowStatus,
)
from re_engine.analyzers.obfuscation_analyzer import (
    OBFUSCATION_VERSION,
    ObfuscationAnalyzer,
)
from re_engine.models.obfuscation import (
    ObfuscationFinding,
    ObfuscationType,
)
from re_engine.graph.models import (
    CallGraph,
    EntryPoint,
    GraphNode,
    NodeKind,
    Resolution,
)
from re_engine.graph.builder import CallGraphBuilder
from re_engine.reconstruct.models import (
    CodeArtifact,
    ReconstructionResult,
)
from re_engine.reconstruct.reconstructor import CodeReconstructor
from re_engine.scoring.models import (
    RankingResult,
    SuspicionScore,
)
from re_engine.scoring.scorer import SuspicionScorer
from re_engine.triage import create_triage_engine, run_triage

__all__ = [
    "REEngine",
    "BEHAVIOR_VERSION",
    "BehaviorEngine",
    "BehaviorFinding",
    "BehaviorResult",
    "BehaviorStatus",
    "DataFlowEngine",
    "DataFlowFinding",
    "DataFlowResult",
    "FlowStatus",
    "AnalysisContext",
    "Finding",
    "Confidence",
    "Severity",
    "FindingCategory",
    "EvidenceType",
    "FindingStatus",
    "ObfuscationAnalyzer",
    "ObfuscationFinding",
    "ObfuscationType",
    "OBFUSCATION_VERSION",
    "create_triage_engine",
    "run_triage",
    "CodeArtifact",
    "CodeReconstructor",
    "ReconstructionResult",
    "SuspicionScore",
    "SuspicionScorer",
    "RankingResult",
    "CallGraph",
    "CallGraphBuilder",
    "GraphNode",
    "EntryPoint",
    "NodeKind",
    "Resolution",
]
