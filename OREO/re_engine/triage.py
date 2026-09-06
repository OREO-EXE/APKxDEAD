"""High-level APK triage entry point.

Bundles the nine deterministic triage analyzers (metadata, structure,
manifest, permissions, DEX, strings, obfuscation, native libraries,
certificates) into a ready-to-run ``REEngine`` and exposes a one-call
``run_triage`` helper.

Order matters: manifest/permission analyzers populate ``context.permissions``
before the permission classifier runs; the string analyzer populates
``context.strings`` so afterwards emitted findings can reference it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.analyzers.certificate_analyzer import CertificateAnalyzer
from re_engine.analyzers.dex_analyzer import DexAnalyzer
from re_engine.analyzers.manifest_analyzer import ManifestAnalyzer
from re_engine.analyzers.metadata_analyzer import MetadataAnalyzer
from re_engine.analyzers.native_lib_analyzer import NativeLibAnalyzer
from re_engine.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from re_engine.analyzers.permission_analyzer import PermissionAnalyzer
from re_engine.analyzers.string_analyzer import StringAnalyzer
from re_engine.analyzers.structure_analyzer import StructureAnalyzer
from re_engine.engine import REEngine
from re_engine.models.context import Submission
from re_engine.output.report import ReReport


def create_triage_engine(
    apk_path,
    submission: Optional[Submission] = None,
    reconstruction_options: Optional[dict] = None,
    suspicion_options: Optional[dict] = None,
    callgraph_options: Optional[dict] = None,
    dataflow_options: Optional[dict] = None,
    behavior_options: Optional[dict] = None,
) -> REEngine:
    """Build an REEngine pre-loaded with the nine triage analyzers."""
    analyzers: list = [
        MetadataAnalyzer(),
        StructureAnalyzer(),
        ManifestAnalyzer(),
        PermissionAnalyzer(),
        DexAnalyzer(),
        StringAnalyzer(),
        ObfuscationAnalyzer(),
        NativeLibAnalyzer(),
        CertificateAnalyzer(),
    ]
    return REEngine(
        apk_path=Path(apk_path),
        analyzers=analyzers,
        submission=submission,
        reconstruction_options=reconstruction_options,
        suspicion_options=suspicion_options,
        callgraph_options=callgraph_options,
        dataflow_options=dataflow_options,
        behavior_options=behavior_options,
    )


def run_triage(
    apk_path,
    submission: Optional[Submission] = None,
    reconstruction_options: Optional[dict] = None,
    suspicion_options: Optional[dict] = None,
    callgraph_options: Optional[dict] = None,
    dataflow_options: Optional[dict] = None,
    behavior_options: Optional[dict] = None,
) -> ReReport:
    """Run the full triage pipeline for one APK and return the report."""
    engine = create_triage_engine(
        apk_path,
        submission,
        reconstruction_options,
        suspicion_options,
        callgraph_options,
        dataflow_options,
        behavior_options,
    )
    return engine.run()


__all__ = ["create_triage_engine", "run_triage"]