"""Behavior-reconstruction engine: evidence -> behavioral profile.

``BehaviorEngine`` consumes the same deterministic, evidence-backed surface as
every other RE stage (``CodeIndex``, ``AnalysisContext``, optional
``DataFlowResult`` / ``CallGraph``) and asks every behaviour in the catalogue
whether its evidence chain holds. Output is a :class:`BehaviorResult` with one
:class:`BehaviorFinding` per behaviour; every claim records the evidence that
leads to its status.

Hard rules
----------
* Static and deterministic: no classifiers, no LLMs, no randomized iteration.
* ``UNKNOWN`` is reported as-is; it is never promoted to ``TRUE``.
* A permission alone never proves a behavior.
* Chained behaviors (download->load, decrypt->load, emulator/root probes)
  require the two signals to co-occur in the same *method* to be ``TRUE``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from re_engine.behavior.detectors import (
    AGGREGATE_KEYS,
    DETECTORS,
    Detection,
    _anti_analysis,
)
from re_engine.behavior.evidence import EvidenceContext, EvidenceIndex
from re_engine.behavior.models import BehaviorFinding, BehaviorResult, BehaviorStatus
from re_engine.behavior.specs import BehaviorSpec, behaviors_in_order
from re_engine.reconstruct.index import CodeIndex

BEHAVIOR_VERSION = "0.1.0"


class BehaviorEngine:
    """Runs all behavior detectors over one APK's evidence surface."""

    def __init__(
        self,
        context=None,
        index: Optional[CodeIndex] = None,
        dataflow=None,
        graph=None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.context = context
        self.dataflow = dataflow
        self.graph = graph
        self.options = {**self._default_options(), **(options or {})}
        self._index_owned = index is None
        self._index = index or (
            CodeIndex(
                list(
                    getattr(
                        getattr(context, "artifacts", None),
                        "dex",
                        None,
                    )
                    or []
                )
            )
            if context is not None
            else CodeIndex([])
        )
        self._evidence: Optional[EvidenceContext] = None
        self._result: Optional[BehaviorResult] = None

    @staticmethod
    def _default_options() -> Dict[str, Any]:
        return {
            "max_methods": 6000,
            "ref_cap": 200,
        }

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    def run(self) -> BehaviorResult:
        self._index._ensure_index()
        index = EvidenceIndex(
            self._index,
            max_methods=int(self.options["max_methods"]),
            ref_cap=int(self.options["ref_cap"]),
        )
        self._evidence = EvidenceContext(
            self.context, index, dataflow=self.dataflow, graph=self.graph
        )
        ordered_specs = behaviors_in_order()
        detections: Dict[str, Detection] = {}
        for spec in ordered_specs:
            if spec.key in AGGREGATE_KEYS:
                continue
            try:
                detections[spec.key] = DETECTORS[spec.key](spec, self._evidence)
            except Exception as exc:  # a bad detector must not kill the stage
                detections[spec.key] = Detection(
                    BehaviorStatus.UNKNOWN,
                    "low",
                    f"detector failed: {exc}",
                    evidence_refs=[f"error:{spec.key}"],
                )
        detections["evasion.anti_analysis"] = _anti_analysis(
            _spec_for("evasion.anti_analysis", ordered_specs),
            self._evidence,
            {k: d.status for k, d in detections.items()},
        )

        findings: List[BehaviorFinding] = []
        for spec in ordered_specs:
            detection = detections.get(spec.key)
            if detection is None:
                continue
            findings.append(
                BehaviorFinding(
                    behavior_id=spec.key,
                    behavior_name=spec.name,
                    category=spec.category,
                    status=detection.status,
                    confidence=detection.confidence,
                    explanation=detection.explanation,
                    evidence_refs=_cap(detection.evidence_refs),
                    related_classes=_cap(
                        self._evidence.related_classes(detection.methods), 24
                    ),
                    related_methods=_cap(detection.methods),
                    related_permissions=_cap(detection.permissions),
                    related_data_flows=_cap(detection.data_flows),
                )
            )

        status_counts = {status.value: 0 for status in BehaviorStatus}
        for finding in findings:
            status_counts[finding.status.value] += 1
        # Stable per-category true-behavior rollup for the summary line.
        true_counts: Dict[str, int] = {}
        for finding in findings:
            if finding.status == BehaviorStatus.TRUE:
                true_counts[finding.category] = (
                    true_counts.get(finding.category, 0) + 1
                )
        summary = "behavior profile: " + ", ".join(
            f"{count} {cat}" for cat, count in sorted(true_counts.items())
        ) or "behavior profile: no verified behaviors"

        limitations = [
            "Behavior reconstruction is static; evidence is a directly observed "
            "bytecode/manifest surface, not runtime behavior.",
            F"Method scan is capped at {self.options['max_methods']} methods and "
            "references to 200 per method; behavior beyond the cap can be missed.",
            "ENCRYPT_MODE/DECRYPT_MODE mixes are approximated via 1/2 const "
            "literals near Cipher.init and may mis-attribute direction.",
            "Dynamically loaded (non-static) DEX cannot be inspected; only the "
            "loading *pattern* is evidence.",
            "Same-method co-occurrence is a heuristic; it cannot prove the "
            "observations are causally linked.",
        ]
        self._result = BehaviorResult(
            findings=findings,
            stats={
                "behaviors_evaluated": len(findings),
                "status_counts": status_counts,
                "methods_scanned": len(index.method_order),
            },
            limitations=limitations,
            summary=summary,
        )
        return self._result

    @property
    def result(self) -> Optional[BehaviorResult]:
        return self._result

    @property
    def evidence(self) -> Optional[EvidenceContext]:
        return self._evidence


def _spec_for(key: str, ordered_specs: List[BehaviorSpec]) -> BehaviorSpec:
    for spec in ordered_specs:
        if spec.key == key:
            return spec
    return BehaviorSpec(key, "evasion", "Anti-analysis", "aggregate behavior")


def _cap(values, limit: int = 32):
    return sorted(set(values), key=str.lower)[:limit]


__all__ = ["BEHAVIOR_VERSION", "BehaviorEngine"]