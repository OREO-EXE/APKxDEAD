"""Deterministic suspicion scoring over one APK's evidence.

:class:`SuspicionScorer` produces a ranked, bounded list of
:class:`SuspicionScore` records across classes, methods, components, APIs,
strings and network functions. Every score is backed by concrete reasons and
the raw evidence references that produced them:

    - methods carry the API hits, network indicator strings, permission+usage
      matches, caller context (e.g. "called by BOOT_COMPLETED receiver") and
      identifier-level obfuscation signals observed in their own bytecode
    - classes aggregate the signals of their methods plus name obfuscation
    - components add manifest role / permission reasons and, when resolvable,
      the code evidence of their class
    - APIs aggregate distinct sensitive API references and their fan-out
    - strings rank observed URL/domain/IP/shell/encoded indicators
    - network functions project methods whose dominant evidence is networking

Nothing here executes APK code, touches the network, imports a classifier or
uses randomness."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from re_engine.models.context import AnalysisContext
from re_engine.reconstruct.index import CodeIndex
from re_engine.scoring.models import (
    SUSPICION_VERSION,
    RankingResult,
    ScoringReason,
    SuspicionScore,
    TargetKind,
)
from re_engine.scoring.signals import (
    PERMISSION_SIGNALS,
    SENSITIVE_DATA_CATEGORIES,
    Signal,
    classify_string,
    high_identifier_entropy,
    is_command_execution,
    permissions_by_category,
    signal_for_call,
    string_signals_as_reasons,
    suspicious_class_segments,
    suspicious_method_segments,
    _BOOT_CALLER_LABEL,
    _BOOT_CALLER_WEIGHT,
    _CLASS_SEGMENT_NAME,
    _COMMAND_EXEC_LABEL,
    _COMMAND_EXEC_WEIGHT,
    _DATA_COLLECTION_LABEL,
    _DATA_COLLECTION_WEIGHT,
    _ENCODED_STRING,
    _ENCODED_STRINGS_LABEL,
    _ENCRYPTED_TRAFFIC_LABEL,
    _ENCRYPTED_TRAFFIC_WEIGHT,
    _HIGH_ENTROPY_LABEL,
    _HIGH_ENTROPY_NAME,
    _METHOD_SEGMENT_NAME,
    _NETWORK_INDICATOR_REF,
    _NETWORK_INDICATORS_LABEL,
    _REFLECTION_HEAVY,
    _REFLECTION_HEAVY_LABEL,
    _SUSPICIOUS_NAME_LABEL,
)

_ALLOWED_COMPONENT_PERMISSION_CATEGORIES = {
    "receiver": {"SMS", "CALL_LOG", "LOCATION", "DEVICE_ADMIN"},
    "service": {"ACCESSIBILITY", "NOTIFICATION", "MICROPHONE", "CAMERA", "LOCATION"},
    "activity": {"CAMERA", "MICROPHONE", "LOCATION", "STORAGE"},
    "provider": {"STORAGE"},
}


@dataclass
class EvidenceContext:
    """Normalized, deduplicated view of one APK's manifest/string evidence."""

    permissions: Set[str] = field(default_factory=set)
    permissions_by_category: Dict[str, List[str]] = field(default_factory=dict)
    boot_receivers: Set[str] = field(default_factory=set)
    foreground_services: Set[str] = field(default_factory=set)
    accessibility_components: Set[str] = field(default_factory=set)
    device_admin_components: Set[str] = field(default_factory=set)
    exported_components: Set[str] = field(default_factory=set)
    component_names: Set[str] = field(default_factory=set)
    component_kind_by_name: Dict[str, str] = field(default_factory=dict)
    urls: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    encoded_strings: Set[str] = field(default_factory=set)
    shell_commands: Set[str] = field(default_factory=set)
    suspicious_keywords: Set[str] = field(default_factory=set)

    @classmethod
    def from_context(cls, context: AnalysisContext) -> "EvidenceContext":
        permissions = set(context.permissions or [])
        return cls(
            permissions=permissions,
            permissions_by_category=permissions_by_category(list(permissions)),
            boot_receivers=set(context.boot_receivers or []),
            foreground_services=set(context.foreground_services or []),
            accessibility_components=set(context.accessibility_components or []),
            device_admin_components=set(context.device_admin_components or []),
            exported_components=set(context.exported_components or []),
            component_names={c.name for c in context.components},
            component_kind_by_name={
                c.name: c.kind for c in context.components if c.name
            },
            urls=set(context.urls or []),
            domains=set(context.domains or []),
            ips=set(context.ips or [])
            | set(context.ipv4 or [])
            | set(context.ipv6 or []),
            encoded_strings=set(context.encoded_strings or []),
            shell_commands=set(context.shell_commands or []),
            suspicious_keywords=set(context.suspicious_keywords or []),
        )


def _normalize_component_name(name: str) -> str:
    value = str(name).strip()
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1].replace("/", ".")
    return value.replace("/", ".")


class SuspicionScorer:
    """Evidence-based, deterministic suspicious-code ranker for one APK."""

    def __init__(self, options: Optional[Dict[str, object]] = None) -> None:
        self.options = {**self._default_options(), **(options or {})}

    @staticmethod
    def _default_options() -> Dict[str, object]:
        return {
            "method_ref_cap": 60,
            "caller_scan_cap": 15000,
            "max_per_kind": 60,
            "entropy_threshold": 3.8,
            "reflection_heavy_min": 3,
            "usage_bonus_cap": 8,
            "min_network_function_score": 15,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def rank(self, context: AnalysisContext) -> RankingResult:
        """Rank the evidence of one analysis context, highest score first."""
        evidence = EvidenceContext.from_context(context)
        dex_files = getattr(getattr(context, "artifacts", None), "dex", None) or []
        index = CodeIndex(
            dex_files,
            caller_scan_cap=int(self.options["caller_scan_cap"]),
        )
        return self._rank_with(evidence, index)

    def _rank_with(
        self, evidence: EvidenceContext, index: CodeIndex
    ) -> RankingResult:
        index._ensure_index()
        boot_descriptors = self._resolved_descriptors(
            index, evidence.boot_receivers
        )

        method_scores: Dict[str, SuspicionScore] = {}
        api_usage: Dict[str, Dict[str, object]] = {}
        string_usage: Dict[str, Set[str]] = {}
        class_data: Dict[str, Dict[str, object]] = {}

        for descriptor in sorted(index._class_by_desc.keys(), key=str.lower):
            class_entry = index._class_by_desc[descriptor]
            data = class_data.setdefault(
                descriptor,
                {
                    "api_signals": {},
                    "strings": set(),
                    "reflection_count": 0,
                    "network": False,
                    "sensitive": False,
                },
            )
            for method_entry in class_entry.methods():
                self._score_method(
                    method_entry,
                    evidence,
                    index,
                    boot_descriptors,
                    method_scores,
                    api_usage,
                    string_usage,
                    data,
                )
            data["strings"] = sorted(data["strings"])  # type: ignore[assignment]

        scores: List[SuspicionScore] = []
        for descriptor in sorted(class_data.keys(), key=str.lower):
            score = self._class_score(
                descriptor,
                class_data[descriptor],
                index,
                evidence,
                boot_descriptors,
            )
            if score is not None:
                scores.append(score)

        scores.extend(self._method_list(method_scores))
        scores.extend(self._api_list(api_usage))
        scores.extend(self._string_list(evidence, string_usage))
        scores.extend(self._network_function_list(method_scores))
        scores.extend(self._component_list(evidence, index, method_scores))

        scores = self._finalize(scores)
        total = len(scores)
        summary = (
            f"ranked {total} suspicious code targets from "
            f"{index.stats.get('classes_indexed', 0)} classes across "
            f"{index.stats.get('dex_count', 0)} dex file(s)"
        )
        return RankingResult(scores=scores, summary=summary)

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------
    def _score_method(
        self,
        method_entry,
        evidence: EvidenceContext,
        index: CodeIndex,
        boot_descriptors: Set[str],
        method_scores: Dict[str, SuspicionScore],
        api_usage: Dict[str, Dict[str, object]],
        string_usage: Dict[str, Set[str]],
        class_data: Dict[str, object],
    ) -> None:
        mid = method_entry.mid
        if not mid:
            return
        refs = method_entry.references(ref_cap=int(self.options["method_ref_cap"]))
        reasons: List[ScoringReason] = []
        api_categories: Set[str] = set()
        has_network_api = False
        has_crypt_api = False
        has_sensitive_data_api = False

        for call in refs.get("calls", []):
            signal = signal_for_call(call)
            if signal is None:
                continue
            reasons.append(
                ScoringReason(signal.label, signal.weight, signal.category, call)
            )
            api_categories.add(signal.category)
            has_network_api = has_network_api or signal.category == "NETWORK"
            has_crypt_api = has_crypt_api or signal.category == "CRYPTO"
            has_sensitive_data_api = (
                has_sensitive_data_api
                or signal.category in SENSITIVE_DATA_CATEGORIES
            )
            record = api_usage.setdefault(
                call, {"signal": signal, "mids": set()}
            )
            record["mids"].add(mid)
            class_signals = class_data["api_signals"]  # type: ignore[union-attr]
            if signal.label not in class_signals:
                class_signals[signal.label] = (
                    signal.weight,
                    signal.category,
                    call,
                )
            if signal.category in ("REFLECTION", "DYNAMIC_LOADING"):
                class_data["reflection_count"] += 1  # type: ignore[operator]
            if signal.category == "NETWORK":
                class_data["network"] = True  # type: ignore[assignment]
            if signal.category in SENSITIVE_DATA_CATEGORIES:
                class_data["sensitive"] = True  # type: ignore[assignment]
            if is_command_execution(call):
                reasons.append(
                    ScoringReason(
                        _COMMAND_EXEC_LABEL,
                        _COMMAND_EXEC_WEIGHT,
                        "BEHAVIOR",
                        call,
                    )
                )

        for value in refs.get("strings", []):
            signals = string_signals_as_reasons(value, evidence.shell_commands)
            for signal in signals:
                reasons.append(
                    ScoringReason(signal.label, signal.weight, signal.category, value)
                )
            if signals:
                class_data["strings"].add(value)  # type: ignore[union-attr]
                string_usage.setdefault(value, set()).add(mid)

        if evidence.permissions_by_category:
            for category in sorted(api_categories):
                declared = evidence.permissions_by_category.get(category)
                if not declared:
                    continue
                for permission in declared[:3]:
                    signal = PERMISSION_SIGNALS.get(permission)
                    if signal is None:
                        continue
                    reasons.append(
                        ScoringReason(
                            f"{signal.label} declared with {category} API usage",
                            signal.weight,
                            "PERMISSION",
                            permission,
                        )
                    )

        if boot_descriptors:
            caller = self._boot_caller(index, mid, boot_descriptors)
            if caller is not None:
                reasons.append(
                    ScoringReason(
                        _BOOT_CALLER_LABEL, _BOOT_CALLER_WEIGHT, "BEHAVIOR", caller
                    )
                )

        if has_network_api and has_crypt_api:
            reasons.append(
                ScoringReason(
                    _ENCRYPTED_TRAFFIC_LABEL,
                    _ENCRYPTED_TRAFFIC_WEIGHT,
                    "BEHAVIOR",
                    "; ".join(sorted(api_categories)),
                )
            )
        if has_sensitive_data_api and has_network_api:
            reasons.append(
                ScoringReason(
                    _DATA_COLLECTION_LABEL,
                    _DATA_COLLECTION_WEIGHT,
                    "BEHAVIOR",
                    mid,
                )
            )

        name = method_entry.name or ""
        for segment in suspicious_method_segments(name):
            reasons.append(
                ScoringReason(
                    _SUSPICIOUS_NAME_LABEL,
                    _METHOD_SEGMENT_NAME,
                    "OBFUSCATION",
                    segment,
                )
            )
        if high_identifier_entropy(
            name, threshold=float(self.options["entropy_threshold"])
        ):
            reasons.append(
                ScoringReason(
                    _HIGH_ENTROPY_LABEL,
                    _HIGH_ENTROPY_NAME,
                    "OBFUSCATION",
                    name,
                )
            )

        reasons = self._dedupe_reasons(reasons)
        if not reasons:
            return
        method_scores[mid] = SuspicionScore(
            target=mid,
            kind=TargetKind.METHOD,
            score=sum(r.weight for r in reasons),
            reasons=reasons,
            evidence_refs=self._evidence_refs(reasons),
        )

    def _boot_caller(
        self, index: CodeIndex, mid: str, boot_descriptors: Set[str]
    ) -> Optional[str]:
        for caller in index.callers_of(mid):
            caller_class = caller.split("->", 1)[0]
            if caller_class in boot_descriptors:
                return caller
        return None

    # ------------------------------------------------------------------
    # Classes
    # ------------------------------------------------------------------
    def _class_score(
        self,
        descriptor: str,
        data: Dict[str, object],
        index: CodeIndex,
        evidence: EvidenceContext,
        boot_descriptors: Set[str],
    ) -> Optional[SuspicionScore]:
        class_entry = index.find_class(descriptor)
        if class_entry is None:
            return None
        reasons: List[ScoringReason] = []
        dotted = class_entry.dotted

        for segment in suspicious_class_segments(dotted):
            reasons.append(
                ScoringReason(
                    _SUSPICIOUS_NAME_LABEL,
                    _CLASS_SEGMENT_NAME,
                    "OBFUSCATION",
                    f"{descriptor}:{segment}",
                )
            )
        simple_name = dotted.rsplit(".", 1)[-1]
        if high_identifier_entropy(
            simple_name, threshold=float(self.options["entropy_threshold"])
        ):
            reasons.append(
                ScoringReason(
                    _HIGH_ENTROPY_LABEL,
                    _HIGH_ENTROPY_NAME,
                    "OBFUSCATION",
                    descriptor,
                )
            )

        class_signals: Dict[str, object] = data["api_signals"]  # type: ignore[assignment]
        for label in sorted(class_signals):
            weight, category, call = class_signals[label]  # type: ignore[misc]
            reasons.append(ScoringReason(label, weight, category, call))

        class_strings: Set[str] = data["strings"]  # type: ignore[assignment]
        network_indicators = sorted(
            s
            for s in class_strings
            if any(sig.category == "NETWORK" for sig in classify_string(s))
        )
        if network_indicators:
            reasons.append(
                ScoringReason(
                    _NETWORK_INDICATORS_LABEL,
                    _NETWORK_INDICATOR_REF,
                    "NETWORK",
                    network_indicators[0],
                )
            )
        encoded_samples = sorted(
            s
            for s in class_strings
            if any(sig.category == "ENCODED" for sig in classify_string(s))
        )
        if encoded_samples:
            reasons.append(
                ScoringReason(
                    _ENCODED_STRINGS_LABEL,
                    _ENCODED_STRING,
                    "OBFUSCATION",
                    encoded_samples[0],
                )
            )

        network: bool = data["network"]  # type: ignore[assignment]
        sensitive: bool = data["sensitive"]  # type: ignore[assignment]
        if network and sensitive:
            reasons.append(
                ScoringReason(
                    _DATA_COLLECTION_LABEL,
                    _DATA_COLLECTION_WEIGHT,
                    "BEHAVIOR",
                    descriptor,
                )
            )

        reflection_count: int = data["reflection_count"]  # type: ignore[assignment]
        if reflection_count >= int(self.options["reflection_heavy_min"]):
            reasons.append(
                ScoringReason(
                    _REFLECTION_HEAVY_LABEL,
                    _REFLECTION_HEAVY,
                    "OBFUSCATION",
                    descriptor,
                )
            )

        for component_name in self._matching_components(evidence, dotted, descriptor):
            if descriptor in boot_descriptors:
                reasons.append(
                    ScoringReason(
                        "declared BOOT_COMPLETED receiver",
                        20,
                        "COMPONENT",
                        component_name,
                    )
                )

        reasons = self._dedupe_reasons(reasons)
        if not reasons:
            return None
        return SuspicionScore(
            target=descriptor,
            kind=TargetKind.CLASS,
            score=sum(r.weight for r in reasons),
            reasons=reasons,
            evidence_refs=self._evidence_refs(reasons),
        )

    @staticmethod
    def _matching_components(
        evidence: EvidenceContext, dotted: str, descriptor: str
    ) -> List[str]:
        return [
            name
            for name in sorted(evidence.component_names)
            if _normalize_component_name(name) in (dotted, descriptor)
        ]

    # ------------------------------------------------------------------
    # APIs / strings / network functions / components
    # ------------------------------------------------------------------
    def _api_list(
        self, api_usage: Dict[str, Dict[str, object]]
    ) -> List[SuspicionScore]:
        scores: List[SuspicionScore] = []
        for call in sorted(api_usage.keys()):
            record = api_usage[call]
            signal: Signal = record["signal"]  # type: ignore[assignment]
            mids: Set[str] = record["mids"]  # type: ignore[assignment]
            usage = len(mids)
            bonus = min(int(self.options["usage_bonus_cap"]), usage)
            reasons = [
                ScoringReason(signal.label, signal.weight, signal.category, call),
                ScoringReason(
                    f"used by {usage} method(s)",
                    bonus,
                    "USAGE",
                    "; ".join(sorted(mids))[:400],
                ),
            ]
            scores.append(
                SuspicionScore(
                    target=call,
                    kind=TargetKind.API,
                    score=signal.weight + bonus,
                    reasons=reasons,
                    evidence_refs=self._evidence_refs(reasons),
                )
            )
        return scores

    def _string_list(
        self, evidence: EvidenceContext, string_usage: Dict[str, Set[str]]
    ) -> List[SuspicionScore]:
        candidates: Set[str] = set()
        for bucket in (
            evidence.urls,
            evidence.domains,
            evidence.ips,
            evidence.encoded_strings,
            evidence.shell_commands,
            evidence.suspicious_keywords,
        ):
            candidates.update(bucket)
        candidates.update(string_usage.keys())

        scores: List[SuspicionScore] = []
        for value in sorted(candidates):
            signals = string_signals_as_reasons(value, evidence.shell_commands)
            if not signals:
                continue
            reasons = [
                ScoringReason(sig.label, sig.weight, sig.category, value)
                for sig in signals
            ]
            users = string_usage.get(value, set())
            if len(users) > 1:
                reasons.append(
                    ScoringReason(
                        f"referenced by {len(users)} method(s)",
                        min(int(self.options["usage_bonus_cap"]), len(users)),
                        "USAGE",
                        "; ".join(sorted(users))[:400],
                    )
                )
            scores.append(
                SuspicionScore(
                    target=value,
                    kind=TargetKind.STRING,
                    score=sum(r.weight for r in reasons),
                    reasons=self._dedupe_reasons(reasons),
                    evidence_refs=self._evidence_refs(reasons),
                )
            )
        return scores

    def _network_function_list(
        self, method_scores: Dict[str, SuspicionScore]
    ) -> List[SuspicionScore]:
        scores: List[SuspicionScore] = []
        for mid in sorted(method_scores.keys()):
            score_object = method_scores[mid]
            network_reasons = [
                r for r in score_object.reasons if r.category == "NETWORK"
            ]
            network_score = sum(r.weight for r in network_reasons)
            if not network_reasons:
                continue
            if network_score < int(self.options["min_network_function_score"]):
                continue
            scores.append(
                SuspicionScore(
                    target=mid,
                    kind=TargetKind.NETWORK,
                    score=network_score,
                    reasons=self._dedupe_reasons(network_reasons),
                    evidence_refs=self._evidence_refs(network_reasons),
                )
            )
        return scores

    def _component_list(
        self,
        evidence: EvidenceContext,
        index: CodeIndex,
        method_scores: Dict[str, SuspicionScore],
    ) -> List[SuspicionScore]:
        scores: List[SuspicionScore] = []
        for name in sorted(evidence.component_names):
            reasons: List[ScoringReason] = []

            if name in evidence.boot_receivers:
                reasons.append(
                    ScoringReason(
                        "declared BOOT_COMPLETED receiver",
                        20,
                        "COMPONENT",
                        name,
                    )
                )
            if name in evidence.device_admin_components:
                reasons.append(
                    ScoringReason(
                        "declared device-admin receiver",
                        30,
                        "COMPONENT",
                        name,
                    )
                )
            if name in evidence.accessibility_components:
                reasons.append(
                    ScoringReason(
                        "declared accessibility service",
                        30,
                        "COMPONENT",
                        name,
                    )
                )
            if name in evidence.foreground_services:
                reasons.append(
                    ScoringReason(
                        "declared foreground service",
                        10,
                        "COMPONENT",
                        name,
                    )
                )
            if name in evidence.exported_components:
                reasons.append(
                    ScoringReason(
                        "exported component (external invocation)",
                        6,
                        "COMPONENT",
                        name,
                    )
                )

            kind = evidence.component_kind_by_name.get(name, "component")
            for permission in self._kind_permissions(evidence, kind):
                signal = PERMISSION_SIGNALS.get(permission)
                if signal is None:
                    continue
                reasons.append(
                    ScoringReason(
                        f"declared {signal.label}",
                        signal.weight,
                        "PERMISSION",
                        permission,
                    )
                )

            entry = index.find_class(name)
            if entry is not None and entry.descriptor in evidence.boot_receivers:
                reasons.append(
                    ScoringReason(
                        "declared BOOT_COMPLETED receiver",
                        20,
                        "COMPONENT",
                        name,
                    )
                )
            if entry is not None:
                class_mids = [
                    m.mid for m in entry.methods() if m.mid in method_scores
                ]
                if class_mids:
                    top_mid = sorted(
                        class_mids, key=lambda m: -method_scores[m].score
                    )[0]
                    reasons.append(
                        ScoringReason(
                            "class contains top-scored method",
                            8,
                            "BEHAVIOR",
                            top_mid,
                        )
                    )

            reasons = self._dedupe_reasons(reasons)
            if not reasons:
                continue
            scores.append(
                SuspicionScore(
                    target=name,
                    kind=TargetKind.COMPONENT,
                    score=sum(r.weight for r in reasons),
                    reasons=reasons,
                    evidence_refs=self._evidence_refs(reasons),
                )
            )
        return scores

    @staticmethod
    def _kind_permissions(evidence: EvidenceContext, kind: str) -> List[str]:
        categories = _ALLOWED_COMPONENT_PERMISSION_CATEGORIES.get(kind, set())
        found: Set[str] = set()
        for category in categories:
            found.update(evidence.permissions_by_category.get(category, []))
        return sorted(found)[:3]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _finalize(self, scores: List[SuspicionScore]) -> List[SuspicionScore]:
        unique: Dict[tuple, SuspicionScore] = {}
        for score in scores:
            unique.setdefault((score.kind.value, score.target), score)
        cap = int(self.options["max_per_kind"])
        kept: List[SuspicionScore] = []
        for kind in TargetKind:
            kind_scores = sorted(
                (s for s in unique.values() if s.kind is kind),
                key=lambda s: (-s.score, s.target),
            )
            kept.extend(kind_scores[:cap])
        kept.sort(key=lambda s: (-s.score, s.kind.value, s.target))
        return kept

    @staticmethod
    def _resolved_descriptors(index: CodeIndex, names: Set[str]) -> Set[str]:
        descriptors: Set[str] = set()
        for name in names:
            entry = index.find_class(name)
            if entry is not None:
                descriptors.add(entry.descriptor)
        return descriptors

    @staticmethod
    def _method_list(
        method_scores: Dict[str, SuspicionScore]
    ) -> List[SuspicionScore]:
        return [method_scores[mid] for mid in sorted(method_scores.keys())]

    @staticmethod
    def _dedupe_reasons(reasons: List[ScoringReason]) -> List[ScoringReason]:
        seen: Dict[tuple, ScoringReason] = {}
        for reason in reasons:
            key = (reason.label, reason.weight)
            if key not in seen:
                seen[key] = reason
        return sorted(
            seen.values(), key=lambda r: (-r.weight, r.label, r.category)
        )

    @staticmethod
    def _evidence_refs(reasons: List[ScoringReason]) -> List[str]:
        return sorted({r.evidence for r in reasons if r.evidence})[:80]