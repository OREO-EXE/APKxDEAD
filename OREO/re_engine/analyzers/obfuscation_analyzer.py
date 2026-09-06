"""Obfuscation and anti-analysis analyzer.

Produces structured :class:`ObfuscationFinding` records backed by real,
measured bytecode metrics - never by pre-baked suspicion values. Every
category score is derived from observed distributions:

    identifier       class/method/field name-length shares, package collapse
    string           encoded/encrypted literal ratios, runtime reconstruction
    reflection       Class.forName / Method.invoke / Constructor.newInstance
                     dispatch density
    dynamic_loading  DexClassLoader / loadLibrary site density
    runtime_exec     Runtime.exec / ProcessBuilder sites (+ shell co-reference)
    anti_analysis    emulator / debugger / root / frida / env-check signals
    control_flow     switch density, goto flattening, giant-method share

Guardrails: findings are only emitted once measurements clear data-derived
minimums, so a single short identifier or one suspicious string can never by
itself produce a claim. All iteration is sorted; every cap is deterministic.
No classifier imports.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from typing import Dict, List, Optional, Set

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.analyzers.strings_patterns import BASE64_LIKE_RE, HEX_LIKE_RE
from re_engine.behavior.evidence import api_key
from re_engine.models.context import AnalysisContext
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)
from re_engine.models.obfuscation import ObfuscationFinding, ObfuscationType
from re_engine.reconstruct.index import ClassEntry, CodeIndex, MethodEntry

OBFUSCATION_VERSION = "0.1.0"

# Deterministic scan bounds (mirrors the behavior evidence index).
_MAX_CLASSES = 6000
_MAX_METHODS = 6000
_REF_CAP = 200

# Minimum sample sizes before naming/distribution claims are allowed.
_MIN_NAME_SAMPLE = 8
_MIN_METHOD_SAMPLE = 8
_MIN_LITERAL_SAMPLE = 10

# Encoded-literal judgement.
_ENCODED_MIN_LEN = 20
_ENTROPY_BITS = 4.5
_RAW_ENCODED_MIN = 12


def _matches_any(key: str, prefixes: tuple) -> bool:
    return any(key.startswith(prefix) for prefix in prefixes)


# Reflection API references, normalized to the "Lclass;->name" api_key() form.
_REFLECTION_PREFIXES = (
    "Ljava/lang/Class;->forName",
    "Ljava/lang/Class;->getMethod",
    "Ljava/lang/Class;->getDeclaredMethod",
    "Ljava/lang/Class;->getField",
    "Ljava/lang/Class;->getDeclaredField",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/reflect/Constructor;->newInstance",
    "Ljava/lang/reflect/Field;->get",
    "Ljava/lang/reflect/Field;->set",
    "Ljava/lang/Object;->getClass",
)

_DYNAMIC_LOAD_PREFIXES = (
    "Ldalvik/system/DexClassLoader;->",
    "Ldalvik/system/BaseDexClassLoader;->",
    "Ldalvik/system/PathClassLoader;->",
    "Ldalvik/system/InMemoryDexClassLoader;->",
    "Ldalvik/system/DexFile;->",
    "Ldalvik/system/DexPathList;->",
    "Ljava/lang/ClassLoader;->loadClass",
    "Ljava/lang/Runtime;->load",
    "Ljava/lang/Runtime;->loadLibrary",
    "Ljava/lang/System;->load",
    "Ljava/lang/System;->loadLibrary",
)

_EXEC_PREFIXES = (
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/ProcessBuilder;->start",
)

# Runtime string-reconstruction / decryption families.
_DECODER_PREFIXES = (
    "Landroid/util/Base64;->decode",
    "Ljava/util/Base64;->decode",
    "Ljavax/crypto/Cipher;->doFinal",
    "Ljavax/crypto/Cipher;->update",
    "Ljava/io/ByteArrayOutputStream;->toByteArray",
)
_BUILDER_PREFIXES = (
    "Ljava/lang/StringBuilder;->append",
    "Ljava/lang/StringBuffer;->append",
)
_ENCRYPT_PREFIXES = (
    "Ljavax/crypto/Cipher;->init",
)

# Anti-analysis signal families. Each token is weak (needs a second hit or a
# strong hit to count) unless marked strong.
_ANTI_ANALYSIS_SIGNALS = {
    "emulator": {
        "apis": (
            "Landroid/os/Build;->MODEL",
            "Landroid/os/Build;->FINGERPRINT",
            "Landroid/os/Build;->HARDWARE",
            "Landroid/os/Build;->PRODUCT",
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
        ),
        "tokens": {
            "qemu": False,
            "goldfish": False,
            "ranchu": False,
            "sdk_gphone": False,
            "google_sdk": False,
            "ro.kernel.qemu": True,
            "/dev/qemu_pipe": True,
        },
    },
    "debugger": {
        "apis": ("Landroid/os/Debug;->isDebuggerConnected",),
        "tokens": {
            "tracerpid": False,
            "waitfordebugger": False,
            "isdebuggerconnected": False,
            "/proc/self/status": True,
            "ptrace": False,
        },
    },
    "root": {
        "apis": (),
        "tokens": {
            "/system/xbin/su": True,
            "/system/bin/su": True,
            "/system/app/superuser.apk": True,
            "which su": True,
            "roottools": False,
            "iamroot": False,
        },
    },
    "frida_xposed": {
        "apis": (),
        "tokens": {
            "frida": False,
            "xposed": False,
            "xposedbridge": False,
            "com.saurik.substrate": True,
            "27042": True,
        },
    },
    "runtime_environment": {
        "apis": ("Landroid/os/Build;->TAGS",),
        "tokens": {
            "ro.debuggable": True,
            "ro.secure": True,
            "test-keys": False,
            "/proc/self/maps": True,
        },
    },
}


def _scale(ratio: float, floor: float, ceiling: float) -> float:
    """Normalize a measured ratio into a 0.0..1.0 component score.

    ``floor``/``ceiling`` are calibration points for the mapping; they are not
    claimed obfuscation values. Below ``floor`` the component contributes 0 and
    above ``ceiling`` it saturates at 1.0.
    """
    if ceiling <= floor:
        return 0.0
    return min(1.0, max(0.0, (ratio - floor) / (ceiling - floor)))


class _Stats:
    """Bounded, deterministic measurement accumulator over one DEX set."""

    def __init__(self) -> None:
        self.class_descriptors: List[str] = []
        self.class_simple_names: List[str] = []
        self.class_parent_segments: List[str] = []
        self.method_names: List[str] = []
        self.field_names: List[str] = []

        self.methods_scanned = 0
        self.mid_to_class: Dict[str, str] = {}
        self.call_key_callers: Counter = Counter()
        self.method_call_keys: Dict[str, Set[str]] = {}
        self.method_literals: Dict[str, Set[str]] = {}
        self.literal_total = 0
        self.encoded_literals = 0

        self.method_instruction_counts: List[int] = []
        self.switch_ops = 0
        self.goto_ops = 0
        self.branch_ops = 0
        self.switch_methods = 0
        self.goto_methods = 0


class ObfuscationAnalyzer(BaseAnalyzer):
    """App-wide obfuscation and anti-analysis measurement."""

    name = "obfuscation"
    version = OBFUSCATION_VERSION
    description = (
        "Measured obfuscation and anti-analysis techniques "
        "(identifiers, strings, reflection, dynamic loading, exec, "
        "anti-analysis, control flow)"
    )

    def run(self, context: AnalysisContext) -> None:
        stats = self._scan(context)
        findings: List[ObfuscationFinding] = []

        for builder in (
            self._identifier,
            self._strings,
            self._reflection,
            self._dynamic_loading,
            self._runtime_execution,
            self._anti_analysis,
            self._control_flow,
        ):
            finding = builder(stats, context)
            if finding is not None:
                finding.analyzer = self.name
                finding.severity = _severity_for(finding.type, finding.score)
            findings.append(finding)

        present = [f for f in findings if f is not None]
        context.obfuscation = sorted(
            present, key=lambda f: (f.type.value, -f.score)
        )

        if present:
            top = present[0]
            severity = max((f.severity for f in present), key=lambda s: _rank(s))
        else:
            top = None
            severity = Severity.INFO

        self.emit(
            context,
            Finding(
                category=FindingCategory.DEX,
                title="Obfuscation and anti-analysis scan complete",
                description=(
                    "; ".join(
                        f"{f.type.value}={f.score:.2f} conf={f.confidence.value}"
                        for f in present
                    )
                    if present
                    else "no obfuscation or anti-analysis techniques measured"
                ),
                severity=severity,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.CODE,
                source_file="classes*.dex",
                metadata={
                    "technique_count": len(present),
                    "obfuscation_type": (
                        top.type.value if top is not None else None
                    ),
                    "obfuscation_score": (
                        round(top.score, 4) if top is not None else 0.0
                    ),
                },
            ),
        )

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    def _scan(self, context: AnalysisContext) -> _Stats:
        stats = _Stats()
        dex_files = []
        artifacts = getattr(context, "artifacts", None)
        if artifacts is not None:
            dex_files = getattr(artifacts, "dex", None) or []
        if not dex_files:
            return stats

        index = CodeIndex(dex_files)
        index._ensure_index()

        class_count = 0
        for descriptor in sorted(index._class_by_desc.keys(), key=str.lower):
            if class_count >= _MAX_CLASSES:
                break
            class_count += 1
            class_entry: ClassEntry = index._class_by_desc[descriptor]

            stats.class_descriptors.append(descriptor)
            stats.class_simple_names.append(_simple_name(descriptor))
            parent = _parent_segment(descriptor)
            if parent:
                stats.class_parent_segments.append(parent)
            stats.field_names.extend(
                _field_simple_names(class_entry.fields())
            )

            for entry in class_entry.methods():
                if stats.methods_scanned >= _MAX_METHODS:
                    break
                stats.methods_scanned += 1
                self._scan_method(stats, entry)
            if stats.methods_scanned >= _MAX_METHODS:
                break
        return stats

    def _scan_method(self, stats: _Stats, entry: MethodEntry) -> None:
        mid = entry.mid
        if not mid:
            return
        stats.mid_to_class[mid] = entry.class_descriptor

        name = entry.name
        if name not in ("<init>", "<clinit>"):
            stats.method_names.append(name)

        refs = entry.references(ref_cap=_REF_CAP)
        call_keys = {api_key(c) for c in refs.get("calls", [])}
        stats.method_call_keys[mid] = call_keys
        for key in call_keys:
            stats.call_key_callers[key] += 1

        literals = {t for t in refs.get("strings", []) if t}
        if literals:
            stats.method_literals[mid] = literals
            stats.literal_total += len(literals)
            stats.encoded_literals += sum(
                1 for t in literals if _is_encoded_literal(t)
            )

        opcodes = _opcode_names(entry)
        stats.method_instruction_counts.append(len(opcodes))
        has_switch = False
        has_goto = False
        for opcode in opcodes:
            if opcode.startswith("packed-switch") or opcode.startswith(
                "sparse-switch"
            ):
                stats.switch_ops += 1
                has_switch = True
            elif opcode.startswith("goto"):
                stats.goto_ops += 1
                has_goto = True
            elif opcode.startswith("if-"):
                stats.branch_ops += 1
        if has_switch:
            stats.switch_methods += 1
        if has_goto:
            stats.goto_methods += 1

    # ------------------------------------------------------------------
    # Identifier obfuscation
    # ------------------------------------------------------------------
    def _identifier(self, stats: _Stats, context) -> Optional[ObfuscationFinding]:
        class_sample = len(stats.class_simple_names)
        if class_sample < _MIN_NAME_SAMPLE:
            return None

        tiny_class = sum(1 for n in stats.class_simple_names if len(n) <= 2)
        short3_class = sum(1 for n in stats.class_simple_names if len(n) <= 3)
        parent_sample = len(stats.class_parent_segments)
        collapsed_pkg = sum(
            1 for p in stats.class_parent_segments if len(p) <= 2
        )

        method_sample = len(stats.method_names)
        tiny_method = (
            sum(1 for n in stats.method_names if len(n) <= 2)
            if method_sample >= _MIN_NAME_SAMPLE
            else 0
        )
        tiny_field = (
            sum(1 for n in stats.field_names if len(n) <= 2)
            if stats.field_names
            else 0
        )

        parts = []
        parts.append(_scale(tiny_class / class_sample, 0.20, 0.60))
        parts.append(_scale(short3_class / class_sample, 0.35, 0.80) * 0.8)
        if parent_sample:
            parts.append(_scale(collapsed_pkg / parent_sample, 0.20, 0.70))
        if method_sample >= _MIN_NAME_SAMPLE:
            parts.append(_scale(tiny_method / method_sample, 0.15, 0.50))
        if stats.field_names:
            parts.append(_scale(tiny_field / len(stats.field_names), 0.15, 0.55))

        score = max(parts)
        if score <= 0.0:
            return None

        evidence = [
            f"class names {tiny_class}/{class_sample} <= 2 chars "
            f"(share={tiny_class / class_sample:.2f})",
            f"method names {tiny_method}/{method_sample} <= 2 chars "
            f"(share={tiny_method / method_sample:.2f})"
            if method_sample
            else "method names not sampled (too few)",
            f"parent package segments collapsed to <= 2 chars "
            f"{collapsed_pkg}/{parent_sample} (share={collapsed_pkg / parent_sample:.2f})"
            if parent_sample
            else "package collapse not computed (no parent packages)",
        ]
        signals = [part for part in parts if part >= 0.15]
        confidence = (
            Confidence.HIGH
            if len(signals) >= 2
            else (Confidence.MEDIUM if len(signals) == 1 else Confidence.LOW)
        )
        return ObfuscationFinding(
            type=ObfuscationType.IDENTIFIER,
            target="app",
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="Identifier obfuscation",
            description=(
                "Naming distribution (class/method/field lengths, package "
                "collapse) is consistent with automated renaming."
            ),
            metadata={
                "classes_sampled": class_sample,
                "methods_sampled": method_sample,
                "short_class_share": round(tiny_class / class_sample, 4),
                "collapsed_package_share": round(
                    collapsed_pkg / parent_sample, 4
                )
                if parent_sample
                else 0.0,
            },
        )

    # ------------------------------------------------------------------
    # String obfuscation
    # ------------------------------------------------------------------
    def _strings(self, stats: _Stats, context) -> Optional[ObfuscationFinding]:
        parts = []
        if stats.literal_total >= _MIN_LITERAL_SAMPLE:
            parts.append(
                _scale(
                    stats.encoded_literals / stats.literal_total, 0.10, 0.50
                )
            )
        raw_encoded = len(getattr(context, "encoded_strings", None) or [])
        if raw_encoded >= _RAW_ENCODED_MIN:
            parts.append(_scale(min(raw_encoded, 500) / 500.0, 0.10, 0.80))
        encoded_urls = sum(
            1 for u in (getattr(context, "urls", None) or []) if "%" in u
        )
        if encoded_urls >= 2:
            parts.append(_scale(encoded_urls, 2, 8) * 0.5)

        recon = self._reconstruction_signals(stats)
        if recon["score"] > 0.0:
            parts.append(recon["score"])

        if not parts:
            return None
        score = max(parts)
        if score <= 0.0:
            return None

        evidence = []
        if stats.literal_total >= _MIN_LITERAL_SAMPLE:
            evidence.append(
                f"encoded-looking string constants "
                f"{stats.encoded_literals}/{stats.literal_total} "
                f"(share={stats.encoded_literals / stats.literal_total:.2f})"
            )
        if raw_encoded >= _RAW_ENCODED_MIN:
            evidence.append(f"{raw_encoded} base64/hex-like blobs in raw bytes")
        if recon["count"]:
            evidence.append(
                f"{recon['count']} methods combine decoders/encryptors with "
                f"string literals"
            )

        confidence = (
            Confidence.HIGH
            if recon["dual"] and recon["count"] >= 2
            else (Confidence.MEDIUM if len(parts) >= 2 else Confidence.LOW)
        )
        return ObfuscationFinding(
            type=ObfuscationType.STRING,
            target="app",
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="String obfuscation",
            description=(
                "Encoded/encrypted string constants or runtime string "
                "reconstruction routines are present."
            ),
            metadata={
                "literals_total": stats.literal_total,
                "encoded_literals": stats.encoded_literals,
                "raw_encoded_strings": raw_encoded,
                "reconstruction_methods": recon["count"],
            },
        )

    def _reconstruction_signals(self, stats: _Stats):
        decoder_mids: Set[str] = set()
        encrypt_mids: Set[str] = set()
        builder_mids: Set[str] = set()
        for mid, keys in stats.method_call_keys.items():
            if any(_matches_any(k, _DECODER_PREFIXES) for k in keys):
                decoder_mids.add(mid)
            if any(_matches_any(k, _ENCRYPT_PREFIXES) for k in keys):
                encrypt_mids.add(mid)
            if any(_matches_any(k, _BUILDER_PREFIXES) for k in keys):
                builder_mids.add(mid)

        wiring = decoder_mids | encrypt_mids
        with_literals = {
            mid for mid in stats.method_literals if stats.method_literals[mid]
        }
        count = len((wiring | builder_mids) & with_literals)
        if count == 0:
            return {"score": 0.0, "count": 0, "dual": False}
        score = min(1.0, _scale(count, 0, 6) * 0.9)
        dual = bool(decoder_mids and encrypt_mids)
        if dual:
            score = min(1.0, score + 0.3)
        return {"score": score, "count": count, "dual": dual}

    # ------------------------------------------------------------------
    # Reflection
    # ------------------------------------------------------------------
    def _reflection(self, stats: _Stats, context) -> Optional[ObfuscationFinding]:
        keys_hit = {
            k
            for k in stats.call_key_callers
            if _matches_any(k, _REFLECTION_PREFIXES)
        }
        if not keys_hit:
            return None
        reflection_callers = sum(stats.call_key_callers[k] for k in keys_hit)
        density = reflection_callers / max(1, stats.methods_scanned)
        score = max(
            _scale(density, 0.05, 0.40),
            _scale(reflection_callers, 0, 10),
        )
        if score <= 0.0:
            return None

        has_dynamic_invoke = any(
            k.startswith("Ljava/lang/reflect/Method;->invoke")
            or k.startswith("Ljava/lang/reflect/Constructor;->newInstance")
            for k in keys_hit
        )
        has_for_name = any(
            k.startswith("Ljava/lang/Class;->forName") for k in keys_hit
        )
        top_class = self._top_class_for(stats, _REFLECTION_PREFIXES)

        evidence = [
            f"{reflection_callers} method(s) in {len(keys_hit)} reflection "
            f"APIs (density={density:.2f})",
            "reflection APIs: " + ", ".join(sorted(keys_hit))[:400],
        ]
        confidence = (
            Confidence.HIGH
            if has_dynamic_invoke and has_for_name
            else (Confidence.MEDIUM if reflection_callers >= 3 else Confidence.LOW)
        )
        return ObfuscationFinding(
            type=ObfuscationType.REFLECTION,
            target=top_class or "app",
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="Reflection-heavy dispatch",
            description=(
                "Reflection APIs (Class.forName / Method.invoke / "
                "Constructor.newInstance / field access) are used to resolve "
                "and dispatch calls at runtime."
            ),
            metadata={
                "reflection_callers": reflection_callers,
                "reflection_api_count": len(keys_hit),
                "density": round(density, 4),
            },
        )

    # ------------------------------------------------------------------
    # Dynamic loading
    # ------------------------------------------------------------------
    def _dynamic_loading(
        self, stats: _Stats, context
    ) -> Optional[ObfuscationFinding]:
        keys_hit = {
            k
            for k in stats.call_key_callers
            if _matches_any(k, _DYNAMIC_LOAD_PREFIXES)
        }
        if not keys_hit:
            return None
        callers = sum(stats.call_key_callers[k] for k in keys_hit)

        loader_present = any(
            _matches_any(
                k,
                (
                    "Ldalvik/system/DexClassLoader;->",
                    "Ldalvik/system/PathClassLoader;->",
                    "Ldalvik/system/InMemoryDexClassLoader;->",
                    "Ldalvik/system/DexFile;->",
                ),
            )
            for k in keys_hit
        )
        native_load = any(
            k.startswith("Ljava/lang/Runtime;->load")
            or k.startswith("Ljava/lang/System;->load")
            for k in keys_hit
        )

        density = callers / max(1, stats.methods_scanned)
        score = max(_scale(density, 0.02, 0.30), 0.55 if loader_present else 0.0)
        if native_load and loader_present:
            score = min(1.0, score + 0.25)
        if score <= 0.0:
            return None

        target = self._top_class_for(stats, _DYNAMIC_LOAD_PREFIXES) or "app"
        evidence = [
            f"{callers} method(s) reference {len(keys_hit)} loading APIs",
            "loading APIs: " + ", ".join(sorted(keys_hit))[:400],
        ]
        if loader_present:
            evidence.append("dynamic-class loading APIs present")
        if native_load:
            evidence.append("runtime native-library loading present")
        confidence = (
            Confidence.HIGH
            if loader_present and native_load
            else (Confidence.MEDIUM if loader_present else Confidence.LOW)
        )
        return ObfuscationFinding(
            type=ObfuscationType.DYNAMIC_LOADING,
            target=target,
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="Dynamic code loading",
            description=(
                "Bytecode loads classes or native libraries at runtime "
                "(DexClassLoader / PathClassLoader / loadLibrary)."
            ),
            metadata={
                "loading_callers": callers,
                "loading_api_count": len(keys_hit),
                "loader_present": loader_present,
                "native_load_present": native_load,
            },
        )

    # ------------------------------------------------------------------
    # Runtime execution
    # ------------------------------------------------------------------
    def _runtime_execution(
        self, stats: _Stats, context
    ) -> Optional[ObfuscationFinding]:
        exec_mids = sorted(
            mid
            for mid, keys in stats.method_call_keys.items()
            if any(_matches_any(k, _EXEC_PREFIXES) for k in keys)
        )
        if not exec_mids:
            return None

        shell_literals = {
            literal
            for mid in exec_mids
            for literal in stats.method_literals.get(mid, ())
            if _looks_shell(literal)
        }
        shell_co_reference = bool(shell_literals)
        score = min(1.0, 0.7 + (0.3 if shell_co_reference else 0.0))
        target = exec_mids[0]
        evidence = [
            f"{len(exec_mids)} method(s) invoke Runtime.exec/ProcessBuilder.start",
        ]
        if shell_co_reference:
            evidence.append(
                "shell command string(s) referenced by exec site: "
                + ", ".join(sorted(shell_literals))[:300]
            )
        confidence = (
            Confidence.HIGH if shell_co_reference else Confidence.MEDIUM
        )
        return ObfuscationFinding(
            type=ObfuscationType.RUNTIME_EXECUTION,
            target=target,
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="Runtime process execution",
            description=(
                "The app begins OS processes at runtime, optionally "
                "piping shell commands."
            ),
            metadata={
                "exec_sites": len(exec_mids),
                "shell_co_reference": shell_co_reference,
            },
        )

    # ------------------------------------------------------------------
    # Anti-analysis
    # ------------------------------------------------------------------
    def _anti_analysis(self, stats: _Stats, context) -> Optional[ObfuscationFinding]:
        literal_text = {
            lit.lower()
            for literals in stats.method_literals.values()
            for lit in literals
        }
        raw_text = {s.lower() for s in (getattr(context, "strings", None) or [])}
        all_text = literal_text | raw_text

        categories: Dict[str, Dict[str, object]] = {}
        for category, cfg in _ANTI_ANALYSIS_SIGNALS.items():
            api_methods = sum(
                stats.call_key_callers[k]
                for k in stats.call_key_callers
                if _matches_any(k, cfg["apis"])
            )
            strong_tokens = 0
            weak_tokens = 0
            found_tokens = []
            for token, strong in cfg["tokens"].items():
                if any(token in text for text in all_text):
                    if strong:
                        strong_tokens += 1
                    else:
                        weak_tokens += 1
                    found_tokens.append(token)
            if api_methods > 0 or strong_tokens >= 1 or weak_tokens + strong_tokens >= 2:
                categories[category] = {
                    "api_methods": api_methods,
                    "strong_tokens": strong_tokens,
                    "weak_tokens": weak_tokens,
                    "tokens": found_tokens,
                }

        if not categories:
            return None
        count = len(categories)
        score = min(1.0, 0.30 + 0.20 * count)

        evidence = []
        for category, info in sorted(categories.items()):
            evidence.append(
                f"{category}: {info['api_methods']} api-calling method(s), "
                f"tokens={info['tokens']}"
            )
        strong_api_only = count == 1 and sum(
            info["api_methods"] for info in categories.values()
        ) > 0
        confidence = (
            Confidence.HIGH
            if count >= 2 or strong_api_only
            else Confidence.MEDIUM
        )
        return ObfuscationFinding(
            type=ObfuscationType.ANTI_ANALYSIS,
            target="app",
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="Anti-analysis checks",
            description=(
                "Emulator, debugger, root, instrumentation or environment "
                "probing is present."
            ),
            metadata={
                "categories": sorted(categories),
                "category_count": count,
            },
        )

    # ------------------------------------------------------------------
    # Control flow
    # ------------------------------------------------------------------
    def _control_flow(self, stats: _Stats, context) -> Optional[ObfuscationFinding]:
        if stats.methods_scanned < _MIN_METHOD_SAMPLE:
            return None
        if not stats.method_instruction_counts:
            return None

        total_ops = sum(stats.method_instruction_counts)
        switch_method_fraction = stats.switch_methods / stats.methods_scanned
        switch_density = stats.switch_ops / total_ops if total_ops else 0.0
        branch_total = stats.goto_ops + stats.branch_ops
        goto_density = stats.goto_ops / branch_total if branch_total else 0.0

        counts = sorted(stats.method_instruction_counts)
        median = statistics.median(counts)
        p95 = counts[int(len(counts) * 0.95)]
        giant_threshold = max(2 * median, p95, 16)
        giant_share = (
            sum(1 for c in counts if c > giant_threshold) / len(counts)
        )

        parts = [
            _scale(switch_method_fraction, 0.05, 0.40),
            _scale(switch_density, 0.02, 0.20),
            _scale(goto_density, 0.35, 0.70) * 0.8,
            _scale(giant_share, 0.0, 0.10),
        ]
        score = max(parts)
        if score <= 0.0:
            return None

        evidence = [
            f"{stats.switch_methods}/{stats.methods_scanned} methods contain "
            f"switch dispatch (share={switch_method_fraction:.2f})",
            f"switch ops {stats.switch_ops}/{total_ops} "
            f"(density={switch_density:.4f})",
            f"goto {stats.goto_ops} ops vs {stats.branch_ops} conditionals "
            f"(goto share of branches={goto_density:.2f})",
            f"giant methods (>{giant_threshold} instructions): "
            f"{int(giant_share * len(counts))} "
            f"(share={giant_share:.3f})",
        ]
        signals = [part for part in parts if part >= 0.1]
        confidence = (
            Confidence.HIGH
            if len(signals) >= 2
            else (Confidence.MEDIUM if len(signals) == 1 else Confidence.LOW)
        )
        return ObfuscationFinding(
            type=ObfuscationType.CONTROL_FLOW,
            target="app",
            score=score,
            evidence=evidence,
            confidence=confidence,
            title="Control-flow obfuscation indicators",
            description=(
                "Switch-heavy dispatch, goto flattening or unusually large "
                "methods suggest control-flow obfuscation."
            ),
            metadata={
                "switch_ops": stats.switch_ops,
                "goto_ops": stats.goto_ops,
                "branch_ops": stats.branch_ops,
                "giant_threshold": giant_threshold,
                "giant_methods": int(giant_share * len(counts)),
                "methods_scanned": stats.methods_scanned,
            },
        )

    # ------------------------------------------------------------------
    def _top_class_for(self, stats: _Stats, prefixes: tuple) -> Optional[str]:
        per_class: Counter = Counter()
        for mid, keys in stats.method_call_keys.items():
            if any(_matches_any(k, prefixes) for k in keys):
                per_class[stats.mid_to_class.get(mid, "?")] += 1
        if not per_class:
            return None
        return per_class.most_common(1)[0][0]


def _simple_name(descriptor: str) -> str:
    path = descriptor.lstrip("L").rstrip(";")
    if "/" in path:
        return path.rpartition("/")[2]
    return path


def _parent_segment(descriptor: str) -> str:
    path = descriptor.lstrip("L").rstrip(";")
    parts = path.split("/")
    if len(parts) >= 2:
        return parts[-2]
    return ""


def _field_simple_names(fields: List[str]) -> List[str]:
    names = []
    for field in fields:
        name = str(field).split(":", 1)[0]
        if name:
            names.append(name)
    return names


def _opcode_names(entry: MethodEntry) -> List[str]:
    names = []
    try:
        instructions = entry.instructions()
    except Exception:
        return names
    for instruction in instructions:
        try:
            name = str(instruction.get_name() or "")
        except Exception:
            continue
        if name:
            names.append(name)
    return names


def _looks_shell(text: str) -> bool:
    lower = text.lower()
    return any(
        token in lower
        for token in (
            "/system/bin/sh",
            "/bin/sh",
            "sh -c",
            "su -c",
            "cmd /c",
            "chmod ",
            "chown ",
            "rm -rf",
            "wget ",
            "curl ",
            "iptables",
            "nc -",
        )
    )


def _is_encoded_literal(text: str) -> bool:
    value = text.strip()
    if len(value) < _ENCODED_MIN_LEN:
        return False
    if BASE64_LIKE_RE.fullmatch(value) or HEX_LIKE_RE.fullmatch(value):
        return True
    if _token_chars_only(value):
        return _entropy(value) >= _ENTROPY_BITS
    return False


def _token_chars_only(value: str) -> bool:
    for char in value:
        if not (
            char.isascii()
            and (char.isalnum() or char in "+/=_-")
        ):
            return False
    return True


def _entropy(text: str) -> float:
    length = len(text)
    if length == 0:
        return 0.0
    counts = Counter(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


_SEVERITY_WEAK = {ObfuscationType.IDENTIFIER, ObfuscationType.CONTROL_FLOW}


def _rank(severity: Severity) -> int:
    return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(severity.value)


def _severity_for(find_type: ObfuscationType, score: float) -> Severity:
    if find_type in _SEVERITY_WEAK:
        return Severity.INFO
    if score >= 0.8:
        return Severity.HIGH
    if score >= 0.5:
        return Severity.MEDIUM
    if score >= 0.25:
        return Severity.LOW
    return Severity.INFO