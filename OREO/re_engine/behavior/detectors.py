"""Per-behavior detectors: derive evidence-backed behavioral statuses.

Each detector takes a :class:`~re_engine.behavior.specs.BehaviorSpec` and an
:class:`~re_engine.behavior.evidence.EvidenceContext` and returns a
:class:`Detection`. The status rules are deliberately conservative:

    TRUE     only when a concrete, directly observed evidence chain exists
             (bytecode API calls, manifest components, same-method
             co-occurrence for chained dynamic behaviors).
    UNKNOWN  when only *permissive* evidence exists (e.g. a permission is
             granted, or two signals exist app-wide but their link is not
             proven). UNKNOWN is never promoted to TRUE.
    FALSE    everything else (no relevant evidence within scan bounds).

Every claim records its evidence refs, related methods/classes, relevant
permissions and linked data flows so it stays traceable back to the APK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from re_engine.behavior.evidence import EvidenceContext
from re_engine.behavior.models import BehaviorStatus
from re_engine.behavior.specs import BehaviorSpec

# A method is "giant" when its instruction count suggests flattened control
# flow (a common trait of commercial obfuscators).
_GIANT_METHOD_THRESHOLD = 2000

_NETWORK_FETCH_PREFIXES = (
    "Ljava/net/URL;->openStream",
    "Ljava/net/URL;->openConnection",
    "Ljava/net/HttpURLConnection",
    "Lorg/apache/http/",
    "Lokhttp3/OkHttpClient",
    "Lcom/squareup/okhttp/OkHttpClient",
)

_DEX_LOADER_PREFIXES = (
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/InMemoryDexClassLoader",
    "Ldalvik/system/PathClassLoader",
)


@dataclass
class Detection:
    """Output of one behavior detector."""

    status: BehaviorStatus
    confidence: str
    explanation: str
    evidence_refs: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    data_flows: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def _present_permissions(spec: BehaviorSpec, ctx: EvidenceContext) -> List[str]:
    if not spec.permissions:
        return []
    return ctx.present_permissions(spec.permissions)


def _api_evidence(prefix: str, methods: List[str]) -> List[str]:
    return [f"api:{prefix}@{mid}" for mid in methods]


def _field_evidence(prefix: str, methods: List[str]) -> List[str]:
    return [f"field:{prefix}@{mid}" for mid in methods]


def _string_evidence(text: str, methods: List[str]) -> List[str]:
    return [f"string:{text!r}@{mid}" for mid in methods]


def _class_evidence(prefix: str, methods: List[str]) -> List[str]:
    return [f"class:{prefix}@{mid}" for mid in methods]


def _manifest_evidence(kind: str, name: str, detail: str = "") -> List[str]:
    suffix = f"@{detail}" if detail else ""
    return [f"manifest:{kind}:{name}{suffix}"]


def _mid_label(mid: str) -> str:
    return mid


def _code_methods(
    spec: BehaviorSpec, ctx: EvidenceContext
) -> Dict[str, Set[str]]:
    """Methods evidencing each evidence bucket for a spec."""
    calls: Set[str] = set()
    for prefix in spec.call_prefixes:
        calls.update(ctx.api_mids(prefix))
    fields: Set[str] = set()
    for prefix in spec.field_prefixes:
        fields.update(ctx.field_mids(prefix))
    classes: Set[str] = set()
    for prefix in spec.class_prefixes:
        classes.update(ctx.class_mids(prefix))
    for prefix in spec.field_prefixes:
        classes.update(ctx.class_mids(prefix))
    strings: Set[str] = set()
    for text in spec.strings:
        strings.update(ctx.string_mids(text))
    return {"calls": calls, "fields": fields, "classes": classes, "strings": strings}


def _collect_evidence(spec: BehaviorSpec, bucket: str, methods: List[str]) -> List[str]:
    if bucket == "calls":
        return [f"api:{spec.call_prefixes[0] if spec.call_prefixes else '?'}@{m}" for m in methods]
    if bucket == "fields":
        return [f"field:@{m}" for m in methods]
    if bucket == "classes":
        return [f"class:@{m}" for m in methods]
    return [f"string:@{m}" for m in methods]


# ---------------------------------------------------------------------------
# PERSISTENCE
# ---------------------------------------------------------------------------
def _boot_completion(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    received = [p for p in spec.permissions if ctx.has_permission(p)]
    receivers = ctx.boot_receivers
    if receivers:
        evidence = []
        for name in receivers[:8]:
            evidence.extend(_manifest_evidence("boot_receiver", name, "BOOT_COMPLETED"))
        return Detection(
            BehaviorStatus.TRUE, "high",
            f"Manifest declares receiver(s) {', '.join(receivers[:8])} for "
            "android.intent.action.BOOT_COMPLETED, so the app runs on every boot.",
            evidence, permissions=received,
        )
    if received or ctx.substring_mids("android.intent.action.BOOT_COMPLETED"):
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "RECEIVE_BOOT_COMPLETED is granted (or the action string appears in "
            "code) but no manifest receiver registers for BOOT_COMPLETED.",
            evidence_refs=[f"permission:{p}" for p in received], permissions=received,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No boot-completion receiver and no RECEIVE_BOOT_COMPLETED evidence.",
    )


def _foreground_service(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    perms = _present_permissions(spec, ctx)
    fg = ctx.foreground_services
    if fg:
        evidence = []
        for name in fg[:8]:
            evidence.extend(_manifest_evidence("foreground_service", name))
        return Detection(
            BehaviorStatus.TRUE, "high",
            f"Service(s) {', '.join(fg[:8])} declare a foreground service type.",
            evidence, permissions=perms,
        )
    starters = ctx.api_mids("Landroid/app/Service;->startForeground")
    if starters:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "A Service invokes startForeground, running persistently with a "
            "foreground notification.",
            _api_evidence("Landroid/app/Service;->startForeground", starters),
            starters,
        )
    if perms and ctx.services:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "FOREGROUND_SERVICE is granted and services exist, but no "
            "startForeground call or foreground service type was observed.",
            permissions=perms,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No foreground-service declaration or startForeground call observed.",
    )


def _background_service(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    services = ctx.services
    if services:
        evidence = []
        for name in services[:8]:
            evidence.extend(_manifest_evidence("service", name))
        return Detection(
            BehaviorStatus.TRUE, "medium",
            f"Service component(s) {', '.join(services[:8])} are declared and can "
            "run user-visible background work.",
            evidence,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No service components declared.",
    )


def _scheduled_jobs(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    perms = _present_permissions(spec, ctx)
    methods: Set[str] = set()
    evidence: List[str] = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "The Android job scheduler API is used (JobScheduler/JobInfo/JobService).",
            evidence, sorted(methods, key=str.lower), permissions=perms,
        )
    if perms:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "BIND_JOB_SERVICE is declared but no job API call was observed.",
            permissions=perms,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No scheduled-job API usage or declaration observed.",
    )


def _alarms(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence: List[str] = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "AlarmManager schedules one-shot or repeating alarms for later execution.",
            evidence, sorted(methods, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No AlarmManager scheduling observed.",
    )


def _device_admin(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    admins = ctx.device_admin_components
    if admins:
        evidence = []
        for name in admins[:8]:
            evidence.extend(
                _manifest_evidence("device_admin", name, "BIND_DEVICE_ADMIN")
            )
        return Detection(
            BehaviorStatus.TRUE, "high",
            f"Receiver(s) {', '.join(admins[:8])} can be activated as a device "
            "administrator (lock/wipe/policy control).",
            evidence,
        )
    perms = _present_permissions(spec, ctx)
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "DevicePolicyManager is used to manage device-administrator policy.",
            evidence, sorted(methods, key=str.lower), permissions=perms,
        )
    if perms:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "BIND_DEVICE_ADMIN permission is declared but no admin receiver or "
            "DevicePolicyManager usage was observed.",
            permissions=perms,
        )
    return Detection(BehaviorStatus.FALSE, "medium", "No device-admin evidence observed.")


def _accessibility(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    components = ctx.accessibility_components
    if components:
        evidence = []
        for name in components[:8]:
            evidence.extend(
                _manifest_evidence(
                    "accessibility_service", name, "BIND_ACCESSIBILITY_SERVICE"
                )
            )
        return Detection(
            BehaviorStatus.TRUE, "high",
            f"Service(s) {', '.join(components[:8])} declare accessibility-service "
            "capabilities (screen/UI event access).",
            evidence,
        )
    perms = _present_permissions(spec, ctx)
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Accessibility APIs are used to read screen content or UI events.",
            evidence, sorted(methods, key=str.lower), permissions=perms,
        )
    if perms:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "BIND_ACCESSIBILITY_SERVICE permission is declared but no "
            "accessibility service or event-reading API was observed.",
            permissions=perms,
        )
    return Detection(BehaviorStatus.FALSE, "medium", "No accessibility-service evidence observed.")


# ---------------------------------------------------------------------------
# DATA COLLECTION (generic: direct API/class/string/field evidence)
# ---------------------------------------------------------------------------
def _data_collection(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    buckets = _code_methods(spec, ctx)
    all_methods = set()
    evidence: List[str] = []
    ordered = [("calls", spec.call_prefixes), ("fields", spec.field_prefixes),
               ("classes", spec.class_prefixes), ("strings", spec.strings)]
    for bucket, sources in ordered:
        methods = buckets[bucket]
        if not methods:
            continue
        all_methods.update(methods)
        if bucket == "calls":
            prefix = sources[0] if sources else "?"
            evidence.extend(_api_evidence(prefix, sorted(methods, key=str.lower)))
        elif bucket == "fields":
            prefix = sources[0] if sources else "?"
            evidence.extend(_field_evidence(prefix, sorted(methods, key=str.lower)))
        elif bucket == "classes":
            prefix = sources[0] if sources else "?"
            evidence.extend(_class_evidence(prefix, sorted(methods, key=str.lower)))
        else:
            evidence.extend(f"string:@{m}" for m in sorted(methods, key=str.lower))

    data_flows = ctx.linked_data_flows(spec.dataflow_sources)
    perms = _present_permissions(spec, ctx)
    if all_methods:
        confidence = "high" if data_flows else "medium"
        flow_note = (
            f" Collected data reaches a sink ({', '.join(data_flows[:4])})."
            if data_flows else ""
        )
        return Detection(
            BehaviorStatus.TRUE, confidence,
            f"{spec.name}: APIs constructively read sensitive data "
            f"({', '.join(sorted(set(method.split('->')[0] for method in all_methods))[:4])})."
            + flow_note,
            evidence, sorted(all_methods, key=str.lower), permissions=perms,
            data_flows=data_flows,
        )
    if perms and spec.permission_implies_unknown:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            f"{spec.name}: the capability ({', '.join(perms)}) is granted but no "
            "data-reading code path was observed.",
            [f"permission:{p}" for p in perms], permissions=perms,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        f"{spec.name}: no evidence observed.",
    )


# ---------------------------------------------------------------------------
# COMMAND EXECUTION
# ---------------------------------------------------------------------------
def _command_execution(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence: List[str] = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Runtime.exec / ProcessBuilder launches external processes "
            "(shell commands).",
            evidence, sorted(methods, key=str.lower),
        )
    if ctx.shell_commands:
        cmds = ctx.shell_commands[:4]
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Shell-command string literals are present "
            f"({', '.join(cmds)}) but no exec API call was observed.",
            [f"string:{repr(c)}" for c in cmds],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No process-launching API or shell command evidence observed.",
    )


def _native_execution(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    load: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        load.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    native = set(ctx.evidence.native_mids)
    if native and load:
        methods = sorted(native | load, key=str.lower)
        return Detection(
            BehaviorStatus.TRUE, "high",
            "Native (JNI) methods are declared and native libraries are loaded.",
            [f"native:@{m}" for m in sorted(native, key=str.lower)] + evidence,
            methods,
        )
    if native or load:
        methods = sorted((native | load), key=str.lower)
        confidence = "medium"
        return Detection(
            BehaviorStatus.TRUE, confidence,
            "Native code execution is wired up (JNI methods or loadLibrary calls).",
            [f"native:@{m}" for m in sorted(native, key=str.lower)] + evidence,
            methods,
        )
    if ctx.native_libraries:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Native libraries are shipped but no loadLibrary call or JNI method "
            "was observed; loading cannot be proven statically.",
            [f"native_lib:{lib}" for lib in sorted(ctx.native_libraries)[:8]],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No native loading or JNI method evidence observed.",
    )


# ---------------------------------------------------------------------------
# DYNAMIC BEHAVIOR
# ---------------------------------------------------------------------------
def _reflection(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Reflection APIs (Class.forName/Method.invoke/ClassLoader.loadClass) "
            "resolve behavior at runtime.",
            evidence, sorted(methods, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No reflection API usage observed.",
    )


def _class_loading(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    for prefix in ("Ldalvik/system/DexClassLoader", "Ldalvik/system/InMemoryDexClassLoader"):
        mids = ctx.class_mids(prefix)
        methods.update(mids)
        evidence.extend(_class_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "high",
            "DEX bytecode is loaded at runtime via DexClassLoader / "
            "InMemoryDexClassLoader, which can defeat static inspection.",
            evidence, sorted(methods, key=str.lower),
        )
    path = ctx.api_mids("Ldalvik/system/PathClassLoader;-><init>")
    if path:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Only the standard PathClassLoader construction is present; dynamic "
            "loading of extra DEX cannot be proven.",
            _api_evidence("Ldalvik/system/PathClassLoader;-><init>", path),
            path,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No dynamic DEX class loading observed.",
    )


def _encrypted_payload(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    crypto = (
        "Ljavax/crypto/Cipher;->",
        "Ljavax/crypto/SecretKey",
        "Landroid/security/keystore/",
    )
    dex = _DEX_LOADER_PREFIXES
    co_located = ctx.same_method(call_prefixes=crypto, class_prefixes=dex)
    if co_located:
        methods = sorted(co_located, key=str.lower)
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "A single method both uses crypto (decrypt/deciphering) and constructs "
            "a DEX class loader - consistent with an encrypted payload being "
            "decrypted then loaded.",
            [f"co-located:@{m}" for m in methods], methods,
        )
    crypto_mids = set()
    for prefix in crypto:
        crypto_mids.update(ctx.api_mids(prefix))
    loader_mids = set()
    for prefix in dex:
        loader_mids.update(ctx.api_mids(prefix))
        loader_mids.update(ctx.class_mids(prefix))
    if crypto_mids and loader_mids:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Both crypto routines and dynamic class loading exist, but their link "
            "is not proven (no method does both).",
            ["presence:crypto", "presence:dexclassloader"],
            sorted(crypto_mids | loader_mids, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No encrypted-payload loading signature observed.",
    )


def _downloaded_code(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    co_located = ctx.same_method(
        call_prefixes=_NETWORK_FETCH_PREFIXES, class_prefixes=_DEX_LOADER_PREFIXES
    )
    if co_located:
        methods = sorted(co_located, key=str.lower)
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "A method both fetches data over the network and constructs a DEX "
            "class loader - the app can download and execute code.",
            [f"co-located:@{m}" for m in methods], methods,
        )
    net_mids = set()
    for prefix in _NETWORK_FETCH_PREFIXES:
        net_mids.update(ctx.api_mids(prefix))
    loader_mids = set()
    for prefix in _DEX_LOADER_PREFIXES:
        loader_mids.update(ctx.api_mids(prefix))
        loader_mids.update(ctx.class_mids(prefix))
    if net_mids and loader_mids:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Network fetching and dynamic class loading are both present, but the "
            "download-to-load link is not proven (no single method does both).",
            ["presence:network_fetch", "presence:dexclassloader"],
            sorted(net_mids | loader_mids, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No downloaded-code loading signature observed.",
    )


# ---------------------------------------------------------------------------
# NETWORK
# ---------------------------------------------------------------------------
def _network(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    data_flows = ctx.linked_data_flows(spec.dataflow_sources)
    perms = _present_permissions(spec, ctx)
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            f"{spec.name}: network APIs are used in {len(methods)} method(s).",
            evidence, sorted(methods, key=str.lower), permissions=perms,
            data_flows=data_flows,
        )
    if perms:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            f"{spec.name}: the INTERNET permission is granted but no "
            "matching network API was observed.",
            [f"permission:{p}" for p in perms], permissions=perms,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        f"{spec.name}: no network API evidence observed.",
    )


def _custom_protocol(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    standard = {
        "http", "https", "ftp", "file", "content", "android.resource",
        "data", "tel", "smsto", "sms", "geo", "mailto", "market",
        "intent", "javascript", "about", "wap", "mms",
    }
    schemes_seen = set()
    for url in ctx.urls:
        scheme, sep, _rest = url.partition("://")
        if not sep:
            scheme, sep, _rest = url.partition(":")
            if not sep:
                continue
        scheme = scheme.strip().lower()
        if scheme and scheme not in standard:
            schemes_seen.add(scheme)
    if schemes_seen:
        ordered = sorted(schemes_seen)
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Non-standard URI schemes are referenced, indicating custom protocol "
            f"use ({', '.join(ordered[:8])}).",
            [f"scheme:{scheme}" for scheme in ordered[:8]],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No custom URI schemes observed.",
    )


# ---------------------------------------------------------------------------
# EVASION
# ---------------------------------------------------------------------------
def _emulator_detection(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    probes = ctx.same_method(
        strings=spec.strings,
        call_prefixes=spec.call_prefixes,
        field_prefixes=spec.field_prefixes,
    )
    if probes:
        methods = sorted(probes, key=str.lower)
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Sentinel emulator strings are checked together with build/device "
            "properties or Runtime access in the same method.",
            [f"co-located:@{m}" for m in methods], methods,
        )
    hit_strings = set()
    for text in spec.strings:
        if ctx.string_mids(text):
            hit_strings.add(text)
    if hit_strings:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Emulator sentinel string literals are present, but no runtime check "
            "was proven to consume them.",
            [f"string:{text!r}" for text in sorted(hit_strings)],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No emulator-detection evidence observed.",
    )


def _debugger_detection(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    mids = ctx.api_mids("Landroid/os/Debug;->isDebuggerConnected")
    if mids:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "The app calls Debug.isDebuggerConnected to detect a debugger.",
            _api_evidence("Landroid/os/Debug;->isDebuggerConnected", mids),
            mids,
        )
    if ctx.debuggable:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "The app is manifest-debuggable (debugging permitted) but no "
            "anti-debug check was observed.",
            ["manifest:debuggable"],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No debugger-detection evidence observed.",
    )


def _root_detection(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    probes = ctx.same_method(strings=spec.strings, call_prefixes=spec.call_prefixes)
    if probes:
        methods = sorted(probes, key=str.lower)
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Root sentinel strings ('/system/bin/su' etc.) are checked together "
            "with command execution in the same method.",
            [f"co-located:@{m}" for m in methods], methods,
        )
    hit_strings = set()
    for text in spec.strings:
        if ctx.string_mids(text):
            hit_strings.add(text)
    if hit_strings:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Root-probe strings are present, but no command-execution root check "
            "was proven.",
            [f"string:{text!r}" for text in sorted(hit_strings)],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No root-detection evidence observed.",
    )


def _certificate_pinning(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "TLS peer pinning / custom trust managers are implemented "
            "(X509TrustManager, CertificatePinner).",
            evidence, sorted(methods, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No certificate-pinning evidence observed.",
    )


def _string_encryption(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    decoders: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        decoders.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    encoded = ctx.encoded_strings
    if decoders and encoded:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Runtime decoding routines operate alongside encoded/obfuscated "
            "string literals, indicating string encryption.",
            evidence + [f"encoded_string:{repr(e)}" for e in encoded[:4]],
            sorted(decoders, key=str.lower),
        )
    if decoders:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Decoding routines are present, but no obfuscated-string evidence "
            "was found (the decode may be for ordinary payloads).",
            evidence, sorted(decoders, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No string-encryption evidence observed.",
    )


def _control_flow_obfuscation(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    giants = [
        mid
        for mid in ctx.evidence.method_order
        if ctx.evidence.method_instruction_count.get(mid, 0) >= _GIANT_METHOD_THRESHOLD
    ]
    if giants:
        methods = sorted(giants, key=str.lower)[:8]
        return Detection(
            BehaviorStatus.TRUE, "medium",
            f"Methods with {_GIANT_METHOD_THRESHOLD}+ instructions exist, a "
            "signature of flattened/opaque control-flow obfuscation.",
            [f"giant_method:@{mid}:{ctx.evidence.method_instruction_count.get(mid, 0)}" for mid in methods],
            methods,
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No unusually large (obfuscation-flattened) methods observed.",
    )


def _anti_analysis(
    spec: BehaviorSpec, _ctx: EvidenceContext, statuses: Dict[str, BehaviorStatus]
) -> Detection:
    components = (
        "evasion.emulator_detection",
        "evasion.debugger_detection",
        "evasion.root_detection",
        "evasion.certificate_pinning",
        "evasion.string_encryption",
        "evasion.control_flow_obfuscation",
    )
    true_keys = [key for key in components if statuses.get(key) == BehaviorStatus.TRUE]
    if len(true_keys) >= 2:
        return Detection(
            BehaviorStatus.TRUE, "high",
            "Multiple evasion techniques are combined "
            f"({', '.join(true_keys)}), indicating intentional analysis-hostility.",
            [f"behavior:{key}" for key in true_keys],
        )
    if len(true_keys) == 1:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            f"A single evasion technique ({true_keys[0]}) exists; not enough to "
            "classify the app as systematically anti-analysis.",
            [f"behavior:{true_keys[0]}"],
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No combination of evasion techniques observed.",
    )


# ---------------------------------------------------------------------------
# CRYPTOGRAPHY
# ---------------------------------------------------------------------------
def _cipher_behavior(spec: BehaviorSpec, ctx: EvidenceContext, mode: int) -> Detection:
    init_mids = ctx.api_mids("Ljavax/crypto/Cipher;->init")
    matched: List[str] = []
    for mid in init_mids:
        if mode in ctx.cipher_init_literals(mid):
            matched.append(mid)
    if matched:
        mode_name = "ENCRYPT_MODE" if mode == 1 else "DECRYPT_MODE"
        return Detection(
            BehaviorStatus.TRUE, "medium",
            f"Cipher.init is used with {mode_name} ({mode}) in the same method.",
            [f"cipher:{mode_name}@{m}" for m in matched], matched,
        )
    anywhere = set(init_mids) | set(ctx.api_mids("Ljavax/crypto/Cipher;->doFinal"))
    if anywhere:
        return Detection(
            BehaviorStatus.UNKNOWN, "low",
            "Cipher operations exist, but the ENCRYPT_MODE/DECRYPT_MODE constant "
            "was not observed, so the direction cannot be attributed.",
            ["presence:javax/crypto/Cipher"],
            sorted(anywhere, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        f"No {spec.name.lower()} API usage observed.",
    )


def _key_generation(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Cryptographic keys/key pairs are generated (KeyGenerator / "
            "KeyPairGenerator / keystore).",
            evidence, sorted(methods, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No key-generation API usage observed.",
    )


def _hashing(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "MessageDigest/Mac APIs digest data (hashing).",
            evidence, sorted(methods, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No hashing API usage observed.",
    )


def _encoding(spec: BehaviorSpec, ctx: EvidenceContext) -> Detection:
    methods: Set[str] = set()
    evidence = []
    for prefix in spec.call_prefixes:
        mids = ctx.api_mids(prefix)
        methods.update(mids)
        evidence.extend(_api_evidence(prefix, mids))
    if methods:
        return Detection(
            BehaviorStatus.TRUE, "medium",
            "Data is encoded/decoded (Base64, URL encoding).",
            evidence, sorted(methods, key=str.lower),
        )
    return Detection(
        BehaviorStatus.FALSE, "medium",
        "No encoding API usage observed.",
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
DETECTORS: Dict[str, Callable[[BehaviorSpec, EvidenceContext], Detection]] = {
    "persistence.boot_completion": _boot_completion,
    "persistence.foreground_service": _foreground_service,
    "persistence.background_service": _background_service,
    "persistence.scheduled_jobs": _scheduled_jobs,
    "persistence.alarms": _alarms,
    "persistence.device_admin": _device_admin,
    "persistence.accessibility": _accessibility,
    "collection.sms": _data_collection,
    "collection.contacts": _data_collection,
    "collection.call_log": _data_collection,
    "collection.location": _data_collection,
    "collection.device_identifiers": _data_collection,
    "collection.files": _data_collection,
    "collection.notifications": _data_collection,
    "collection.clipboard": _data_collection,
    "collection.microphone": _data_collection,
    "collection.camera": _data_collection,
    "execution.command": _command_execution,
    "execution.native": _native_execution,
    "dynamic.reflection": _reflection,
    "dynamic.class_loading": _class_loading,
    "dynamic.encrypted_payload": _encrypted_payload,
    "dynamic.downloaded_code": _downloaded_code,
    "network.http": _network,
    "network.https": _network,
    "network.sockets": _network,
    "network.websockets": _network,
    "network.dns": _network,
    "network.custom_protocol": _custom_protocol,
    "evasion.emulator_detection": _emulator_detection,
    "evasion.debugger_detection": _debugger_detection,
    "evasion.root_detection": _root_detection,
    "evasion.certificate_pinning": _certificate_pinning,
    "evasion.string_encryption": _string_encryption,
    "evasion.control_flow_obfuscation": _control_flow_obfuscation,
    "crypto.encryption": lambda spec, ctx: _cipher_behavior(spec, ctx, 1),
    "crypto.decryption": lambda spec, ctx: _cipher_behavior(spec, ctx, 2),
    "crypto.key_generation": _key_generation,
    "crypto.hashing": _hashing,
    "crypto.encoding": _encoding,
}

# Behaviors whose status depends on the others' results (computed last).
AGGREGATE_KEYS: Set[str] = {"evasion.anti_analysis"}