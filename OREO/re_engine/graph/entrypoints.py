"""Android entry-point detection for the call graph.

Prioritized entry sources:

    - Activity / Service / BroadcastReceiver / ContentProvider / Application
      lifecycles (framework-trggered, INFERRED)
    - JobScheduler (``JobService.onStartJob/onStopJob``)
    - WorkManager (``Worker/CoroutineWorker/ListenableWorker.doWork``)
    - AlarmManager (``PendingIntent.getBroadcast`` registration sites)
    - Accessibility services (``onAccessibilityEvent``)
    - Notification listeners (``onNotificationPosted``)
    - Firebase messaging callbacks (``onMessageReceived`` / ``onNewToken``)
    - BOOT_COMPLETED receivers (from ``context.boot_receivers``)

Lifecycle findings come from the superclass/interface graph of the DEX (known
statically) plus the manifest component declarations, and are reported as
INFERRED: the OS actually triggers these, which static analysis cannot observe.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from re_engine.graph.models import EntryPoint, Resolution
from re_engine.reconstruct.index import CodeIndex, MethodEntry

# (name, interpreted signature) pairs per role. An empty signature tuple matches
# any signature (DEX/version variants make signatures unstable).
RoleMethods = Tuple[Tuple[str, tuple], ...]
Roles = Tuple[str, RoleMethods]

ACTIVITY_ROLES: Roles = (
    "activity",
    (
        ("onCreate", ("(Landroid/os/Bundle;)V",)),
        ("onStart", ()),
        ("onResume", ()),
        ("onRestart", ()),
        ("onPause", ()),
        ("onStop", ()),
        ("onDestroy", ()),
        ("onNewIntent", ()),
        ("onActivityResult", ()),
    ),
)
SERVICE_ROLES: Roles = (
    "service",
    (
        ("onCreate", ()),
        ("onStartCommand", ()),
        ("onBind", ()),
        ("onUnbind", ()),
        ("onDestroy", ()),
        ("onRebind", ()),
    ),
)
RECEIVER_ROLES: Roles = ("receiver", (("onReceive", ()),))
PROVIDER_ROLES: Roles = (
    "provider",
    (
        ("onCreate", ()),
        ("query", ()),
        ("insert", ()),
        ("update", ()),
        ("delete", ()),
        ("getType", ()),
        ("call", ()),
    ),
)
APPLICATION_ROLES: Roles = (
    "application",
    (("onCreate", ()), ("attachBaseContext", ())),
)
JOB_SCHEDULER_ROLES: Roles = (
    "jobscheduler",
    (("onStartJob", ()), ("onStopJob", ())),
)
WORK_MANAGER_ROLES: Roles = ("workmanager", (("doWork", ()),))
ACCESSIBILITY_ROLES: Roles = (
    "accessibility",
    (
        ("onAccessibilityEvent", ()),
        ("onServiceConnected", ()),
        ("onInterrupt", ()),
    ),
)
NOTIFICATION_LISTENER_ROLES: Roles = (
    "notification_listener",
    (
        ("onNotificationPosted", ()),
        ("onNotificationRemoved", ()),
        ("onListenerConnected", ()),
    ),
)
FIREBASE_ROLES: Roles = (
    "firebase",
    (("onMessageReceived", ()), ("onNewToken", ())),
)

# superclass descriptor -> role
SUPERCLASS_ROLES: Dict[str, Roles] = {
    "Landroid/app/Activity;": ACTIVITY_ROLES,
    "Landroid/app/Service;": SERVICE_ROLES,
    "Landroid/content/BroadcastReceiver;": RECEIVER_ROLES,
    "Landroid/content/ContentProvider;": PROVIDER_ROLES,
    "Landroid/app/Application;": APPLICATION_ROLES,
    "Landroid/app/job/JobService;": JOB_SCHEDULER_ROLES,
    "Landroidx/work/Worker;": WORK_MANAGER_ROLES,
    "Landroidx/work/CoroutineWorker;": WORK_MANAGER_ROLES,
    "Landroidx/work/ListenableWorker;": WORK_MANAGER_ROLES,
    "Landroid/accessibilityservice/AccessibilityService;": ACCESSIBILITY_ROLES,
    "Landroid/service/notification/NotificationListenerService;": NOTIFICATION_LISTENER_ROLES,
    "Lcom/google/firebase/messaging/FirebaseMessagingService;": FIREBASE_ROLES,
}

# component kind -> role
COMPONENT_KIND_ROLES: Dict[str, Roles] = {
    "activity": ACTIVITY_ROLES,
    "service": SERVICE_ROLES,
    "receiver": RECEIVER_ROLES,
    "provider": PROVIDER_ROLES,
}

BOOT_RECEIVER_ROLE = "boot_receiver#onReceive"
ALARM_MANAGER_ROLE = "alarmmanager#schedule"

PENDING_INTENT_GET_BROADCAST = "Landroid/app/PendingIntent;->getBroadcast"

# Callback registration rules: register-call prefix -> callback method name.
# Edges built from these are INFERRED (the receiver wired at runtime).
CALLBACK_RULES: List[Tuple[str, str]] = [
    ("Landroid/view/View;->setOnClickListener", "onClick"),
    ("Landroid/view/View;->setOnLongClickListener", "onLongClick"),
    ("Landroid/widget/AdapterView;->setOnItemClickListener", "onItemClick"),
    ("Landroid/content/Context;->registerReceiver", "onReceive"),
    ("Landroid/os/Handler;->postDelayed", "run"),
    ("Landroid/os/Handler;->post", "run"),
    ("Ljava/lang/Runnable;->run", "run"),
]


def detect_entry_points(
    index, context=None, alarm_scan_cap: int = 10000
) -> List[EntryPoint]:
    """Detect the Android entry points of an APK's DEX, deterministically.

    ``context`` is an :class:`AnalysisContext` or a duck-typed object exposing
    ``components`` and ``boot_receivers`` (both optional). ``alarm_scan_cap``
    bounds the expensive full-method scan used to find AlarmManager
    registrations.
    """
    index._ensure_index()
    components = list(getattr(context, "components", None) or [])
    boot_receivers = set(getattr(context, "boot_receivers", None) or [])
    component_by_name = {
        getattr(c, "name", None): c for c in components if getattr(c, "name", None)
    }

    raw: Dict[Tuple[str, str], EntryPoint] = {}

    def remember(entry: EntryPoint) -> None:
        raw[(entry.role, entry.method_mid)] = entry

    # 1) Manifest components: component -> class -> lifecycle roles.
    for component in components:
        name = getattr(component, "name", None)
        kind = getattr(component, "kind", None) or "component"
        if not name:
            continue
        class_entry = index.find_class(name)
        if class_entry is None:
            continue
        roles = COMPONENT_KIND_ROLES.get(kind)
        if roles is None:
            continue
        for method_name, signatures in _role_methods(roles):
            for candidate in index.methods_named(class_entry.descriptor, method_name):
                remember(
                    _component_entry(
                        f"{kind}#{method_name}",
                        candidate,
                        name,
                        class_entry.descriptor,
                        f"{kind}:{name}",
                        signatures,
                    )
                )
                if kind == "receiver" and name in boot_receivers:
                    remember(
                        _component_entry(
                            BOOT_RECEIVER_ROLE,
                            candidate,
                            name,
                            class_entry.descriptor,
                            f"{kind}:{name}",
                            signatures,
                            extra={"boot": True},
                        )
                    )

    # 2) Superclass-driven special roles across every indexed class.
    for descriptor in sorted(index._class_by_desc.keys(), key=str.lower):
        class_entry = index._class_by_desc[descriptor]
        superclass = (class_entry.superclass() or "").strip()
        if not superclass:
            continue
        roles = SUPERCLASS_ROLES.get(superclass)
        if roles is None:
            continue
        kind, role_methods = roles
        owner = class_entry.dotted or descriptor
        for method_name, signatures in role_methods:
            for candidate in index.methods_named(descriptor, method_name):
                remember(
                    EntryPoint(
                        role=f"{kind}#{method_name}",
                        method_mid=candidate.mid,
                        component=owner,
                        resolution=Resolution.INFERRED,
                        evidence_refs=[
                            {"kind": "role", "ref": f"{kind}#{method_name}"},
                            {"kind": "superclass", "ref": superclass},
                            {"kind": "class", "ref": descriptor},
                        ],
                        metadata={
                            "source": "superclass",
                            "signature_mismatch": not _signature_ok(
                                candidate, signatures
                            ),
                        },
                    )
                )

    # 3) AlarmManager: methods that schedule via PendingIntent.getBroadcast.
    for mid in _alarm_scheduler_mids(index, alarm_scan_cap=alarm_scan_cap):
        remember(
            EntryPoint(
                role=ALARM_MANAGER_ROLE,
                method_mid=mid,
                component=_alarm_target_component(
                    mid, component_by_name, index
                ),
                resolution=Resolution.INFERRED,
                evidence_refs=[
                    {"kind": "role", "ref": ALARM_MANAGER_ROLE},
                    {"kind": "call", "ref": PENDING_INTENT_GET_BROADCAST},
                ],
                metadata={"source": "alarm_manager"},
            )
        )

    return sorted(raw.values(), key=lambda entry: (entry.role, entry.method_mid))


def _role_methods(roles: Roles) -> List[Tuple[str, tuple]]:
    _, role_methods = roles
    return [(name, signatures) for name, signatures in role_methods]


def _component_entry(
    role: str,
    candidate: MethodEntry,
    component_name: str,
    class_descriptor: str,
    manifest_ref: str,
    signatures: tuple,
    extra: Optional[Dict[str, object]] = None,
) -> EntryPoint:
    metadata: Dict[str, object] = {
        "source": "manifest",
        "signature_mismatch": not _signature_ok(candidate, signatures),
    }
    if extra:
        metadata.update(extra)
    return EntryPoint(
        role=role,
        method_mid=candidate.mid,
        component=component_name,
        resolution=Resolution.INFERRED,
        evidence_refs=[
            {"kind": "role", "ref": role},
            {"kind": "manifest", "ref": manifest_ref},
            {"kind": "class", "ref": class_descriptor},
        ],
        metadata=metadata,
    )


def _signature_ok(candidate: MethodEntry, signatures: tuple) -> bool:
    if not signatures:
        return True
    return (candidate.signature or "") in signatures or not candidate.signature


def _alarm_scheduler_mids(index: CodeIndex, alarm_scan_cap: int = 10000) -> List[str]:
    """Methods that schedule AlarmManager work via PendingIntent.getBroadcast.

    Bounded by ``alarm_scan_cap`` (sorted class/method order) because the full
    method pass parses every instruction stream; the same scan the graph
    builder later performs for its own (capped) usage index.
    """
    from re_engine.reconstruct.smali import extract_call_sites

    wanted = _api_key(PENDING_INTENT_GET_BROADCAST)
    found: List[str] = []
    scanned = 0
    for descriptor in sorted(index._class_by_desc.keys(), key=str.lower):
        for method in index._class_by_desc[descriptor].methods():
            if alarm_scan_cap and scanned >= alarm_scan_cap:
                return found
            scanned += 1
            if not method.mid:
                continue
            try:
                sites = extract_call_sites(method.method)
            except Exception:
                sites = []
            if any(_api_key(target) == wanted for _, target in sites):
                found.append(method.mid)
    return sorted(found, key=str.lower)


def _alarm_target_component(
    mid: str, component_by_name: Dict[str, object], index: CodeIndex
) -> str:
    """The receiver a scheduling method plausibly targets.

    Priority: an indexed ``BroadcastReceiver`` subclass referenced by the
    scheduling method (e.g. ``const-class``), then a manifest-declared receiver
    whose name/descriptor is referenced, then the method's own class.
    """
    class_desc = mid.partition("->")[0]
    entry = index.get_method(mid)
    if entry is None:
        return class_desc
    refs = set(entry.references().get("classes", []))
    for ref in sorted(refs, key=str.lower):
        if not index.class_exists(ref):
            continue
        if _is_receiver_subclass(index, ref):
            return ref
    for name, component in component_by_name.items():
        if getattr(component, "kind", None) != "receiver":
            continue
        if name == class_desc or name in refs or f"L{name.replace('.', '/')};" in refs:
            return name
    return class_desc


def _is_receiver_subclass(index: CodeIndex, descriptor: str, max_depth: int = 40) -> bool:
    """Walk the app superclass chain to see if ``descriptor`` is a receiver."""
    seen: Set[str] = set()
    cursor = descriptor
    for _ in range(max_depth):
        if cursor in seen:
            return False
        seen.add(cursor)
        entry = index._class_by_desc.get(cursor)
        if entry is None:
            return False
        parent = (entry.superclass() or "").strip()
        if not parent:
            return False
        if parent == "Landroid/content/BroadcastReceiver;":
            return True
        if not index.class_exists(parent):
            return False
        cursor = parent
    return False


def _api_key(ref: str) -> str:
    ref = str(ref).strip().strip('"')
    head, sep, tail = ref.partition("->")
    if not sep:
        return ref
    name = tail.split("(", 1)[0].rstrip(";")
    return f"{head}->{name}"