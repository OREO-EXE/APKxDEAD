"""Hermetic fixtures for call-graph tests.

A small hand-built DEX (via the triage fakes — methods as tuples) with
realistic Android components, dispatch-heavy virtual/interface calls, Worker
overrides, callback registrations and an AlarmManager registration so every
graph feature is testable without androguard.
"""

from __future__ import annotations

from types import SimpleNamespace

from re_engine.models.context import Component
from re_engine.tests.triage.fixtures import FakeDex, FakeDexClass, FakeInstruction

MAIN_ACTIVITY = "com.app.MainActivity"
STEAL_RECEIVER = "com.app.StealReceiver"
SPY_SERVICE = "com.app.SpyService"
MY_PROVIDER = "com.app.MyProvider"
ALARM_RECEIVER = "com.app.AlarmReceiver"
ALARM_RECEIVER_CLASS = "Lcom/app/AlarmReceiver;"

MID_ONCREATE = "Lcom/app/MainActivity;->onCreate(Landroid/os/Bundle;)V"
MID_ONDESTROY = "Lcom/app/MainActivity;->onDestroy()V"
MID_ONRECEIVE_STEAL = (
    "Lcom/app/StealReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
)
MID_ONRECEIVE_ALARM = (
    "Lcom/app/AlarmReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
)
MID_SPY_CREATE = "Lcom/app/SpyService;->onCreate()V"
MID_PAYLOAD_RUNTASK = "Lcom/app/Payload;->runTask()V"
MID_PAYLOAD_COLLATERAL = "Lcom/app/Payload;->collateral()V"
MID_PAYLOAD_STEALSMS = "Lcom/app/Payload;->stealSms()V"
MID_PAYLOAD_EXFIL = "Lcom/app/Payload;->doExfil()V"
MID_PAYLOAD_USEWORKER = "Lcom/app/Payload;->useWorker()V"
MID_NOTIFY_ONNOTIFY = "Lcom/app/Notify;->onNotify()V"
MID_IMPLA_ONNOTIFY = "Lcom/app/ImplA;->onNotify()V"
MID_IMPLB_ONNOTIFY = "Lcom/app/ImplB;->onNotify()V"
MID_BASE_REPORT = "Lcom/app/BaseWorker;->report()V"
MID_EVIL_REPORT = "Lcom/app/EvilWorker;->report()V"
MID_BIND_BUTTON = "Lcom/app/UIControl;->bindButton()V"
MID_UICLICK = "Lcom/app/UIControl;->onClick(Landroid/view/View;)V"
MID_SCHEDULE = "Lcom/app/AlarmScheduler;->schedule()V"
MID_WORKER_DOWORK = "Lcom/app/BaseWorker;->doWork()Landroidx/work/ListenableWorker$Result;"
MID_EVIL_DOWORK = "Lcom/app/EvilWorker;->doWork()Landroidx/work/ListenableWorker$Result;"
MID_SYNC_DOWORK = "Lcom/app/SyncWorker;->doWork()Landroidx/work/ListenableWorker$Result;"
MID_FIREBASE = (
    "Lcom/app/FirebasePush;->onMessageReceived(Lcom/google/firebase/messaging/RemoteMessage;)V"
)
MID_APP_CREATE = "Lcom/app/MyApplication;->onCreate()V"
MID_PROVIDER_QUERY = (
    "Lcom/app/MyProvider;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;"
    "[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"
)
MID_OVERLAY_EVENT = (
    "Lcom/app/OverlayService;->onAccessibilityEvent"
    "(Landroid/view/accessibility/AccessibilityEvent;)V"
)
MID_JOB_START = "Lcom/app/JobWorker;->onStartJob(Landroid/app/job/JobParameters;)Z"

SECRET_STRING = "secret-key-9f3a"
EXFIL_URL = "http://evil.example/x"


def _inst(name, output, string=None):
    return FakeInstruction(name, output, string=string)


def _method(name, descriptor, access, instructions):
    return (name, descriptor, access, instructions)


def build_callgraph_dex():
    """Return a FakeDex with all the scenario classes."""
    return FakeDex(
        [
            FakeDexClass(
                "Lcom/app/MainActivity;",
                "Landroid/app/Activity;",
                [],
                [],
                [
                    _method(
                        "onCreate",
                        "(Landroid/os/Bundle;)V",
                        "protected",
                        [
                            _inst(
                                "invoke-virtual",
                                "Lcom/app/Notify;->onNotify()V, v0",
                            ),
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->runTask()V, v0",
                            ),
                            _inst("const-string", '"hi there"', "hi there"),
                        ],
                    ),
                    _method("onDestroy", "()V", "protected", []),
                ],
            ),
            FakeDexClass(
                "Lcom/app/StealReceiver;",
                "Landroid/content/BroadcastReceiver;",
                [],
                [],
                [
                    _method(
                        "onReceive",
                        "(Landroid/content/Context;Landroid/content/Intent;)V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->doExfil()V, p0",
                            )
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/SpyService;",
                "Landroid/app/Service;",
                [],
                [],
                [
                    _method(
                        "onCreate",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->stealSms()V, v0",
                            )
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/Payload;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "runTask",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->collateral()V, v0",
                            )
                        ],
                    ),
                    _method(
                        "collateral",
                        "()V",
                        "private",
                        [_inst("const-string", '"fu"', "fu")],
                    ),
                    _method(
                        "stealSms",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->collateral()V, v0",
                            )
                        ],
                    ),
                    _method(
                        "doExfil",
                        "()V",
                        "public",
                        [
                            _inst("const-string", f'"{EXFIL_URL}"', EXFIL_URL),
                            _inst(
                                "invoke-interface",
                                "Lcom/app/Notify;->onNotify()V, v0",
                            ),
                            _inst(
                                "invoke-static",
                                "Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;, v0",
                            ),
                        ],
                    ),
                    _method(
                        "useWorker",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-virtual",
                                "Lcom/app/BaseWorker;->report()V, v0",
                            ),
                            _inst(
                                "invoke-virtual",
                                "Lcom/app/EvilWorker;->report()V, v0",
                            ),
                        ],
                    ),
                ],
            ),
            FakeDexClass(
                "Lcom/app/Notify;",
                "Ljava/lang/Object;",
                [],
                [],
                [_method("onNotify", "()V", "public abstract", [])],
            ),
            FakeDexClass(
                "Lcom/app/ImplA;",
                "Ljava/lang/Object;",
                ["Lcom/app/Notify;"],
                [],
                [
                    _method(
                        "onNotify",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->collateral()V, v0",
                            )
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/ImplB;",
                "Ljava/lang/Object;",
                ["Lcom/app/Notify;"],
                [],
                [
                    _method(
                        "onNotify",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->collateral()V, v0",
                            )
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/BaseWorker;",
                "Landroidx/work/Worker;",
                [],
                [],
                [
                    _method(
                        "doWork",
                        "()Landroidx/work/ListenableWorker$Result;",
                        "public",
                        [],
                    ),
                    _method("report", "()V", "public", []),
                ],
            ),
            FakeDexClass(
                "Lcom/app/EvilWorker;",
                "Lcom/app/BaseWorker;",
                [],
                [],
                [
                    _method(
                        "doWork",
                        "()Landroidx/work/ListenableWorker$Result;",
                        "public",
                        [],
                    ),
                    _method("report", "()V", "public", []),
                ],
            ),
            FakeDexClass(
                "Lcom/app/FirebasePush;",
                "Lcom/google/firebase/messaging/FirebaseMessagingService;",
                [],
                [],
                [
                    _method(
                        "onMessageReceived",
                        "(Lcom/google/firebase/messaging/RemoteMessage;)V",
                        "public",
                        [
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->doExfil()V, v0",
                            )
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/MyApplication;",
                "Landroid/app/Application;",
                [],
                [],
                [_method("onCreate", "()V", "public", [])],
            ),
            FakeDexClass(
                "Lcom/app/MyProvider;",
                "Landroid/content/ContentProvider;",
                [],
                [],
                [
                    _method(
                        "query",
                        "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;"
                        "[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                        "public",
                        [
                            _inst(
                                "invoke-virtual",
                                "Lcom/app/Payload;->runTask()V, v0",
                            )
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/AlarmReceiver;",
                "Landroid/content/BroadcastReceiver;",
                [],
                [],
                [
                    _method(
                        "onReceive",
                        "(Landroid/content/Context;Landroid/content/Intent;)V",
                        "public",
                        [
                            _inst("const-string", '"alarm-tick"', "alarm-tick"),
                            _inst(
                                "invoke-direct",
                                "Lcom/app/Payload;->runTask()V, p0",
                            ),
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/AlarmScheduler;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "schedule",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-static",
                                "Landroid/app/PendingIntent;->getBroadcast"
                                "(Landroid/content/Context;ILandroid/content/Intent;I)"
                                "Landroid/app/PendingIntent;, v0",
                            ),
                            _inst("const-class", "Lcom/app/AlarmReceiver;"),
                        ],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/UIControl;",
                "Ljava/lang/Object;",
                [],
                [],
                [
                    _method(
                        "bindButton",
                        "()V",
                        "public",
                        [
                            _inst(
                                "invoke-virtual",
                                "Landroid/view/View;->setOnClickListener"
                                "(Landroid/view/View$OnClickListener;)V, v0",
                            ),
                            _inst("const-string", f'"{SECRET_STRING}"', SECRET_STRING),
                        ],
                    ),
                    _method(
                        "onClick",
                        "(Landroid/view/View;)V",
                        "public",
                        [
                            _inst(
                                "invoke-virtual",
                                "Lcom/app/Payload;->runTask()V, v1",
                            )
                        ],
                    ),
                ],
            ),
            FakeDexClass(
                "Lcom/app/JobWorker;",
                "Landroid/app/job/JobService;",
                [],
                [],
                [
                    _method(
                        "onStartJob",
                        "(Landroid/app/job/JobParameters;)Z",
                        "public",
                        [],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/SyncWorker;",
                "Landroidx/work/CoroutineWorker;",
                [],
                [],
                [
                    _method(
                        "doWork",
                        "()Landroidx/work/ListenableWorker$Result;",
                        "public",
                        [],
                    )
                ],
            ),
            FakeDexClass(
                "Lcom/app/OverlayService;",
                "Landroid/accessibilityservice/AccessibilityService;",
                [],
                [],
                [
                    _method(
                        "onAccessibilityEvent",
                        "(Landroid/view/accessibility/AccessibilityEvent;)V",
                        "public",
                        [],
                    )
                ],
            ),
        ]
    )


def fake_context(dex=None):
    """A context exposing components / boot receivers over a fake DEX."""
    return SimpleNamespace(
        components=[
            Component(name=MAIN_ACTIVITY, kind="activity", exported=True),
            Component(name=STEAL_RECEIVER, kind="receiver", exported=True),
            Component(name=SPY_SERVICE, kind="service", exported=False),
            Component(name=MY_PROVIDER, kind="provider", exported=False),
        ],
        boot_receivers=[STEAL_RECEIVER],
        foreground_services=[],
        artifacts=SimpleNamespace(dex=[dex] if dex is not None else []),
    )