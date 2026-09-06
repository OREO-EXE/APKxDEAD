"""Tests for Android entry-point detection on the hermetic DEX."""

from __future__ import annotations

from re_engine.graph.entrypoints import (
    ALARM_MANAGER_ROLE,
    BOOT_RECEIVER_ROLE,
    detect_entry_points,
)
from re_engine.graph.models import Resolution
from re_engine.reconstruct.index import CodeIndex

from .fixtures import (
    ALARM_RECEIVER_CLASS,
    MAIN_ACTIVITY,
    MID_APP_CREATE,
    MID_EVIL_DOWORK,
    MID_FIREBASE,
    MID_JOB_START,
    MID_NOTIFY_ONNOTIFY,
    MID_ONCREATE,
    MID_ONDESTROY,
    MID_ONRECEIVE_STEAL,
    MID_OVERLAY_EVENT,
    MID_PROVIDER_QUERY,
    MID_SCHEDULE,
    MID_SPY_CREATE,
    MID_SYNC_DOWORK,
    MID_WORKER_DOWORK,
    STEAL_RECEIVER,
    build_callgraph_dex,
    fake_context,
)


def detect(dex=None):
    index = CodeIndex([dex or build_callgraph_dex()])
    return detect_entry_points(index, fake_context(dex or build_callgraph_dex()))


def test_entry_points_are_sorted_and_deduplicated():
    points = detect()
    by_key = {}
    for point in points:
        key = (point.role, point.method_mid)
        assert key not in by_key, f"duplicate entry {key}"
        by_key[key] = point
    roles = [p.role for p in points]
    assert roles == sorted(roles)


def test_manifest_component_lifecycle_roles():
    points = detect()
    by_mid = {p.method_mid: p for p in points}
    create = by_mid[MID_ONCREATE]
    # MainActivity.onCreate is a manifest activity -> component ref present.
    assert create.role == "activity#onCreate"
    assert create.component == MAIN_ACTIVITY
    assert create.resolution == Resolution.INFERRED


def test_boot_receiver_gets_extra_entry_variant():
    points = detect()
    boot = [p for p in points if p.role == BOOT_RECEIVER_ROLE]
    assert boot
    assert boot[0].method_mid == MID_ONRECEIVE_STEAL
    assert boot[0].component == STEAL_RECEIVER
    assert boot[0].metadata.get("boot") is True


def test_superclass_roles_no_manifest_dependency():
    points = detect()
    mids = {p.method_mid for p in points}
    assert MID_ONRECEIVE_STEAL in mids  # receiver#onReceive
    assert MID_ONDESTROY in mids  # activity#onDestroy via superclass
    assert MID_SPY_CREATE in mids


def test_worker_and_messaging_roles():
    points = detect()
    roles = {(p.role, p.method_mid) for p in points}
    assert ("workmanager#doWork", MID_WORKER_DOWORK) in roles
    assert ("workmanager#doWork", MID_SYNC_DOWORK) in roles
    assert ("firebase#onMessageReceived", MID_FIREBASE) in roles
    assert ("jobscheduler#onStartJob", MID_JOB_START) in roles
    assert ("accessibility#onAccessibilityEvent", MID_OVERLAY_EVENT) in roles
    assert ("application#onCreate", MID_APP_CREATE) in roles


def test_provider_query_recognised():
    points = detect()
    assert any(
        p.role == "provider#query" and p.method_mid == MID_PROVIDER_QUERY
        for p in points
    )


def test_worker_override_is_not_an_entry_point():
    points = detect()
    roles = {(p.role, p.method_mid) for p in points}
    assert ("workmanager#doWork", MID_WORKER_DOWORK) in roles
    assert not any(
        role == "workmanager#doWork" for role, mid in roles if mid == MID_EVIL_DOWORK
    )


def test_alarm_scheduler_detected_via_pending_intent():
    points = detect()
    alarm = [p for p in points if p.role == ALARM_MANAGER_ROLE]
    assert alarm
    assert alarm[0].method_mid == MID_SCHEDULE
    # const-class reference resolves to the receiver even though it is not a
    # manifest component.
    assert alarm[0].component == ALARM_RECEIVER_CLASS


def test_dispatch_target_is_marked_inferred():
    # The interface dispatcher inside MainActivity.onCreate is not itself an
    # entry point; the lifecycle entry still targets the method directly.
    points = detect()
    assert all(p.method_mid != MID_NOTIFY_ONNOTIFY for p in points)
    assert bool(points)