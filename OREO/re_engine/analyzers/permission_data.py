"""Permission taxonomy for deterministic APK triage.

A permission is NEVER judged malicious by itself. Classification produces two
independent attributes:

    * ``protection``  -- Android protection level: dangerous / normal /
                         privileged / signature / unknown
    * ``security_relevant`` -- whether the permission is frequently abused and
                         therefore warrants additional scrutiny.

The ``bucket`` combines both so results can be bucketed into the four
requested triage classes: normal, dangerous, privileged, suspicious.
"""

from __future__ import annotations

from typing import Dict

# Reuse the repository's existing suspicious-permission set where possible.
try:
    from ai.feature_extraction.constant import (
        SUSPICIOUS_PERMISSIONS as _REPO_SUSPICIOUS,
    )
except Exception:  # pragma: no cover - repo layout unchanged
    _REPO_SUSPICIOUS = set()

NORMAL_PERMISSIONS = {
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BROADCAST_STICKY",
    "android.permission.CALL_PHONE_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FLASHLIGHT",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.GET_PACKAGE_SIZE",
    "android.permission.INTERNET",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.NFC",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SET_ALARM",
    "android.permission.SET_WALLPAPER",
    "android.permission.SET_WALLPAPER_HINTS",
    "android.permission.TRANSMIT_IR",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.WRITE_SETTINGS",
    "android.companion.association.delegate",
}

DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CLIPBOARD_IN_SYSTEM",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SENSORS",
    "android.permission.UWB_RANGING",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

PRIVILEGED_PERMISSIONS = {
    "android.permission.ACCESS_SUPERUSER",
    "android.permission.ACCESS_SURFACE_FLINGER",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.BATTERY_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.CAMERA_DISABLE_TRANSMIT_LED",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.CHANGE_DEVICE_IDLE_SETTINGS",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.CLEAR_APP_USER_DATA",
    "android.permission.DELETE_CACHE_FILES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.DEVICE_POWER",
    "android.permission.DUMP",
    "android.permission.FACTORY_RESET",
    "android.permission.FORCE_STOP_PACKAGES",
    "android.permission.GET_TASKS",
    "android.permission.GLOBAL_SEARCH",
    "android.permission.HARDWARE_TEST",
    "android.permission.INSTALL_LOCATION_PROVIDER",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.MANAGE_DEVICE_ADMINS",
    "android.permission.MANAGE_USB",
    "android.permission.MANAGE_USERS",
    "android.permission.MASTER_CLEAR",
    "android.permission.MODIFY_PHONE_STATE",
    "android.permission.MOUNT_FORMAT_FILESYSTEMS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_LOGS",
    "android.permission.READ_PRECISE_PHONE_STATE",
    "android.permission.REBOOT",
    "android.permission.RECOVERY",
    "android.permission.REMOVE_TASKS",
    "android.permission.RETRIEVE_WINDOW_CONTENT",
    "android.permission.SET_ANIMATION_SCALE",
    "android.permission.SET_DEBUG_APP",
    "android.permission.SET_PROCESS_LIMIT",
    "android.permission.SET_TIME",
    "android.permission.SET_TIME_ZONE",
    "android.permission.SET_WALLPAPER_COMPONENT",
    "android.permission.SHUTDOWN",
    "android.permission.STOP_APP_SWITCHES",
    "android.permission.UPDATE_APP_OPS_STATS",
    "android.permission.WRITE_APN_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.WRITE_SETTINGS",
}

# Security-relevant: frequently abused, needs scrutiny regardless of
# protection level. Repository set + curated additions.
SUSPICIOUS_PERMISSIONS = set(_REPO_SUSPICIOUS) | {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESSIBILITY_SERVICE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.CAMERA",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_CLIPBOARD_IN_SYSTEM",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.USES_POLICY_FORCE_LOCK",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.WRITE_SETTINGS",
}

BUCKET_DANGEROUS = "dangerous"
BUCKET_NORMAL = "normal"
BUCKET_PRIVILEGED = "privileged"
BUCKET_SUSPICIOUS = "suspicious"


def classify_permission(permission: str) -> Dict[str, object]:
    """Deterministic triage classification of a single permission.

    Returns a dict with ``bucket``, ``protection`` and ``security_relevant``.
    A permission is a *suspicious* bucket member when it is security-relevant
    (regardless of protection level); the note string states this is a
    security-review flag, never a "malicious" verdict.
    """
    if permission in DANGEROUS_PERMISSIONS:
        protection = "dangerous"
        default_bucket = BUCKET_DANGEROUS
    elif permission in PRIVILEGED_PERMISSIONS:
        protection = "privileged"
        default_bucket = BUCKET_PRIVILEGED
    elif permission in NORMAL_PERMISSIONS:
        protection = "normal"
        default_bucket = BUCKET_NORMAL
    else:
        protection = "unknown"
        default_bucket = BUCKET_NORMAL

    relevant = permission in SUSPICIOUS_PERMISSIONS

    if relevant:
        bucket = BUCKET_SUSPICIOUS
    elif protection == "unknown":
        bucket = BUCKET_NORMAL
    else:
        bucket = default_bucket

    return {
        "bucket": bucket,
        "protection": protection,
        "security_relevant": relevant,
        "note": (
            "security-relevant; requires manual review (not inherently "
            "malicious)" if relevant else "declared permission"
        ),
    }


def is_security_relevant(permission: str) -> bool:
    return permission in SUSPICIOUS_PERMISSIONS


__all__ = [
    "classify_permission",
    "is_security_relevant",
    "SUSPICIOUS_PERMISSIONS",
    "DANGEROUS_PERMISSIONS",
    "PRIVILEGED_PERMISSIONS",
    "NORMAL_PERMISSIONS",
    "BUCKET_NORMAL",
    "BUCKET_DANGEROUS",
    "BUCKET_PRIVILEGED",
    "BUCKET_SUSPICIOUS",
]