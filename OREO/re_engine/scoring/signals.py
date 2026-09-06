"""Deterministic signal tables and detectors for suspicious-code ranking.

The whole subsystem is a pure, static rule set. There is no machine learning
here: every rule returns a :class:`Signal` (label + weight + category) so
scores can always be traced back to the evidence that triggered them.

Categories are stable strings used only for grouping/explanation:
``PERMISSION``, ``SMS``, ``CONTACTS``, ``CALL_LOG``, ``LOCATION``,
``ACCESSIBILITY``, ``MICROPHONE``, ``CAMERA``, ``NOTIFICATION``,
``DEVICE_ADMIN``, ``STORAGE``, ``NETWORK``, ``CRYPTO``, ``REFLECTION``,
``DYNAMIC_LOADING``, ``EXEC``, ``WEBVIEW``, ``FILE``, ``PACKAGE``,
``BEHAVIOR``, ``OBFUSCATION``, ``COMPONENT``, ``ENCODED``.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Signal:
    """One weighted, explainable signal produced by a detector rule."""

    label: str
    weight: int
    category: str


# ---------------------------------------------------------------------------
# Permission signals
# ---------------------------------------------------------------------------

PERMISSION_SIGNALS: Dict[str, Signal] = {
    # SMS
    "android.permission.SEND_SMS": Signal("SEND_SMS", 35, "SMS"),
    "android.permission.READ_SMS": Signal("READ_SMS", 35, "SMS"),
    "android.permission.RECEIVE_SMS": Signal("RECEIVE_SMS", 35, "SMS"),
    "android.permission.RECEIVE_WAP_PUSH": Signal(
        "RECEIVE_WAP_PUSH", 25, "SMS"
    ),
    "android.permission.RECEIVE_MMS": Signal("RECEIVE_MMS", 25, "SMS"),
    "android.permission.READ_PHONE_NUMBERS": Signal(
        "READ_PHONE_NUMBERS", 20, "SMS"
    ),
    # Contacts
    "android.permission.READ_CONTACTS": Signal("READ_CONTACTS", 22, "CONTACTS"),
    "android.permission.WRITE_CONTACTS": Signal(
        "WRITE_CONTACTS", 16, "CONTACTS"
    ),
    # Call logs
    "android.permission.READ_CALL_LOG": Signal("READ_CALL_LOG", 22, "CALL_LOG"),
    "android.permission.WRITE_CALL_LOG": Signal(
        "WRITE_CALL_LOG", 14, "CALL_LOG"
    ),
    "android.permission.PROCESS_OUTGOING_CALLS": Signal(
        "PROCESS_OUTGOING_CALLS", 16, "CALL_LOG"
    ),
    # Location
    "android.permission.ACCESS_FINE_LOCATION": Signal(
        "ACCESS_FINE_LOCATION", 18, "LOCATION"
    ),
    "android.permission.ACCESS_COARSE_LOCATION": Signal(
        "ACCESS_COARSE_LOCATION", 12, "LOCATION"
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": Signal(
        "ACCESS_BACKGROUND_LOCATION", 22, "LOCATION"
    ),
    # Microphone / camera
    "android.permission.RECORD_AUDIO": Signal("RECORD_AUDIO", 30, "MICROPHONE"),
    "android.permission.CAPTURE_AUDIO_OUTPUT": Signal(
        "CAPTURE_AUDIO_OUTPUT", 30, "MICROPHONE"
    ),
    "android.permission.CAMERA": Signal("CAMERA", 22, "CAMERA"),
    # Accessibility / enumeration
    "android.permission.BIND_ACCESSIBILITY_SERVICE": Signal(
        "BIND_ACCESSIBILITY_SERVICE", 30, "ACCESSIBILITY"
    ),
    "android.permission.QUERY_ALL_PACKAGES": Signal(
        "QUERY_ALL_PACKAGES", 18, "PACKAGE"
    ),
    "android.permission.PACKAGE_USAGE_STATS": Signal(
        "PACKAGE_USAGE_STATS", 18, "NOTIFICATION"
    ),
    # Notification access
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": Signal(
        "BIND_NOTIFICATION_LISTENER_SERVICE", 22, "NOTIFICATION"
    ),
    # Device admin
    "android.permission.BIND_DEVICE_ADMIN": Signal(
        "BIND_DEVICE_ADMIN", 30, "DEVICE_ADMIN"
    ),
    "android.permission.MANAGE_DEVICE_ADMINS": Signal(
        "MANAGE_DEVICE_ADMINS", 26, "DEVICE_ADMIN"
    ),
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": Signal(
        "READ_EXTERNAL_STORAGE", 12, "STORAGE"
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": Signal(
        "WRITE_EXTERNAL_STORAGE", 12, "STORAGE"
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": Signal(
        "MANAGE_EXTERNAL_STORAGE", 16, "STORAGE"
    ),
    # Network
    "android.permission.INTERNET": Signal("INTERNET", 5, "NETWORK"),
    "android.permission.ACCESS_NETWORK_STATE": Signal(
        "ACCESS_NETWORK_STATE", 3, "NETWORK"
    ),
    "android.permission.ACCESS_WIFI_STATE": Signal(
        "ACCESS_WIFI_STATE", 6, "NETWORK"
    ),
    "android.permission.CHANGE_WIFI_STATE": Signal(
        "CHANGE_WIFI_STATE", 8, "NETWORK"
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": Signal(
        "SYSTEM_ALERT_WINDOW", 16, "MISC"
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": Signal(
        "REQUEST_INSTALL_PACKAGES", 16, "MISC"
    ),
    "android.permission.READ_PHONE_STATE": Signal(
        "READ_PHONE_STATE", 12, "SMS"
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": Signal(
        "RECEIVE_BOOT_COMPLETED", 12, "COMPONENT"
    ),
}


def permissions_by_category(
    permissions: List[str],
) -> Dict[str, List[str]]:
    """Bucket declared permissions by their signal category (sorted)."""
    by: Dict[str, List[str]] = {}
    for permission in sorted(permissions):
        signal = PERMISSION_SIGNALS.get(permission)
        if signal is not None:
            by.setdefault(signal.category, []).append(permission)
    return {key: by[key] for key in sorted(by)}


# ---------------------------------------------------------------------------
# API signals (ordered: the first matching rule wins for label/weight)
# ---------------------------------------------------------------------------

_API_SPECS: List[Tuple[str, Signal]] = [
    # SMS / telephony
    (
        r"Landroid/telephony/SmsManager",
        Signal("SmsManager API", 40, "SMS"),
    ),
    (
        r"Landroid/telephony/SmsMessage",
        Signal("SmsMessage API", 30, "SMS"),
    ),
    (
        r"Landroid/telephony/TelephonyManager;->(?:getLine1Number|getDeviceId"
        r"|getImei|getSubscriberId|getSimSerialNumber|listen)",
        Signal("telephony identity API", 25, "SMS"),
    ),
    (
        r"Landroid/telephony/gsm/SmsManager",
        Signal("SmsManager (gsm) API", 40, "SMS"),
    ),
    # Contacts / call logs
    (
        r"Landroid/provider/ContactsContract",
        Signal("ContactsContract API", 24, "CONTACTS"),
    ),
    (
        r"Landroid/provider/CallLog",
        Signal("CallLog API", 24, "CALL_LOG"),
    ),
    (
        r"Landroid/accounts/AccountManager",
        Signal("AccountManager API", 18, "CONTACTS"),
    ),
    # Location
    (
        r"Lcom/google/android/gms/location/FusedLocationProviderClient",
        Signal("Fused location API", 24, "LOCATION"),
    ),
    (
        r"Landroid/location/LocationManager",
        Signal("LocationManager API", 22, "LOCATION"),
    ),
    (
        r"Landroid/location/Geocoder",
        Signal("Geocoder API", 14, "LOCATION"),
    ),
    # Accessibility
    (
        r"Landroid/accessibilityservice/AccessibilityService",
        Signal("AccessibilityService API", 30, "ACCESSIBILITY"),
    ),
    (
        r"Landroid/accessibilityservice/AccessibilityNodeInfo",
        Signal("AccessibilityNodeInfo API", 26, "ACCESSIBILITY"),
    ),
    (
        r"Landroid/accessibilityservice/GestureDescription",
        Signal("Accessibility gesture API", 22, "ACCESSIBILITY"),
    ),
    # Capture
    (
        r"Landroid/media/AudioRecord",
        Signal("AudioRecord API", 28, "MICROPHONE"),
    ),
    (
        r"Landroid/media/MediaRecorder",
        Signal("MediaRecorder API", 26, "CAPTURE"),
    ),
    (
        r"Landroid/hardware/camera2?/",
        Signal("Camera API", 20, "CAMERA"),
    ),
    # Crypto / TLS
    (
        r"Ljavax/net/ssl/",
        Signal("SSL/TLS API", 12, "CRYPTO"),
    ),
    (
        r"Ljavax/crypto/",
        Signal("javax.crypto API", 12, "CRYPTO"),
    ),
    (
        r"Landroid/security/keystore",
        Signal("keystore API", 10, "CRYPTO"),
    ),
    # Networking
    (
        r"Lokhttp3/WebSocket",
        Signal("OkHttp WebSocket API", 18, "NETWORK"),
    ),
    (
        r"Ljava/net/http/WebSocket",
        Signal("WebSocket API", 18, "NETWORK"),
    ),
    (
        r"Lokhttp3/",
        Signal("OkHttp client", 12, "NETWORK"),
    ),
    (
        r"Ljava/net/HttpURLConnection",
        Signal("HttpURLConnection API", 12, "NETWORK"),
    ),
    (
        r"Lorg/apache/http/",
        Signal("Apache HTTP client", 10, "NETWORK"),
    ),
    (
        r"Lretrofit2/",
        Signal("Retrofit client", 8, "NETWORK"),
    ),
    (
        r"Lcom/android/volley",
        Signal("Volley client", 10, "NETWORK"),
    ),
    (
        r"Ljava/net/Socket",
        Signal("Socket API", 15, "NETWORK"),
    ),
    (
        r"Ljava/net/DatagramSocket",
        Signal("DatagramSocket API", 15, "NETWORK"),
    ),
    (
        r"Ljava/net/InetAddress",
        Signal("InetAddress API", 10, "NETWORK"),
    ),
    (
        r"Ljava/net/InetSocketAddress",
        Signal("InetSocketAddress API", 12, "NETWORK"),
    ),
    (
        r"Ljava/net/URL",
        Signal("URL API", 8, "NETWORK"),
    ),
    # Reflection / dynamic loading
    (
        r"Ldalvik/system/InMemoryDexClassLoader",
        Signal("InMemoryDexClassLoader API", 40, "DYNAMIC_LOADING"),
    ),
    (
        r"Ldalvik/system/DexClassLoader",
        Signal("DexClassLoader API", 40, "DYNAMIC_LOADING"),
    ),
    (
        r"Ljava/net/URLClassLoader",
        Signal("URLClassLoader API", 28, "DYNAMIC_LOADING"),
    ),
    (
        r"Ldalvik/system/PathClassLoader",
        Signal("PathClassLoader API", 20, "DYNAMIC_LOADING"),
    ),
    (
        r"Ljava/lang/ClassLoader;->(?:loadClass|defineClass)",
        Signal("dynamic class loading", 35, "DYNAMIC_LOADING"),
    ),
    (
        r"Ldalvik/system/DexFile",
        Signal("DexFile API", 18, "DYNAMIC_LOADING"),
    ),
    (
        r"Ljava/lang/Class;->forName",
        Signal("Class.forName API", 16, "REFLECTION"),
    ),
    (
        r"Ljava/lang/reflect/Method;->invoke",
        Signal("reflective invoke API", 16, "REFLECTION"),
    ),
    (
        r"Ljava/lang/reflect/",
        Signal("Reflection API", 14, "REFLECTION"),
    ),
    # Runtime / process execution
    (
        r"Ljava/lang/Runtime;->exec",
        Signal("Runtime.exec API", 40, "EXEC"),
    ),
    (
        r"Ljava/lang/ProcessBuilder",
        Signal("ProcessBuilder API", 38, "EXEC"),
    ),
    (
        r"Landroid/os/ShellCommand",
        Signal("ShellCommand API", 22, "EXEC"),
    ),
    # WebView
    (
        r"Landroid/webkit/WebView;->addJavascriptInterface",
        Signal("addJavascriptInterface API", 30, "WEBVIEW"),
    ),
    (
        r"Landroid/webkit/JavascriptInterface",
        Signal("JavascriptInterface API", 24, "WEBVIEW"),
    ),
    (
        r"Landroid/webkit/WebSettings;->setJavaScriptEnabled",
        Signal("WebView JS enabled", 14, "WEBVIEW"),
    ),
    (
        r"Landroid/webkit/WebView",
        Signal("WebView API", 12, "WEBVIEW"),
    ),
    # File access
    (
        r"Ljava/io/FileOutputStream",
        Signal("FileOutputStream API", 8, "FILE"),
    ),
    (
        r"Ljava/io/FileInputStream",
        Signal("FileInputStream API", 8, "FILE"),
    ),
    (
        r"Ljava/io/File",
        Signal("File I/O API", 6, "FILE"),
    ),
    (
        r"Ljava/nio/file/",
        Signal("NIO file API", 6, "FILE"),
    ),
    # Package management / device admin
    (
        r"Landroid/app/admin/DevicePolicyManager",
        Signal("DevicePolicyManager API", 30, "DEVICE_ADMIN"),
    ),
    (
        r"Landroid/app/admin/DeviceAdminReceiver",
        Signal("DeviceAdminReceiver API", 26, "DEVICE_ADMIN"),
    ),
    (
        r"Landroid/content/pm/PackageManager;->(?:queryIntentActivities|"
        r"getInstalledPackages|getInstalledApplications)",
        Signal("installed-app enumeration", 18, "PACKAGE"),
    ),
    (
        r"Landroid/content/pm/PackageManager",
        Signal("PackageManager API", 10, "PACKAGE"),
    ),
    (
        r"Landroid/app/NotificationListenerService",
        Signal("NotificationListenerService API", 22, "NOTIFICATION"),
    ),
    (
        r"Landroid/database/sqlite/",
        Signal("SQLite API", 10, "FILE"),
    ),
    # Misc sensitive surfaces
    (
        r"Landroid/telephony/TelephonyManager",
        Signal("TelephonyManager API", 12, "SMS"),
    ),
    (
        r"Landroid/view/accessibility/AccessibilityEvent",
        Signal("AccessibilityEvent API", 20, "ACCESSIBILITY"),
    ),
]

API_SIGNALS: List[Tuple[re.Pattern, Signal]] = [
    (re.compile(pattern), signal) for pattern, signal in _API_SPECS
]

# Command execution labelled as a behavior too (in addition to the API hit).
_COMMAND_EXEC_API = re.compile(
    r"Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder|Landroid/os/ShellCommand"
)


def signal_for_call(call_reference: str) -> Optional[Signal]:
    """Return the first (highest-priority) signal matching a call reference."""
    for pattern, signal in API_SIGNALS:
        if pattern.search(call_reference):
            return signal
    return None


def is_command_execution(call_reference: str) -> bool:
    return _COMMAND_EXEC_API.search(call_reference) is not None


# ---------------------------------------------------------------------------
# Behavior detectors (composed from the signals above)
# ---------------------------------------------------------------------------

_BOOT_CALLER_WEIGHT = 20
_ENCRYPTED_TRAFFIC_WEIGHT = 15
_DATA_COLLECTION_WEIGHT = 20
_COMMAND_EXEC_WEIGHT = 20

SENSITIVE_DATA_CATEGORIES = {"SMS", "CONTACTS", "CALL_LOG", "LOCATION"}


# ---------------------------------------------------------------------------
# Obfuscation signals
# ---------------------------------------------------------------------------

CLASS_NAME_SEGMENTS: List[str] = [
    "beacon",
    "bot",
    "c2", "crypt",
    "dexload",
    "dropper",
    "evil",
    "exfil",
    "exploit",
    "hook",
    "inject",
    "keylog",
    "loader",
    "malware",
    "payload",
    "ransom",
    "rat",
    "rootkit",
    "spy",
    "steal",
    "stub",
    "trojan",
]

METHOD_NAME_SEGMENTS: List[str] = [
    "beacon",
    "dexload",
    "dropper",
    "exfil",
    "hook",
    "inject",
    "loaddex",
    "popen",
    "rootkit",
    "steal",
    "shell",
]

_CLASS_SEGMENT_NAME = 12
_METHOD_SEGMENT_NAME = 6
_HIGH_ENTROPY_NAME = 10
_REFLECTION_HEAVY = 15
_ENCODED_STRING = 8
_NETWORK_INDICATOR_REF = 12


def suspicious_class_segments(identifier: str) -> List[str]:
    lowered = identifier.lower()
    return [seg for seg in CLASS_NAME_SEGMENTS if seg in lowered]


def suspicious_method_segments(identifier: str) -> List[str]:
    lowered = identifier.lower()
    return [seg for seg in METHOD_NAME_SEGMENTS if seg in lowered]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def high_identifier_entropy(
    identifier: str, threshold: float = 3.8
) -> bool:
    if len(identifier) < 6:
        return False
    return shannon_entropy(identifier) >= threshold


# ---------------------------------------------------------------------------
# String classification (network / encoding indicators)
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+"
    r"[a-z]{2,24}$",
    re.IGNORECASE,
)
_ENCODED_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
_ENCODED_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")

_URL_WEIGHT = 15
_IP_WEIGHT = 15
_DOMAIN_WEIGHT = 8
_SHELL_WEIGHT = 12


def _looks_base64(value: str) -> bool:
    if not (16 <= len(value) <= 512):
        return False
    if not _ENCODED_BASE64_RE.match(value):
        return False
    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return (has_lower and has_upper) or (has_lower and has_digit)


def classify_string(value: str) -> List[Signal]:
    """Classify one string into network/encoded signals (deterministic)."""
    if not value:
        return []
    compact = value.strip()
    if not compact:
        return []
    signals: List[Signal] = []

    if _URL_RE.match(compact) and ("http" in compact.lower() or "ftp" in compact.lower()):
        signals.append(Signal("hardcoded URL", _URL_WEIGHT, "NETWORK"))
    elif _IPV4_RE.match(compact):
        signals.append(Signal("hardcoded IP address", _IP_WEIGHT, "NETWORK"))
    elif _IPV6_RE.match(compact) and compact.count(":") >= 2:
        signals.append(Signal("hardcoded IPv6 address", _IP_WEIGHT, "NETWORK"))
    elif _DOMAIN_RE.match(compact):
        signals.append(Signal("hardcoded domain", _DOMAIN_WEIGHT, "NETWORK"))

    if _looks_base64(compact):
        signals.append(Signal("encoded string (base64-like)", _ENCODED_STRING, "ENCODED"))
    elif _ENCODED_HEX_RE.match(compact):
        signals.append(Signal("encoded string (hex-like)", _ENCODED_STRING, "ENCODED"))

    return signals


def string_signals_as_reasons(
    value: str, shell_commands: Optional[set] = None
) -> List[Signal]:
    signals = classify_string(value)
    if shell_commands is not None and value in shell_commands:
        signals = signals + [Signal("shell command string", _SHELL_WEIGHT, "EXEC")]
    return signals


# Behavior reason helpers ------------------------------------------------------

_BOOT_CALLER_LABEL = "called by BOOT_COMPLETED receiver"
_ENCRYPTED_TRAFFIC_LABEL = "encrypted network traffic"
_DATA_COLLECTION_LABEL = "sensitive data collection (API + network)"
_COMMAND_EXEC_LABEL = "command execution"
_REFLECTION_HEAVY_LABEL = "reflection-heavy code"
_ENCODED_STRINGS_LABEL = "encoded strings in methods"
_NETWORK_INDICATORS_LABEL = "references network indicators"
_HIGH_ENTROPY_LABEL = "high identifier entropy"
_SUSPICIOUS_NAME_LABEL = "suspicious identifier segments"