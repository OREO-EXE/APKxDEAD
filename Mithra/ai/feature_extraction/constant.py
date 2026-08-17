"""
Global constants used across the Feature Extraction module.
"""

from pathlib import Path

# -------------------------
# Project Paths
# -------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"

# -------------------------
# Malware Behaviour Categories
# -------------------------

NETWORK = "NETWORK"
SMS = "SMS"
CRYPTO = "CRYPTO"
FILE = "FILE"
REFLECTION = "REFLECTION"
DYNAMIC_LOADING = "DYNAMIC_LOADING"
RUNTIME = "RUNTIME"
LOCATION = "LOCATION"
CAMERA = "CAMERA"
DATABASE = "DATABASE"
WEBVIEW = "WEBVIEW"
OTHER = "OTHER"

API_CATEGORIES = [
    NETWORK,
    SMS,
    CRYPTO,
    FILE,
    REFLECTION,
    DYNAMIC_LOADING,
    RUNTIME,
    LOCATION,
    CAMERA,
    DATABASE,
    WEBVIEW,
    OTHER,
]

# -------------------------
# Suspicious Permissions
# -------------------------

SUSPICIOUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}

# -------------------------
# Android Manifest Filename
# -------------------------

ANDROID_MANIFEST = "AndroidManifest.xml"

# -------------------------
# Default Report Filename
# -------------------------

DEFAULT_REPORT_NAME = "analysis_report.json"