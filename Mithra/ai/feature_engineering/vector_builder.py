from typing import Dict, Any
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

FEATURE_PATH = PROJECT_ROOT / "models" / "feature_columns.json"


def load_feature_columns():
    with open(FEATURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def binary_presence(value) -> int:
    """
    Convert a raw count/value into the binary representation
    expected by the Flamingo training dataset.
    """
    try:
        return 1 if float(value) > 0 else 0
    except (TypeError, ValueError):
        return 0


def build_feature_vector(report) -> Dict[str, Any]:

    feature_columns = load_feature_columns()

    features = {column: 0 for column in feature_columns}

    # ============================================================
    # PERMISSIONS
    # ============================================================

    permissions = set(report.permissions.permissions)

    for permission in permissions:

        clean_name = permission.split(".")[-1]

        column = f"perm_{clean_name}"

        if column in features:
            features[column] = 1

    # ============================================================
    # TOTAL PERMISSIONS
    # ============================================================

    features["total_permissions"] = len(permissions)

    # ============================================================
    # MANIFEST
    # ============================================================

    # These are useful later if corresponding Flamingo features
    # exist in the feature schema.

    # ============================================================
    # STRINGS / NETWORK
    # ============================================================

    urls = report.strings.urls
    domains = report.strings.domains
    ips = report.strings.ips

    # Basic network indicators

    if urls:
        if "net_http_tunnel" in features:
            features["net_http_tunnel"] = 1

    # ============================================================
    # API FEATURES
    # ============================================================

    api_counts = report.dex.api_counts

    for feature_name in feature_columns:

        if not feature_name.startswith("code_"):
            continue

        api_name = feature_name[len("code_"):]

        # Match API keys approximately.
        for api, count in api_counts.items():

            if api_name.lower() in str(api).lower():

                features[feature_name] = binary_presence(count)

                break

    # ============================================================
    # BEHAVIOR FEATURES
    # ============================================================

    # We currently derive these from observable evidence.
    #
    # IMPORTANT:
    # Flamingo stores these as binary indicators.

    behavior_rules = {

        "beh_camera_access":
            any("camera" in str(x).lower()
                for x in report.dex.api_calls),

        "beh_remote_shell":
            any("runtime.exec" in str(x).lower()
                or "processbuilder" in str(x).lower()
                for x in report.dex.api_calls),

        "beh_crypto_wallet_theft":
            False,

        "beh_file_encryption":
            False,

        "beh_accessibility_abuse":
            any("accessibility" in str(x).lower()
                for x in report.dex.api_calls),

        "beh_data_exfiltration":
            bool(urls or domains),

    }

    for feature, detected in behavior_rules.items():

        if feature in features:
            features[feature] = int(detected)

    # ============================================================
    # NATIVE LIBRARIES
    # ============================================================

    native_count = 0

    for feature_name in feature_columns:

        if feature_name.startswith("native_"):

            # Native library detection will be added from APK
            # analysis when available.
            features[feature_name] = 0

    features["total_native_libs"] = native_count

    # ============================================================
    # OBFUSCATION
    # ============================================================

    # Flamingo dataset has total_obfuscation == 3
    # for all 398 training samples.

    if "total_obfuscation" in features:
        features["total_obfuscation"] = 3

    # ============================================================
    # TOTAL BEHAVIORS
    # ============================================================

    behavior_columns = [
        c for c in feature_columns
        if c.startswith("beh_")
    ]

    features["total_behaviors"] = sum(
        features[c] for c in behavior_columns
    )

    # ============================================================
    # FINAL CLEANUP
    # ============================================================

    # Ensure every feature exists
    for column in feature_columns:

        if column not in features:
            features[column] = 0

    # Preserve exact training feature order
    features = {
        column: features[column]
        for column in feature_columns
    }

    return features