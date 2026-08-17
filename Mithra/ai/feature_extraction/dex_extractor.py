from collections import Counter
from androguard.misc import AnalyzeAPK

try:
    from .api_classifier import classify_api
except ImportError:
    from api_classifier import classify_api


NOISE_APIS = {
    "StringBuilder",
    "StringBuffer",
    "Object;-><init>",
    "Intrinsics",
    "Enum;->ordinal",
    "CollectionsKt",
    "ArraysKt",
    "ComposerKt",
    "Lambda;-><init>"
}

SUSPICIOUS_APIS = [
    "Runtime.exec",
    "DexClassLoader",
    "PathClassLoader",
    "SmsManager",
    "TelephonyManager",
    "Cipher",
    "MessageDigest",
    "Socket",
    "AccessibilityService",
    "WebView",
    "LocationManager"
]


class DexExtractor:

    def __init__(self, apk_path):
        self.apk_path = apk_path

    def extract(self, report):

        print("   ├── Parsing DEX files...")

        _, dex_files, _ = AnalyzeAPK(str(self.apk_path))

        total_classes = 0
        total_methods = 0

        api_categories = Counter()
        api_frequency = Counter()

        for dex in dex_files:

            for cls in dex.get_classes():

                total_classes += 1

                for method in cls.get_methods():

                    total_methods += 1

                    code = method.get_code()

                    if code is None:
                        continue

                    try:

                        bc = code.get_bc()

                        for instruction in bc.get_instructions():

                            if not instruction.get_name().startswith("invoke"):
                                continue

                            api = instruction.get_output()

                            if any(x in api for x in NOISE_APIS):
                                continue

                            api_frequency[api] += 1

                            category = classify_api(api)

                            api_categories[category] += 1

                    except Exception:
                        continue

        suspicious = []

        for api, count in api_frequency.items():
            if any(x in api for x in SUSPICIOUS_APIS):
                suspicious.append({"api": api, "count": count})

        report.dex.total_classes = total_classes
        report.dex.total_methods = total_methods
        report.dex.api_counts = dict(api_categories)
        report.dex.api_calls = [api for api, _ in api_frequency.most_common(100)]
        report.dex.top_api_calls = [
            {"api": api, "count": count}
            for api, count in api_frequency.most_common(20)
        ]
        report.dex.suspicious_apis = sorted(
            suspicious,
            key=lambda item: item["count"],
            reverse=True,
        )

        print(f"   ├── Classes : {total_classes:,}")
        print(f"   ├── Methods : {total_methods:,}")
        print(f"   └── APIs    : {len(api_frequency):,}")