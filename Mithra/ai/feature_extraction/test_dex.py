from pathlib import Path

from feature_extraction.dex_extractor import extract


def main():
    # Project root
    project_root = Path(__file__).resolve().parents[1]

    # APK path
    apk = project_root / "samples" / "app.apk"

    # Extract features
    report = extract(apk)

    print("Classes:", report["total_classes"])
    print("Methods:", report["total_methods"])

    print("\nAPI Categories")
    for category, count in report["api_counts"].items():
        print(f"{category}: {count}")

    print("\nFirst 20 API Calls")
    for api in report["api_calls"][:20]:
        print(api)


if __name__ == "__main__":
    main()