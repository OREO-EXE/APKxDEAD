import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from androguard.core.apk import APK

if __package__ in {None, ""}:
    from analysis_report import AnalysisReport
    from metadata_extractor import MetadataExtractor
    from permission_extractor import PermissionExtractor
    from manifest_extractor import ManifestExtractor
    from certificate_extractor import CertificateExtractor
    from string_extractor import StringExtractor
    from dex_extractor import DexExtractor
else:
    from .analysis_report import AnalysisReport
    from .metadata_extractor import MetadataExtractor
    from .permission_extractor import PermissionExtractor
    from .manifest_extractor import ManifestExtractor
    from .certificate_extractor import CertificateExtractor
    from .string_extractor import StringExtractor
    from .dex_extractor import DexExtractor

from ai.evidence.report_builder import build_report
from ai.evidence.terminal_report import print_report


def main() -> None:
    apk_path = PROJECT_ROOT / "samples" / "app.apk"

    print("=" * 70)
    print("ANDROID MALWARE ANALYSIS")
    print("=" * 70)

    print("[1/7] Loading APK...")
    apk = APK(str(apk_path))

    report = AnalysisReport()

    print("[2/7] Extracting Metadata...")
    MetadataExtractor(apk, apk_path).extract(report)

    print("[3/7] Extracting Permissions...")
    PermissionExtractor(apk).extract(report)

    print("[4/7] Extracting Manifest...")
    ManifestExtractor(apk).extract(report)

    print("[5/7] Extracting Certificate...")
    CertificateExtractor(apk).extract(report)

    print("[6/7] Extracting Strings...")
    StringExtractor(apk_path).extract(report)

    print("[7/7] Analyzing DEX...")
    DexExtractor(apk_path).extract(report)

    print("\nBuilding Professional Evidence Report...\n")
    evidence = build_report(report)
    print_report(evidence)

    print("\nAnalysis Complete.")


if __name__ == "__main__":
    main()