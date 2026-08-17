from ai.feature_extraction.apk_parser import APK
from ai.feature_extraction.analysis_report import AnalysisReport

from ai.feature_extraction.metadata_extractor import MetadataExtractor
from ai.feature_extraction.permission_extractor import PermissionExtractor
from ai.feature_extraction.manifest_extractor import ManifestExtractor
from ai.feature_extraction.certificate_extractor import CertificateExtractor
from ai.feature_extraction.string_extractor import StringExtractor
from ai.feature_extraction.dex_extractor import DexExtractor

from ai.feature_engineering.vector_builder import build_feature_vector

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APK_PATH = PROJECT_ROOT / "samples" / "app.apk"


print("=" * 60)
print("BUILDING REAL APK FEATURE VECTOR")
print("=" * 60)

apk = APK(str(APK_PATH))

report = AnalysisReport()

print("Extracting metadata...")
MetadataExtractor(apk, APK_PATH).extract(report)

print("Extracting permissions...")
PermissionExtractor(apk).extract(report)

print("Extracting manifest...")
ManifestExtractor(apk).extract(report)

print("Extracting certificate...")
CertificateExtractor(apk).extract(report)

print("Extracting strings...")
StringExtractor(APK_PATH).extract(report)

print("Analyzing DEX...")
DexExtractor(APK_PATH).extract(report)

print("\nBuilding 261-feature vector...")

X = build_feature_vector(report)

print("Feature vector shape:", X.shape)
print("Number of features:", len(X.columns))

print("\nNon-zero features:")

nonzero = X.loc[:, (X != 0).any(axis=0)]

for column in nonzero.columns:
    print(f"{column}: {X.iloc[0][column]}")

print("\nSUCCESS.")