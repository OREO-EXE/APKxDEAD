from pathlib import Path

from ai.feature_extraction.analysis_report import AnalysisReport
from ai.feature_extraction.metadata_extractor import MetadataExtractor
from ai.evidence.report_builder import build_report


class DummyAPK:
    def get_package(self):
        return "com.example.app"

    def get_app_name(self):
        return "Example App"

    def get_androidversion_name(self):
        return "1.0"

    def get_androidversion_code(self):
        return "1"

    def get_min_sdk_version(self):
        return "21"

    def get_target_sdk_version(self):
        return "34"


def test_metadata_extractor_updates_dataclass_fields(tmp_path):
    apk_path = tmp_path / "dummy.apk"
    apk_path.write_bytes(b"fake-apk")

    report = AnalysisReport()
    MetadataExtractor(DummyAPK(), apk_path).extract(report)

    assert report.metadata.app_name == "Example App"
    assert report.metadata.package_name == "com.example.app"
    assert report.metadata.version_name == "1.0"
    assert report.metadata.sha256


def test_build_report_returns_evidence_dataclass():
    report = AnalysisReport()
    report.metadata.package_name = "com.example.app"
    report.metadata.app_name = "Example App"
    report.metadata.version_name = "1.0"
    report.metadata.min_sdk = "21"
    report.metadata.target_sdk = "34"
    report.metadata.sha256 = "abc123"
    report.metadata.apk_size = 42

    report.permissions.permissions = ["android.permission.INTERNET"]
    report.permissions.suspicious_permissions = []

    report.manifest.activities = ["MainActivity"]
    report.manifest.services = []
    report.manifest.receivers = []
    report.manifest.providers = []

    report.certificate.issuer = "Issuer"
    report.certificate.subject = "Subject"
    report.certificate.sha256 = "abc123"

    report.strings.urls = ["https://example.com"]
    report.strings.domains = ["example.com"]
    report.strings.ips = ["8.8.8.8"]

    report.dex.total_classes = 10
    report.dex.total_methods = 20
    report.dex.api_counts = {"NETWORK": 2}
    report.dex.api_calls = ["android.net.Uri.parse"]
    report.dex.top_api_calls = [{"api": "android.net.Uri.parse", "count": 2}]
    report.dex.suspicious_apis = []

    evidence = build_report(report)

    assert evidence.executive.application == "Example App"
    assert evidence.permissions.total == 1
    assert evidence.manifest.activities == 1
    assert evidence.dex.classes == 10
    assert evidence.recommendation.verdict
