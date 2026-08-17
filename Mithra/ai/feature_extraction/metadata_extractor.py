import hashlib
from pathlib import Path


class MetadataExtractor:
    def __init__(self, apk, apk_path):
        self.apk = apk
        self.apk_path = apk_path

    def extract(self, report) -> None:
        sha256 = hashlib.sha256()

        with Path(self.apk_path).open("rb") as handle:
            while chunk := handle.read(8192):
                sha256.update(chunk)

        report.metadata.package_name = self.apk.get_package()
        report.metadata.app_name = self.apk.get_app_name()
        report.metadata.version_name = self.apk.get_androidversion_name()
        report.metadata.version_code = self.apk.get_androidversion_code()
        report.metadata.min_sdk = self.apk.get_min_sdk_version()
        report.metadata.target_sdk = self.apk.get_target_sdk_version()
        report.metadata.sha256 = sha256.hexdigest()
        report.metadata.apk_size = Path(self.apk_path).stat().st_size