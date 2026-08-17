class ManifestExtractor:
    def __init__(self, apk):
        self.apk = apk

    def extract(self, report) -> None:
        report.manifest.activities = list(self.apk.get_activities())
        report.manifest.services = list(self.apk.get_services())
        report.manifest.receivers = list(self.apk.get_receivers())
        report.manifest.providers = list(self.apk.get_providers())