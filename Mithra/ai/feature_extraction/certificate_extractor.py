class CertificateExtractor:
    def __init__(self, apk):
        self.apk = apk

    def extract(self, report) -> None:
        report.certificate.issuer = ""
        report.certificate.subject = ""
        report.certificate.sha256 = ""