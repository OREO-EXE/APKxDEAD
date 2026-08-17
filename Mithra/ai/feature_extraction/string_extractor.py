import re
from pathlib import Path


class StringExtractor:
    def __init__(self, apk_path):
        self.apk_path = apk_path

    def extract(self, report) -> None:
        urls: set[str] = set()
        domains: set[str] = set()
        ips: set[str] = set()

        with Path(self.apk_path).open("rb") as handle:
            data = handle.read().decode(errors="ignore")

        url_pattern = re.compile(r"https?://[^\s\"'>]+")
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_pattern = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

        urls.update(url_pattern.findall(data))
        ips.update(ip_pattern.findall(data))
        domains.update(domain_pattern.findall(data))

        report.strings.urls = sorted(urls)
        report.strings.domains = sorted(domains)
        report.strings.ips = sorted(ips)