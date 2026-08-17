from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MetadataReport:
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    apk_size: int = 0


@dataclass
class PermissionReport:
    permissions: List[str] = field(default_factory=list)
    suspicious_permissions: List[str] = field(default_factory=list)


@dataclass
class ManifestReport:
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)


@dataclass
class CertificateReport:
    issuer: str = ""
    subject: str = ""
    sha256: str = ""


@dataclass
class StringReport:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)


@dataclass
class DexReport:
    total_classes: int = 0
    total_methods: int = 0
    api_counts: Dict[str, int] = field(default_factory=dict)
    api_calls: List[str] = field(default_factory=list)
    top_api_calls: List[Dict[str, int]] = field(default_factory=list)
    suspicious_apis: List[Dict[str, int]] = field(default_factory=list)


@dataclass
class AnalysisReport:
    metadata: MetadataReport = field(default_factory=MetadataReport)
    permissions: PermissionReport = field(default_factory=PermissionReport)
    manifest: ManifestReport = field(default_factory=ManifestReport)
    certificate: CertificateReport = field(default_factory=CertificateReport)
    strings: StringReport = field(default_factory=StringReport)
    dex: DexReport = field(default_factory=DexReport)