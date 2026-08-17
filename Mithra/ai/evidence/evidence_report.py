from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ExecutiveReport:
    application: str = ""
    package: str = ""
    risk_level: str = "UNKNOWN"
    threat_score: int = 0


@dataclass
class ApkInformationReport:
    version: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    sha256: str = ""
    apk_size: int = 0


@dataclass
class PermissionSummaryReport:
    total: int = 0
    dangerous: List[str] = field(default_factory=list)


@dataclass
class ManifestSummaryReport:
    activities: int = 0
    services: int = 0
    receivers: int = 0
    providers: int = 0


@dataclass
class CertificateSummaryReport:
    issuer: str = ""
    subject: str = ""
    sha256: str = ""


@dataclass
class DexSummaryReport:
    classes: int = 0
    methods: int = 0
    api_counts: Dict[str, int] = field(default_factory=dict)
    top_api_calls: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_apis: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NetworkReport:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)


@dataclass
class BehaviorReport:
    behaviors: List[str] = field(default_factory=list)


@dataclass
class IocReport:
    sha256: str = ""
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)


@dataclass
class RecommendationReport:
    verdict: str = ""
    score: int = 0
    recommendation: str = ""


@dataclass
class EvidenceReport:
    executive: ExecutiveReport = field(default_factory=ExecutiveReport)
    apk_information: ApkInformationReport = field(default_factory=ApkInformationReport)
    permissions: PermissionSummaryReport = field(default_factory=PermissionSummaryReport)
    manifest: ManifestSummaryReport = field(default_factory=ManifestSummaryReport)
    certificate: CertificateSummaryReport = field(default_factory=CertificateSummaryReport)
    network: NetworkReport = field(default_factory=NetworkReport)
    dex: DexSummaryReport = field(default_factory=DexSummaryReport)
    behavior: BehaviorReport = field(default_factory=BehaviorReport)
    iocs: IocReport = field(default_factory=IocReport)
    recommendation: RecommendationReport = field(default_factory=RecommendationReport)