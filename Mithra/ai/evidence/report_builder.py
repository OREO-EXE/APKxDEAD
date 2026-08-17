from .evidence_report import EvidenceReport


def build_report(raw) -> EvidenceReport:
    report = EvidenceReport()
    metadata = raw.metadata
    permissions = raw.permissions.permissions
    manifest = raw.manifest
    dex = raw.dex

    dangerous = [
        permission
        for permission in permissions
        if any(
            marker in permission
            for marker in [
                "REQUEST_INSTALL_PACKAGES",
                "QUERY_ALL_PACKAGES",
                "MANAGE_EXTERNAL_STORAGE",
                "RECEIVE_SMS",
                "SEND_SMS",
                "READ_SMS",
                "SYSTEM_ALERT_WINDOW",
            ]
        )
    ]

    api_counts = dex.api_counts
    behaviors = []
    if api_counts.get("NETWORK", 0):
        behaviors.append("Network Communication")
    if api_counts.get("CRYPTO", 0):
        behaviors.append("Cryptography Usage")
    if api_counts.get("FILE", 0):
        behaviors.append("File Operations")
    if api_counts.get("REFLECTION", 0):
        behaviors.append("Reflection Usage")
    if dangerous:
        behaviors.append("Sensitive Permission Usage")
    if dex.suspicious_apis:
        behaviors.append("Suspicious API Usage")

    score = len(dangerous) * 10
    score += api_counts.get("NETWORK", 0) // 100
    score += api_counts.get("CRYPTO", 0) // 25
    score += len(dex.suspicious_apis) * 5
    score = min(score, 100)

    if score < 20:
        level = "LOW"
        verdict = "Likely Safe"
        recommendation_text = "No immediate threats detected."
    elif score < 40:
        level = "MEDIUM"
        verdict = "Review Recommended"
        recommendation_text = "Manual review is recommended before installation."
    elif score < 70:
        level = "HIGH"
        verdict = "Potentially Malicious"
        recommendation_text = "Manual review is recommended before installation."
    else:
        level = "CRITICAL"
        verdict = "Do Not Install"
        recommendation_text = "Do NOT install this application."

    report.executive.application = metadata.app_name
    report.executive.package = metadata.package_name
    report.executive.risk_level = level
    report.executive.threat_score = score

    report.apk_information.version = metadata.version_name
    report.apk_information.min_sdk = metadata.min_sdk
    report.apk_information.target_sdk = metadata.target_sdk
    report.apk_information.sha256 = metadata.sha256
    report.apk_information.apk_size = metadata.apk_size

    report.permissions.total = len(permissions)
    report.permissions.dangerous = dangerous

    report.manifest.activities = len(manifest.activities)
    report.manifest.services = len(manifest.services)
    report.manifest.receivers = len(manifest.receivers)
    report.manifest.providers = len(manifest.providers)

    report.certificate.issuer = raw.certificate.issuer
    report.certificate.subject = raw.certificate.subject
    report.certificate.sha256 = raw.certificate.sha256

    report.network.urls = raw.strings.urls
    report.network.domains = raw.strings.domains
    report.network.ips = raw.strings.ips

    report.dex.classes = dex.total_classes
    report.dex.methods = dex.total_methods
    report.dex.api_counts = dex.api_counts
    report.dex.top_api_calls = dex.top_api_calls
    report.dex.suspicious_apis = dex.suspicious_apis

    report.behavior.behaviors = behaviors

    report.iocs.sha256 = metadata.sha256
    report.iocs.urls = raw.strings.urls
    report.iocs.domains = raw.strings.domains
    report.iocs.ips = raw.strings.ips

    report.recommendation.verdict = verdict
    report.recommendation.score = score
    report.recommendation.recommendation = recommendation_text

    return report