from textwrap import shorten

LINE = "=" * 70
SECTION = "-" * 70


def print_report(report) -> None:
    print()
    print(LINE)
    print("           ANDROID MALWARE ANALYSIS REPORT")
    print(LINE)

    executive = report.executive
    print("\nEXECUTIVE SUMMARY")
    print(SECTION)
    print(f"Application      : {executive.application or 'N/A'}")
    print(f"Package          : {executive.package or 'N/A'}")
    print(f"Risk Level       : {executive.risk_level or 'UNKNOWN'}")
    print(f"Threat Score     : {executive.threat_score}/100")

    apk = report.apk_information
    print("\nAPK INFORMATION")
    print(SECTION)
    print(f"Version          : {apk.version or 'N/A'}")
    print(f"Min SDK          : {apk.min_sdk or 'N/A'}")
    print(f"Target SDK       : {apk.target_sdk or 'N/A'}")
    print(f"APK Size         : {apk.apk_size or 'Unknown'} bytes")
    print("\nSHA256")
    print(shorten(apk.sha256 or "N/A", width=64, placeholder="..."))

    permissions = report.permissions
    print("\nPERMISSIONS")
    print(SECTION)
    dangerous = permissions.dangerous
    print(f"Total            : {permissions.total}")
    print(f"Dangerous        : {len(dangerous)}")
    if dangerous:
        print("\nDangerous Permissions")
        for permission in dangerous:
            print(f"  • {permission}")

    manifest = report.manifest
    print("\nMANIFEST")
    print(SECTION)
    print(f"Activities       : {manifest.activities}")
    print(f"Services         : {manifest.services}")
    print(f"Receivers        : {manifest.receivers}")
    print(f"Providers        : {manifest.providers}")

    certificate = report.certificate
    print("\nCERTIFICATE")
    print(SECTION)
    print(f"Issuer           : {certificate.issuer or 'Unknown'}")
    print(f"Subject          : {certificate.subject or 'Unknown'}")
    print("\nCertificate SHA256")
    print(shorten(certificate.sha256 or "N/A", width=64, placeholder="..."))

    dex = report.dex
    print("\nDEX ANALYSIS")
    print(SECTION)
    print(f"Classes          : {dex.classes:,}")
    print(f"Methods          : {dex.methods:,}")
    print("\nAPI Categories")
    for category, count in dex.api_counts.items():
        print(f"  {category:<15} {count}")
    print("\nTop API Calls")
    for api in dex.top_api_calls[:10]:
        print(f"  • {api['api']} ({api['count']})")
    suspicious = dex.suspicious_apis
    if suspicious:
        print("\nSuspicious APIs")
        for api in suspicious[:10]:
            print(f"  ⚠ {api['api']} ({api['count']})")

    network = report.network
    print("\nNETWORK INDICATORS")
    print(SECTION)
    print(f"URLs             : {len(network.urls)}")
    print(f"Domains          : {len(network.domains)}")
    print(f"IP Addresses     : {len(network.ips)}")
    if network.urls:
        print("\nURLs")
        for url in network.urls[:10]:
            print(f"  • {url}")

    behavior = report.behavior
    print("\nBEHAVIOR ANALYSIS")
    print(SECTION)
    if behavior.behaviors:
        for item in behavior.behaviors:
            print(f"  ✓ {item}")
    else:
        print("  No suspicious behaviors detected.")

    recommendation = report.recommendation
    print("\nRECOMMENDATION")
    print(SECTION)
    print(f"Verdict          : {recommendation.verdict or 'Unknown'}")
    print(f"Threat Score     : {recommendation.score}/100")
    print(f"Recommendation   : {recommendation.recommendation}")

    print()
    print(LINE)