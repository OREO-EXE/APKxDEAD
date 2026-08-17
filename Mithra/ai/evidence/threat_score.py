from colorama import Fore, Style, init

init(autoreset=True)


def line():
    print(Fore.CYAN + "═" * 70)


def section(title):
    print()
    print(Fore.YELLOW + "▶ " + title)
    print(Fore.CYAN + "─" * 70)


def print_report(report):

    line()
    print(Fore.GREEN + Style.BRIGHT + "        ANDROID MALWARE ANALYSIS REPORT")
    line()

    executive = report.executive

    section("Executive Summary")

    print(f"Application : {executive['application']}")
    print(f"Package     : {executive['package']}")
    print(f"Risk Level  : {executive['risk_level']}")
    print(f"Threat Score: {executive['threat_score']}/100")

    apk = report.apk_information

    section("APK Information")

    print(f"Version     : {apk['version']}")
    print(f"Min SDK     : {apk['min_sdk']}")
    print(f"Target SDK  : {apk['target_sdk']}")
    print(f"SHA256      : {apk['sha256']}")

    section("Permissions")

    print("Total Permissions :", report.permissions["total"])

    if report.permissions["dangerous"]:

        print(Fore.RED + "\nDangerous Permissions")

        for p in report.permissions["dangerous"]:
            print(" •", p)

    else:
        print(Fore.GREEN + "No dangerous permissions detected.")

    section("Behavior Analysis")

    for b in report.behavior["behaviors"]:
        print(" ✓", b)

    dex = report.dex

    section("DEX Statistics")

    print("Classes :", dex["classes"])
    print("Methods :", dex["methods"])

    section("API Categories")

    for category, count in sorted(dex["api_counts"].items()):

        print(f"{category:<20}{count}")

    section("Top Security APIs")

    suspicious = dex.get("suspicious_apis", [])

    if suspicious:

        for api in suspicious[:10]:

            print(f" • {api['api']} ({api['count']})")

    else:

        print("No suspicious APIs detected.")

    section("Indicators of Compromise")

    iocs = report.iocs

    print("SHA256")

    print(iocs["sha256"])

    if iocs["urls"]:

        print("\nURLs")

        for url in iocs["urls"][:10]:
            print(" •", url)

    if iocs["domains"]:

        print("\nDomains")

        for d in iocs["domains"][:10]:
            print(" •", d)

    if iocs["ips"]:

        print("\nIPs")

        for ip in iocs["ips"][:10]:
            print(" •", ip)

    section("Recommendation")

    print(report.recommendation["verdict"])

    line()