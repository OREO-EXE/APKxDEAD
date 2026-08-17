def build_manifest(raw, report):
    report.manifest.activities = len(
        raw.manifest.activities
    )

    report.manifest.services = len(
        raw.manifest.services
    )

    report.manifest.receivers = len(
        raw.manifest.receivers
    )

    report.manifest.providers = len(
        raw.manifest.providers
    )