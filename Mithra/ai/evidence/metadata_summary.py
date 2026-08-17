def build_metadata(raw, report):

    report.executive.app_name = raw.metadata.app_name

    report.executive.package_name = raw.metadata.package_name

    report.apk.version = raw.metadata.version_name

    report.apk.min_sdk = raw.metadata.min_sdk

    report.apk.target_sdk = raw.metadata.target_sdk

    report.apk.size = f"{raw.metadata.apk_size / (1024 * 1024):.2f} MB"

    report.apk.md5 = raw.metadata.md5

    report.apk.sha1 = raw.metadata.sha1

    report.apk.sha256 = raw.metadata.sha256