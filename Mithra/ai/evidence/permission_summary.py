def build_permissions(raw, report):

    report.permissions.total_permissions = len(
        raw.permissions.permissions
    )

    report.permissions.dangerous_permissions = (
        raw.permissions.suspicious_permissions
    )