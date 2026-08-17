class PermissionExtractor:
    def __init__(self, apk):
        self.apk = apk

    def extract(self, report) -> None:
        permissions = sorted(list(self.apk.get_permissions()))
        report.permissions.permissions = permissions
        report.permissions.suspicious_permissions = [
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