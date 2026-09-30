from droidshield.scanner import scan_device


class FakeClient:
    def __init__(self):
        self.serial = "fixture"

    def resolve_serial(self, requested):
        return requested or self.serial

    def properties(self, serial):
        return {
            "ro.product.manufacturer": "Fixture",
            "ro.product.model": "Android-Lab",
            "ro.build.version.release": "14",
            "ro.build.version.sdk": "34",
            "ro.build.version.security_patch": "2026-09-01",
        }

    def packages(self, serial):
        return ["com.android.settings", "com.example.bad"]

    def third_party_packages(self, serial):
        return ["com.example.bad"]

    def package_dump(self, serial, package):
        if package == "com.example.bad":
            return """
            ApplicationInfo{pkgFlags=[ HAS_CODE ] versionCode=9 versionName=3.1.0}
            userId=10088
            firstInstallTime=2026-09-20 10:00:00
            lastUpdateTime=2026-09-22 12:00:00
            installerPackageName=com.android.vending
            enabled=true
            android.permission.BIND_ACCESSIBILITY_SERVICE
            android.permission.SYSTEM_ALERT_WINDOW
            android.permission.REQUEST_INSTALL_PACKAGES
            ServiceInfo{abc com.example.bad.BadService}
            """
        return """
        ApplicationInfo{pkgFlags=[ SYSTEM HAS_CODE ] versionCode=1 versionName=1.0}
        userId=1000
        enabled=true
        android.permission.SYSTEM_ALERT_WINDOW
        """

    def package_paths(self, serial, package):
        if package == "com.example.bad":
            return ["/data/app/com.example.bad/base.apk"]
        return ["/system/app/Settings/Settings.apk"]

    def shell(self, command, serial=None):
        if command.startswith("settings list secure"):
            return "adb_enabled=1\n"
        if command.startswith("settings list global"):
            return "package_verifier_enable=1\n"
        if command.startswith("settings get secure enabled_accessibility_services"):
            return "com.example.bad/com.example.bad.BadService"
        if command.startswith("dumpsys device_policy"):
            return ""
        if command.startswith("cmd appops query-op"):
            return "Uid mode: allow com.example.bad"
        if command.startswith("settings get secure enabled_notification_listeners"):
            return ""
        if command.startswith("cmd package resolve-activity"):
            return "priority=0\ncom.example.bad/.MainActivity"
        if command == "ps -A":
            return "u0_a88 1234 1 0 0 0 S com.example.bad"
        if command == "dumpsys activity services":
            return "ServiceRecord{com.example.bad/.BadService}"
        if command.startswith("logcat -d"):
            return "09-30 10:00:00 ActivityManager: package com.example.bad install"
        if command.startswith("ss -tunap") or command.startswith("netstat -tunap"):
            return "tcp ESTAB 0 0 10.0.0.2:12345 1.2.3.4:443 users:(pid=1234,fd=7)"
        if command.startswith("dumpsys connectivity"):
            return "NetworkAgentInfo"
        raise AssertionError(f"unexpected command: {command}")
