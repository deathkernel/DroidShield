from droidshield.collectors import collect_package_metadata


class FakeClient:
    def package_dump(self, serial, package):
        return """
        ApplicationInfo{pkgFlags=[ SYSTEM HAS_CODE ] versionCode=42 versionName=1.2.3}
        userId=10042
        firstInstallTime=2026-09-01 10:20:30
        lastUpdateTime=2026-09-20 11:22:33
        installerPackageName=com.android.vending
        enabled=true
        android.permission.SYSTEM_ALERT_WINDOW
        android.permission.BIND_ACCESSIBILITY_SERVICE
        """

    def package_paths(self, serial, package):
        return ["/system/app/Foo/Foo.apk"]

    def package_sha256(self, serial, package):
        return {"/system/app/Foo/Foo.apk": "a" * 64}


def test_package_metadata_extracts_forensic_fields():
    result = collect_package_metadata(FakeClient(), "serial", "com.example.foo", hash_apk=True)
    assert result["version_name"] == "1.2.3"
    assert result["version_code"] == 42
    assert result["installer_package"] == "com.android.vending"
    assert "android.permission.SYSTEM_ALERT_WINDOW" in result["permissions"]
    assert result["system_path_evidence"] is True
    assert result["system_flag_evidence"] is True
    assert len(result["apk_sha256"]["/system/app/Foo/Foo.apk"]) == 64
