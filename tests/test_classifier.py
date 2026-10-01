from droidshield.classifier import classify_package


def test_system_package_is_protected():
    result = classify_package("com.android.settings", {
        "permissions": ["android.permission.SYSTEM_ALERT_WINDOW"],
        "system_path_evidence": True,
    })
    assert result["protected_system"] is True
    assert result["system_evidence"]["path"] is True
    assert result["remediation_allowed"] is False


def test_prefix_fallback_is_explicit():
    result = classify_package("com.google.android.fakeapp", {"permissions": []})
    assert result["protected_system"] is True
    assert result["system_evidence"]["prefix_only"] is True
    assert result["remediation_allowed"] is False


def test_risky_capabilities_raise_score():
    result = classify_package("com.example.suspicious", {
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ]
    })
    assert result["level"] == "MEDIUM"
    assert result["capability_score"] == 60
    assert result["corroboration_score"] == 0
    assert "accessibility-capable" in result["signals"]


def test_sensitive_capabilities_become_high_with_active_privileged_role():
    result = classify_package("com.example.suspicious", {
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        "active_roles": ["accessibility"],
    })
    assert result["level"] == "HIGH"
    assert result["corroboration_score"] == 25
    assert "active-accessibility" in result["signals"]


def test_capability_only_does_not_make_system_screen_recorder_high():
    result = classify_package("com.miui.screenrecorder", {
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.READ_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
        ],
        "system_flag_evidence": True,
    })
    assert result["protected_system"] is True
    assert result["level"] == "MEDIUM"
    assert result["remediation_allowed"] is False
