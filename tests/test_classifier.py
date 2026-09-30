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
    assert result["level"] == "HIGH"
    assert "accessibility-capable" in result["signals"]
