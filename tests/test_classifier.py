from droidshield.classifier import classify_package


def test_system_package_is_protected():
    result = classify_package("com.android.settings", {
        "permissions": ["android.permission.SYSTEM_ALERT_WINDOW"]
    })
    assert result["protected_system_prefix"] is True
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
