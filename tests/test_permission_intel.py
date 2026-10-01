from droidshield.permission_intel import analyze_permissions


def test_permission_intelligence_separates_requested_and_granted():
    result = analyze_permissions(
        [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.CAMERA",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        [
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
        ],
    )
    assert result["granted"] == [
        "android.permission.CAMERA",
        "android.permission.READ_SMS",
    ]
    assert "android.permission.SEND_SMS" in result["not_granted"]
    assert "android.permission.READ_SMS" in result["dangerous_granted"]
    assert "android.permission.SYSTEM_ALERT_WINDOW" in result["special_requested"]


def test_permission_combinations_are_explainable():
    result = analyze_permissions(
        [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        [],
    )
    assert "accessibility+overlay" in result["suspicious_combinations"]
    assert "overlay+package-install" in result["suspicious_combinations"]
    assert result["dangerous_granted_count"] == 0
