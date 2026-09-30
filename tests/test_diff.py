from droidshield.diff import compare_reports


def test_compare_reports_tracks_security_and_package_changes():
    before = {
        "packages": ["com.example.bad", "com.example.keep"],
        "security": {
            "accessibility_services": ["com.example.bad/Service"],
            "device_policy": [],
            "overlay_appops": [],
            "notification_listeners": [],
            "default_launcher": "com.example.keep/.Main",
        },
        "risk": {"score": 70, "level": "HIGH"},
        "findings": [
            {"severity": "MEDIUM", "title": "Suspicious", "package": "com.example.bad"}
        ],
    }
    after = {
        "packages": ["com.example.keep"],
        "security": {
            "accessibility_services": [],
            "device_policy": [],
            "overlay_appops": [],
            "notification_listeners": [],
            "default_launcher": "com.example.keep/.Main",
        },
        "risk": {"score": 30, "level": "MEDIUM"},
        "findings": [],
    }

    result = compare_reports(before, after)

    assert result["packages"]["removed"] == ["com.example.bad"]
    assert result["risk"]["score_delta"] == -40
    assert "accessibility_services" in result["security_changes"]
    assert result["findings"]["resolved"] == [
        ("MEDIUM", "Suspicious", "com.example.bad")
    ]
