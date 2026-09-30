from droidshield.detection import correlate


def test_active_sensitive_package_is_correlated():
    report = {
        "third_party_packages": ["com.example.bad"],
        "package_assessments": [
            {
                "package": "com.example.bad",
                "level": "HIGH",
                "score": 60,
            }
        ],
        "security": {
            "accessibility_services": ["com.example.bad/com.example.BadService"],
            "device_policy": [],
            "overlay_appops": [],
            "notification_listeners": [],
            "default_launcher": "",
            "active_component_packages": {
                "accessibility": ["com.example.bad"],
                "device_policy": [],
                "overlay": [],
                "notification": [],
                "launcher": [],
            },
        },
    }
    result = correlate(report)
    assert result["level"] == "HIGH"
    assert "correlated-active-accessibility:com.example.bad" in result["signals"]
    assert result["heuristic"] is True
