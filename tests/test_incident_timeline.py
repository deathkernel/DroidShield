from droidshield.timeline import build_incident_timeline


def test_incident_timeline_includes_scan_privilege_and_remediation():
    report = {
        "generated_at": "2026-09-30T10:00:00+00:00",
        "risk": {"level": "MEDIUM", "score": 45},
        "package_metadata": [],
        "security": {
            "active_component_packages": {
                "accessibility": ["com.example.bad"],
                "device_policy": [],
                "overlay": [],
                "notification": [],
                "launcher": [],
            }
        },
    }
    result = build_incident_timeline(
        report,
        [{
            "timestamp": "2026-09-30T10:05:00+00:00",
            "package": "com.example.bad",
            "action": "disable",
            "verified": True,
        }],
    )

    types = [event["type"] for event in result]
    assert "security_scan" in types
    assert "active_privileged_role" in types
    assert "remediation" in types
