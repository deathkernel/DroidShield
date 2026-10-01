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


def test_compare_reports_tracks_metadata_signals_and_runtime_deltas():
    before = {
        "packages": ["com.example"],
        "package_metadata": [{"package": "com.example", "granted_permissions": ["android.permission.CAMERA"], "active_roles": ["overlay"]}],
        "risk": {"score": 10, "signals": ["sensitive-capabilities:com.example"]},
        "runtime": {"processes": ["p1"]},
        "network": {"sockets": ["s1"]},
        "security": {},
        "findings": [],
    }
    after = {
        "packages": ["com.example"],
        "package_metadata": [{"package": "com.example", "granted_permissions": [], "active_roles": []}],
        "risk": {"score": 5, "signals": []},
        "runtime": {"processes": ["p1", "p2"]},
        "network": {"sockets": []},
        "security": {},
        "findings": [],
    }
    result = compare_reports(before, after)
    assert "com.example" in result["package_metadata"]["changed"]
    assert result["risk_signals"]["removed"] == ["sensitive-capabilities:com.example"]
    assert result["runtime_network"]["process_count_delta"] == 1
    assert result["runtime_network"]["socket_count_delta"] == -1
