from droidshield.timeline import build_install_timeline


def test_install_timeline_is_sorted_and_contains_installer():
    items = [
        {
            "package": "com.example.new",
            "first_install_time": "2026-09-20 12:00:00",
            "last_update_time": "2026-09-20 12:00:00",
            "installer_package": "com.android.vending",
            "version_name": "1.0",
            "version_code": 1,
        },
        {
            "package": "com.example.old",
            "first_install_time": "2026-09-01 10:00:00",
            "last_update_time": "2026-09-15 11:00:00",
            "installer_package": "com.android.vending",
            "version_name": "2.0",
            "version_code": 2,
        },
    ]

    result = build_install_timeline(items)
    assert result[0]["package"] == "com.example.old"
    assert result[0]["type"] == "package_install"
    assert result[-1]["type"] == "package_update"
