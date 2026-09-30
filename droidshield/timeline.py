from __future__ import annotations

from datetime import datetime
from typing import Any


def _parse_android_time(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            continue
    return value


def build_install_timeline(package_metadata: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for item in package_metadata:
        package = item.get("package")
        if not package:
            continue

        first_install = _parse_android_time(item.get("first_install_time"))
        last_update = _parse_android_time(item.get("last_update_time"))

        if first_install:
            events.append({
                "timestamp": first_install,
                "type": "package_install",
                "package": package,
                "installer": item.get("installer_package"),
                "version_name": item.get("version_name"),
                "version_code": item.get("version_code"),
            })

        if last_update and last_update != first_install:
            events.append({
                "timestamp": last_update,
                "type": "package_update",
                "package": package,
                "installer": item.get("installer_package"),
                "version_name": item.get("version_name"),
                "version_code": item.get("version_code"),
            })

    return sorted(events, key=lambda event: event["timestamp"])
