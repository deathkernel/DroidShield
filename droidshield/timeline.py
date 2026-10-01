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


def build_incident_timeline(
    report: dict[str, Any],
    remediation_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    events = list(build_install_timeline(report.get("package_metadata", [])))
    scan_time = report.get("generated_at")

    if scan_time:
        events.append({
            "timestamp": scan_time,
            "type": "security_scan",
            "risk_level": report.get("risk", {}).get("level"),
            "risk_score": report.get("risk", {}).get("score"),
        })

        roles = report.get("security", {}).get("active_component_packages", {})
        for role, packages in roles.items():
            for package in packages:
                events.append({
                    "timestamp": scan_time,
                    "type": "active_privileged_role",
                    "package": package,
                    "role": role,
                })

        for event in report.get("runtime", {}).get("security_events", {}).get("events", []):
            events.append({
                "timestamp": scan_time,
                "type": "runtime_security_event",
                "package": event.get("package"),
                "event_type": event.get("event_type"),
                "categories": event.get("categories", []),
                "line": event.get("line"),
            })

    for record in remediation_records or []:
        timestamp = record.get("timestamp")
        if timestamp:
            events.append({
                "timestamp": timestamp,
                "type": "remediation",
                "package": record.get("package"),
                "action": record.get("action"),
                "verified": record.get("verified"),
            })

    return sorted(events, key=lambda event: event.get("timestamp", ""))
