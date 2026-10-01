from __future__ import annotations

import json
from typing import Any


def _stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _package_map(report: dict) -> dict[str, dict[str, Any]]:
    return {
        item.get("package"): item
        for item in report.get("package_metadata", [])
        if item.get("package")
    }


def _set_change(left, right) -> dict[str, Any] | None:
    if _stable(left) == _stable(right):
        return None
    return {"before": left, "after": right}


def compare_package_metadata(before: dict, after: dict) -> dict[str, Any]:
    left = _package_map(before)
    right = _package_map(after)
    added = sorted(set(right) - set(left))
    removed = sorted(set(left) - set(right))
    changed: dict[str, dict[str, Any]] = {}
    fields = (
        "version_name",
        "version_code",
        "installer_package",
        "granted_permissions",
        "permissions",
        "active_roles",
        "apk_paths",
        "apk_sha256",
        "component_details",
        "enabled",
    )
    for package in sorted(set(left) & set(right)):
        changes = {}
        for field in fields:
            delta = _set_change(left[package].get(field), right[package].get(field))
            if delta:
                changes[field] = delta
        if changes:
            changed[package] = changes
    return {"added": added, "removed": removed, "changed": changed}


def compare_reports(before: dict, after: dict) -> dict:
    before_packages = set(before.get("packages", []))
    after_packages = set(after.get("packages", []))

    security_keys = (
        "accessibility_services",
        "device_policy",
        "overlay_appops",
        "notification_listeners",
        "default_launcher",
    )
    security_changes = {}
    for key in security_keys:
        left = before.get("security", {}).get(key)
        right = after.get("security", {}).get(key)
        if _stable(left) != _stable(right):
            security_changes[key] = {"before": left, "after": right}

    before_findings = {
        (item.get("severity"), item.get("title"), item.get("package"))
        for item in before.get("findings", [])
    }
    after_findings = {
        (item.get("severity"), item.get("title"), item.get("package"))
        for item in after.get("findings", [])
    }
    before_signals = set(before.get("risk", {}).get("signals", []))
    after_signals = set(after.get("risk", {}).get("signals", []))

    return {
        "risk": {
            "before": before.get("risk", {}),
            "after": after.get("risk", {}),
            "score_delta": (
                after.get("risk", {}).get("score", 0)
                - before.get("risk", {}).get("score", 0)
            ),
        },
        "packages": {
            "added": sorted(after_packages - before_packages),
            "removed": sorted(before_packages - after_packages),
        },
        "package_metadata": compare_package_metadata(before, after),
        "security_changes": security_changes,
        "risk_signals": {
            "added": sorted(after_signals - before_signals),
            "removed": sorted(before_signals - after_signals),
        },
        "runtime_network": {
            "process_count_delta": (
                len(after.get("runtime", {}).get("processes", []))
                - len(before.get("runtime", {}).get("processes", []))
            ),
            "socket_count_delta": (
                len(after.get("network", {}).get("sockets", []))
                - len(before.get("network", {}).get("sockets", []))
            ),
        },
        "findings": {
            "new": sorted(after_findings - before_findings),
            "resolved": sorted(before_findings - after_findings),
        },
    }
