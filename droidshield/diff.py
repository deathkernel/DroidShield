from __future__ import annotations

import json


def _stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


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
        (
            item.get("severity"),
            item.get("title"),
            item.get("package"),
        )
        for item in before.get("findings", [])
    }
    after_findings = {
        (
            item.get("severity"),
            item.get("title"),
            item.get("package"),
        )
        for item in after.get("findings", [])
    }

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
        "security_changes": security_changes,
        "findings": {
            "new": sorted(after_findings - before_findings),
            "resolved": sorted(before_findings - after_findings),
        },
    }
