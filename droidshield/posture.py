from __future__ import annotations


def _check(name: str, status: str, detail: str, severity: str = "info") -> dict:
    return {"name": name, "status": status, "detail": detail, "severity": severity}


def assess_posture(report: dict) -> dict:
    device = report.get("device", {})
    security = report.get("security", {})
    checks = []
    patch = device.get("security_patch") or "unknown"
    checks.append(_check("security_patch", "observed" if patch != "unknown" else "unknown", f"Security patch: {patch}"))
    checks.append(_check("accessibility", "attention" if security.get("accessibility_services") else "clear", "Enabled accessibility services should be attributable to trusted apps.", "warning" if security.get("accessibility_services") else "info"))
    checks.append(_check("device_policy", "attention" if security.get("device_policy") else "clear", "Active device-admin policy should be expected.", "warning" if security.get("device_policy") else "info"))
    checks.append(_check("overlays", "attention" if security.get("overlay_appops") else "clear", "Overlay access can obscure UI and capture interaction context.", "warning" if security.get("overlay_appops") else "info"))
    checks.append(_check("notification_listeners", "attention" if security.get("notification_listeners") else "clear", "Notification listeners can observe notification content.", "warning" if security.get("notification_listeners") else "info"))
    coverage = report.get("metadata_coverage", {})
    errors = coverage.get("packages_with_collection_errors", 0)
    unanalyzed = coverage.get("packages_unanalyzed", 0)
    incomplete = errors or unanalyzed
    detail = f"Package collection errors: {errors}; packages not analyzed: {unanalyzed}"
    checks.append(_check("collection_coverage", "attention" if incomplete else "complete", detail, "warning" if incomplete else "info"))
    return {"schema_version": "1.0", "checks": checks, "attention_count": sum(item["status"] == "attention" for item in checks), "coverage": report.get("metadata_coverage", {})}
