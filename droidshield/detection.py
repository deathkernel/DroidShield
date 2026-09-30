from __future__ import annotations


def correlate(report: dict) -> dict:
    signals = []
    score = 0

    security = report.get("security", {})
    if security.get("accessibility_services"):
        signals.append("enabled-accessibility-service")
        score += 20
    if security.get("device_policy"):
        signals.append("device-admin-indicator")
        score += 15
    if security.get("overlay_appops"):
        signals.append("overlay-app-indicator")
        score += 15
    if security.get("notification_listeners"):
        signals.append("notification-listener")
        score += 10

    for item in report.get("package_metadata", []):
        perms = set(item.get("permissions", []))
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
            signals.append(f"accessibility-permission:{item['package']}")
            score += 20
        if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
            signals.append(f"overlay-permission:{item['package']}")
            score += 15
        if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
            signals.append(f"package-install-permission:{item['package']}")
            score += 10

    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return {"score": score, "level": level, "signals": sorted(set(signals))}
