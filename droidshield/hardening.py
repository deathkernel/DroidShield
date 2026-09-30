from __future__ import annotations


def recommendations(report: dict) -> list[str]:
    out = []
    security = report.get("security", {})

    if security.get("accessibility_services"):
        out.append("Review every enabled Accessibility Service and disable unknown/untrusted entries.")
    if security.get("overlay_appops"):
        out.append("Review apps allowed to draw over other apps.")
    if security.get("notification_listeners"):
        out.append("Review apps with notification-listener access.")
    if security.get("device_policy"):
        out.append("Review active device administrators before uninstalling suspicious applications.")

    patch = report.get("device", {}).get("security_patch")
    if not patch:
        out.append("Security patch level could not be collected.")

    out.append("Install Android updates and vendor security patches when available.")
    out.append("Keep installation of apps from unknown sources disabled unless temporarily required.")
    return list(dict.fromkeys(out))
