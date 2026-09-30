from __future__ import annotations


def recommendations(report: dict) -> list[str]:
    out = []
    security = report.get("security", {})
    secure = security.get("settings", {}).get("secure", {})
    global_settings = security.get("settings", {}).get("global", {})

    if security.get("accessibility_services"):
        out.append("Review every enabled Accessibility Service and disable unknown/untrusted entries.")
    if security.get("overlay_appops"):
        out.append("Review apps allowed to draw over other apps.")
    if security.get("notification_listeners"):
        out.append("Review apps with notification-listener access.")
    if security.get("device_policy"):
        out.append("Review active device administrators before uninstalling suspicious applications.")
    if security.get("default_launcher"):
        out.append("Confirm the default launcher is expected after any UI or home-screen incident.")

    adb_enabled = secure.get("adb_enabled")
    if adb_enabled == "1":
        out.append("USB debugging (ADB) is enabled; disable it when device servicing is complete.")

    unknown_sources = (
        secure.get("install_non_market_apps")
        or global_settings.get("install_non_market_apps")
        or global_settings.get("package_verifier_enable")
    )
    if unknown_sources in {"1", "true"}:
        out.append("Review unknown-source installation/package-verifier settings and return them to a hardened state.")

    patch = report.get("device", {}).get("security_patch")
    if not patch:
        out.append("Security patch level could not be collected.")

    network = report.get("network", {})
    if network.get("collection_errors"):
        out.append("Network state collection was incomplete; review vendor permissions/diagnostics before treating the result as exhaustive.")

    out.append("Install Android updates and vendor security patches when available.")
    out.append("Keep installation of apps from unknown sources disabled unless temporarily required.")
    return list(dict.fromkeys(out))
