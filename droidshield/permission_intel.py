from __future__ import annotations

"""Permission intelligence for evidence-driven Android triage."""

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
}

SENSITIVE_SPECIAL = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
    "android.permission.REQUEST_INSTALL_PACKAGES": "package-install",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "notification-listener",
    "android.permission.BIND_DEVICE_ADMIN": "device-admin",
    "android.permission.BIND_VPN_SERVICE": "vpn",
}

COMBINATIONS = (
    ({"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"}, "accessibility+overlay"),
    ({"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.REQUEST_INSTALL_PACKAGES"}, "accessibility+package-install"),
    ({"android.permission.READ_SMS", "android.permission.SEND_SMS"}, "sms-read+sms-send"),
    ({"android.permission.RECORD_AUDIO", "android.permission.CAMERA"}, "microphone+camera"),
    ({"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES"}, "overlay+package-install"),
)


def analyze_permissions(requested: list[str] | None, granted: list[str] | None) -> dict:
    requested_set = {p for p in (requested or []) if p.startswith("android.permission.")}
    granted_set = {p for p in (granted or []) if p.startswith("android.permission.")}
    granted_set &= requested_set

    dangerous_requested = sorted(requested_set & DANGEROUS_PERMISSIONS)
    dangerous_granted = sorted(granted_set & DANGEROUS_PERMISSIONS)
    special_requested = sorted(requested_set & SENSITIVE_SPECIAL)
    special_granted = sorted(granted_set & SENSITIVE_SPECIAL)

    combination_names = []
    for required, name in COMBINATIONS:
        if required <= requested_set:
            combination_names.append(name)

    return {
        "requested": sorted(requested_set),
        "granted": sorted(granted_set),
        "not_granted": sorted(requested_set - granted_set),
        "dangerous_requested": dangerous_requested,
        "dangerous_granted": dangerous_granted,
        "special_requested": special_requested,
        "special_granted": special_granted,
        "suspicious_combinations": sorted(combination_names),
        "requested_count": len(requested_set),
        "granted_count": len(granted_set),
        "dangerous_granted_count": len(dangerous_granted),
        "coverage": "complete" if requested_set else "none",
    }
