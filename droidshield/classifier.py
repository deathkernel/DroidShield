from __future__ import annotations

SYSTEM_PREFIXES = ("com.android.", "com.google.android.", "com.qualcomm.", "com.samsung.android.", "com.miui.", "com.xiaomi.", "com.oneplus.")


def classify_package(package: str, metadata: dict | None = None) -> dict:
    """Classify sensitive capabilities using contextual evidence, not capability alone."""
    metadata = metadata or {}
    lower = package.lower()
    path_evidence = bool(metadata.get("system_path_evidence"))
    flag_evidence = bool(metadata.get("system_flag_evidence"))
    prefix_evidence = lower.startswith(SYSTEM_PREFIXES)
    protected = path_evidence or flag_evidence or prefix_evidence
    permissions = set(metadata.get("permissions", []))
    granted = set(metadata.get("granted_permissions", []))
    active_roles = set(metadata.get("active_roles", []))
    permission_intel = metadata.get("permission_intelligence", {})
    signals: list[str] = []
    capability_score = 0
    granted_score = 0

    capabilities = (
        ("android.permission.BIND_ACCESSIBILITY_SERVICE", "accessibility-capable", 25),
        ("android.permission.SYSTEM_ALERT_WINDOW", "overlay-capable", 20),
        ("android.permission.REQUEST_INSTALL_PACKAGES", "package-install-capable", 15),
        ("android.permission.READ_SMS", "sms-capable", 10),
        ("android.permission.SEND_SMS", "sms-capable", 10),
        ("android.permission.RECORD_AUDIO", "microphone-capable", 8),
        ("android.permission.CAMERA", "camera-capable", 5),
        ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "notification-listener-capable", 12),
        ("android.permission.BIND_DEVICE_ADMIN", "device-admin-capable", 20),
        ("android.permission.BIND_VPN_SERVICE", "vpn-capable", 12),
    )
    for permission, signal, weight in capabilities:
        if permission in permissions:
            signals.append(signal)
            capability_score += weight
            if permission in granted:
                granted_score += weight
                signals.append(signal.replace("-capable", "-granted"))

    corroboration_score = 0
    role_pairs = (("accessibility", "accessibility-capable", 25), ("overlay", "overlay-capable", 20), ("notification", "notification-listener-capable", 15), ("device_policy", "device-admin-capable", 20), ("launcher", "launcher-role-capable", 10))
    for role, capability, weight in role_pairs:
        if role in active_roles:
            signals.append(f"active-{role}")
            if capability in signals:
                corroboration_score += weight
                if permission_intel.get("special_granted"):
                    corroboration_score += 5
    if "notification" in active_roles: signals.append("notification-listener-active")
    if "device_policy" in active_roles: signals.append("device-admin-active")
    if "launcher" in active_roles: signals.append("default-launcher-active")

    dangerous_granted = len(permission_intel.get("dangerous_granted", []))
    combination_count = len(permission_intel.get("suspicious_combinations", []))
    if dangerous_granted >= 3:
        signals.append("multiple-dangerous-permissions-granted")
    if combination_count:
        signals.append("sensitive-permission-combination")

    total_score = min(capability_score + corroboration_score + min(granted_score // 5, 15), 100)
    if protected:
        level = "HIGH" if corroboration_score >= 30 and granted_score >= 25 else ("MEDIUM" if capability_score >= 25 else "LOW")
    elif corroboration_score >= 25 and (capability_score >= 50 or granted_score >= 35):
        level = "HIGH"
    elif capability_score >= 25 or corroboration_score > 0 or dangerous_granted >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"
    evidence_quality = "strong" if corroboration_score >= 25 and granted_score > 0 else "moderate" if (capability_score >= 25 or granted_score > 0) else "weak"
    return {
        "package": package,
        "protected_system": protected,
        "system_evidence": {"path": path_evidence, "flags": flag_evidence, "prefix_only": prefix_evidence and not (path_evidence or flag_evidence)},
        "score": total_score,
        "capability_score": capability_score,
        "granted_capability_score": granted_score,
        "corroboration_score": corroboration_score,
        "dangerous_granted_count": dangerous_granted,
        "permission_combination_count": combination_count,
        "evidence_quality": evidence_quality,
        "active_roles": sorted(active_roles),
        "level": level,
        "signals": sorted(set(signals)),
        "remediation_allowed": not protected,
    }
