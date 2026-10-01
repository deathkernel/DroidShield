from __future__ import annotations

SYSTEM_PREFIXES = (
    "com.android.",
    "com.google.android.",
    "com.qualcomm.",
    "com.samsung.android.",
    "com.miui.",
    "com.xiaomi.",
    "com.oneplus.",
)


def classify_package(package: str, metadata: dict | None = None) -> dict:
    """Classify sensitive capabilities using contextual evidence.

    Capability possession is a triage signal, not proof of malicious behavior.
    A package reaches HIGH only when sensitive capabilities are corroborated by
    an active privileged role (accessibility, overlay, notification listener,
    device policy, or default launcher).
    """
    metadata = metadata or {}
    lower = package.lower()

    path_evidence = bool(metadata.get("system_path_evidence"))
    flag_evidence = bool(metadata.get("system_flag_evidence"))
    prefix_evidence = lower.startswith(SYSTEM_PREFIXES)
    protected = path_evidence or flag_evidence or prefix_evidence

    permissions = set(metadata.get("permissions", []))
    active_roles = set(metadata.get("active_roles", []))
    signals: list[str] = []
    capability_score = 0

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        signals.append("accessibility-capable")
        capability_score += 25
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        signals.append("overlay-capable")
        capability_score += 20
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        signals.append("package-install-capable")
        capability_score += 15
    if {"android.permission.READ_SMS", "android.permission.SEND_SMS"} & permissions:
        signals.append("sms-capable")
        capability_score += 10
    if "android.permission.RECORD_AUDIO" in permissions:
        signals.append("microphone-capable")
        capability_score += 8
    if "android.permission.CAMERA" in permissions:
        signals.append("camera-capable")
        capability_score += 5

    corroboration_score = 0
    role_pairs = (
        ("accessibility", "accessibility-capable", 25),
        ("overlay", "overlay-capable", 20),
        ("notification", "notification-listener-capable", 15),
        ("device_policy", "device-admin-capable", 20),
        ("launcher", "launcher-role-capable", 10),
    )
    for role, capability, weight in role_pairs:
        if role in active_roles:
            signals.append(f"active-{role}")
            if capability in signals:
                corroboration_score += weight

    if "notification" in active_roles:
        signals.append("notification-listener-active")
    if "device_policy" in active_roles:
        signals.append("device-admin-active")
    if "launcher" in active_roles:
        signals.append("default-launcher-active")

    total_score = min(capability_score + corroboration_score, 100)

    if protected:
        # Protected/system packages are still reported, but capability-only
        # evidence must not turn a known system component into a remediation
        # candidate. Active corroboration remains visible for investigation.
        level = "HIGH" if corroboration_score >= 30 else (
            "MEDIUM" if capability_score >= 25 else "LOW"
        )
    elif corroboration_score >= 25 and capability_score >= 50:
        level = "HIGH"
    elif capability_score >= 25 or corroboration_score > 0:
        level = "MEDIUM"
    else:
        level = "LOW"

    evidence_quality = (
        "strong"
        if corroboration_score >= 25
        else "moderate"
        if capability_score >= 25
        else "weak"
    )

    return {
        "package": package,
        "protected_system": protected,
        "system_evidence": {
            "path": path_evidence,
            "flags": flag_evidence,
            "prefix_only": prefix_evidence and not (path_evidence or flag_evidence),
        },
        "score": total_score,
        "capability_score": capability_score,
        "corroboration_score": corroboration_score,
        "evidence_quality": evidence_quality,
        "active_roles": sorted(active_roles),
        "level": level,
        "signals": sorted(set(signals)),
        "remediation_allowed": not protected,
    }
