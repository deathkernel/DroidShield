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
    metadata = metadata or {}
    lower = package.lower()

    path_evidence = bool(metadata.get("system_path_evidence"))
    flag_evidence = bool(metadata.get("system_flag_evidence"))
    prefix_evidence = lower.startswith(SYSTEM_PREFIXES)
    protected = path_evidence or flag_evidence

    permissions = set(metadata.get("permissions", []))
    signals: list[str] = []
    score = 0

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        signals.append("accessibility-capable")
        score += 25
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        signals.append("overlay-capable")
        score += 20
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        signals.append("package-install-capable")
        score += 15
    if {"android.permission.READ_SMS", "android.permission.SEND_SMS"} & permissions:
        signals.append("sms-capable")
        score += 10
    if "android.permission.RECORD_AUDIO" in permissions:
        signals.append("microphone-capable")
        score += 8
    if "android.permission.CAMERA" in permissions:
        signals.append("camera-capable")
        score += 5

    return {
        "package": package,
        "protected_system": protected,
        "system_evidence": {
            "path": path_evidence,
            "flags": flag_evidence,
            "prefix_only": prefix_evidence and not protected,
        },
        "score": score,
        "level": "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW",
        "signals": signals,
        "remediation_allowed": not protected,
    }
