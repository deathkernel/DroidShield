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
    protected = lower.startswith(SYSTEM_PREFIXES)
    permissions = set(metadata.get("permissions", []))

    signals = []
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

    if protected:
        score = min(score, 25)

    level = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return {
        "package": package,
        "protected_system_prefix": protected,
        "score": score,
        "level": level,
        "signals": signals,
        "remediation_allowed": not protected,
    }
