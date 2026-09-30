from __future__ import annotations


def score_findings(report: dict) -> dict:
    score = 0
    reasons: list[str] = []

    security = report.get("security", {})
    if security.get("accessibility_services"):
        score += 20
        reasons.append("Accessibility service(s) enabled")

    if security.get("device_policy"):
        score += 15
        reasons.append("Device-policy/admin indicators observed")

    if security.get("overlay_appops"):
        score += 15
        reasons.append("Overlay-capable app indicators observed")

    if security.get("notification_listeners"):
        score += 10
        reasons.append("Notification listener(s) enabled")

    package_findings = report.get("findings", [])
    score += sum(10 if f.get("severity") == "HIGH" else 5 for f in package_findings)

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": min(score, 100), "level": level, "reasons": reasons}
