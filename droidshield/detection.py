from __future__ import annotations


def correlate(report: dict) -> dict:
    signals = []
    score = 0
    assessments = {
        item.get("package"): item
        for item in report.get("package_assessments", [])
        if item.get("package")
    }
    third_party = set(report.get("third_party_packages", []))

    security = report.get("security", {})
    component_map = security.get("active_component_packages", {})

    if security.get("accessibility_services"):
        signals.append("enabled-accessibility-service")
        score += 15
    if security.get("device_policy"):
        signals.append("device-admin-indicator")
        score += 12
    if security.get("overlay_appops"):
        signals.append("overlay-app-indicator")
        score += 12
    if security.get("notification_listeners"):
        signals.append("notification-listener")
        score += 8

    high_capability_packages = set()
    for package, assessment in assessments.items():
        if assessment.get("level") == "HIGH":
            high_capability_packages.add(package)
            if package in third_party:
                signals.append(f"high-risk-capabilities:{package}")
                score += 15
        elif assessment.get("level") == "MEDIUM" and package in third_party:
            signals.append(f"sensitive-capabilities:{package}")
            score += 4

    for capability, packages in component_map.items():
        for package in packages:
            assessment = assessments.get(package)
            if package in high_capability_packages and package in third_party:
                signals.append(f"correlated-active-{capability}:{package}")
                score += 12
            elif assessment and assessment.get("level") == "MEDIUM":
                signals.append(f"active-sensitive-{capability}:{package}")
                score += 4

    launcher_packages = set(component_map.get("launcher", []))
    for package in launcher_packages:
        if package in third_party:
            signals.append(f"third-party-default-launcher:{package}")
            score += 8

    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    confidence = (
        "higher" if any(s.startswith("correlated-active-") for s in signals)
        else "moderate" if signals
        else "low"
    )
    return {
        "score": score,
        "level": level,
        "confidence": confidence,
        "heuristic": True,
        "signals": sorted(set(signals)),
    }
