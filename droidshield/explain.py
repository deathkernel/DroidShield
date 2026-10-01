from __future__ import annotations

SIGNAL_EXPLANATIONS = {
    "enabled-accessibility-service": "An accessibility service is enabled; this can be legitimate but is security-sensitive.",
    "device-admin-indicator": "A device-admin policy is active and should be attributable to an expected app.",
    "overlay-app-indicator": "One or more apps currently hold overlay capability.",
    "notification-listener": "A notification listener is enabled and can observe notification content.",
}


def explain_assessment(assessment: dict) -> dict:
    reasons = []
    for signal in assessment.get("signals", []):
        if signal in SIGNAL_EXPLANATIONS:
            reasons.append(SIGNAL_EXPLANATIONS[signal])
        elif signal.endswith("-granted"):
            reasons.append(f"The app has a granted sensitive capability: {signal.replace('-granted', '')}.")
        elif signal.endswith("-capable"):
            reasons.append(f"The manifest declares a sensitive capability: {signal.replace('-capable', '')}.")
        elif signal.startswith("active-"):
            reasons.append(f"Device state corroborates an active role: {signal[7:].replace('-', ' ')}.")
        elif signal.startswith("correlated-active-"):
            reasons.append(f"A sensitive capability is both declared and observed active: {signal.split(':', 1)[0][19:]}.")
        elif signal == "sensitive-permission-combination":
            reasons.append("Multiple sensitive permissions form a combination that deserves review.")
        elif signal == "multiple-dangerous-permissions-granted":
            reasons.append("Several dangerous permissions are currently granted.")
        else:
            reasons.append(signal)
    return {"package": assessment.get("package"), "level": assessment.get("level"), "score": assessment.get("score", 0), "evidence_quality": assessment.get("evidence_quality"), "why": reasons, "next_steps": ["Verify installer/provenance and signing identity.", "Review granted permissions against the app's expected purpose.", "Inspect active roles and component evidence.", "Preserve evidence before remediation."]}


def explain_report(report: dict) -> dict:
    explanations = [explain_assessment(item) for item in report.get("package_assessments", [])]
    return {"risk": report.get("risk", {}), "findings": report.get("findings", []), "package_explanations": [item for item in explanations if item.get("level") != "LOW"], "disclaimer": "Heuristic risk indicates evidence requiring review; it is not a malware verdict."}
