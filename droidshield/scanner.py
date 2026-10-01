from __future__ import annotations

from datetime import datetime, timezone
import re

from .adb import AdbClient
from .classifier import classify_package
from .collectors import collect_package_metadata, collect_runtime, collect_security_state
from .component_graph import build_component_graph
from .detection import correlate
from .diff import compare_reports
from .explain import explain_report
from .posture import assess_posture
from .hardening import recommendations
from .network import collect_network_state
from .runtime_intel import summarize_runtime, correlate_network, correlate_security_events
from .permission_intel import analyze_permissions
from .telephony import audit_call_forwarding
from .timeline import build_incident_timeline, build_install_timeline
from .rules import package_findings

PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")


def _component_packages(values: list[str] | str | None) -> list[str]:
    if isinstance(values, str): values = [values]
    result = set()
    for value in values or []:
        for token in re.split(r"[:\s,]+", value):
            token = token.strip()
            package = token.split("/", 1)[0]
            if PACKAGE_RE.fullmatch(package): result.add(package)
    return sorted(result)


def _collect_one(client: AdbClient, serial: str, package: str, hash_apk: bool) -> dict:
    try:
        return collect_package_metadata(client, serial, package, hash_apk=hash_apk)
    except Exception as exc:
        return {"package": package, "permissions": [], "granted_permissions": [], "services": [], "receivers": [], "providers": [], "apk_paths": [], "apk_sha256": {}, "collection_error": str(exc), "raw_size": 0}


def scan_device(client: AdbClient, serial: str | None = None, hash_apks: bool = False) -> dict:
    resolved = client.resolve_serial(serial)
    props = client.properties(resolved)
    packages = client.packages(resolved)
    try: third_party = client.third_party_packages(resolved)
    except Exception: third_party = []
    third_party_set = set(third_party)
    analysis_limit = 500
    target_packages = (sorted(third_party_set) + [p for p in packages if p not in third_party_set][:max(0, analysis_limit - len(third_party_set))])[:analysis_limit]
    unanalyzed_packages = sorted(set(packages) - set(target_packages))
    findings = package_findings(packages)
    security = collect_security_state(client, resolved)
    package_metadata = [_collect_one(client, resolved, package, hash_apks and package in third_party_set) for package in target_packages]

    security["active_component_packages"] = {
        "accessibility": _component_packages(security.get("accessibility_services")),
        "device_policy": _component_packages(security.get("device_policy")),
        "overlay": _component_packages(security.get("overlay_appops")),
        "notification": _component_packages(security.get("notification_listeners")),
        "launcher": _component_packages(security.get("default_launcher")),
    }
    active_roles_by_package: dict[str, list[str]] = {}
    for role, packages_for_role in security["active_component_packages"].items():
        for package in packages_for_role: active_roles_by_package.setdefault(package, []).append(role)

    for item in package_metadata:
        item["active_roles"] = sorted(set(active_roles_by_package.get(item["package"], [])))
        item["permission_intelligence"] = analyze_permissions(item.get("permissions"), item.get("granted_permissions"))

    package_assessments = [classify_package(item["package"], item) for item in package_metadata]

    for item in package_metadata:
        if item.get("collection_error"):
            findings.append({"severity": "LOW", "title": "Package metadata could not be collected", "description": "The package was discovered, but some forensic metadata could not be collected. Investigate the error before treating the package as clean.", "package": item["package"], "evidence": {"error": item["collection_error"]}})
        if item.get("apk_hash_error"):
            findings.append({"severity": "LOW", "title": "APK hash collection incomplete", "description": "APK hashing was requested but one or more hashes could not be collected. Do not treat missing hashes as evidence of absence.", "package": item["package"], "evidence": {"error": item["apk_hash_error"]}})

    for assessment in package_assessments:
        if assessment["level"] == "HIGH" and not assessment["protected_system"]:
            metadata = next(item for item in package_metadata if item["package"] == assessment["package"])
            findings.append({"severity": "MEDIUM", "title": "High-risk app capability combination", "description": "This third-party package has sensitive capabilities corroborated by device state. Review provenance, granted permissions, and whether each capability is expected.", "package": assessment["package"], "evidence": {"score": assessment["score"], "capability_score": assessment["capability_score"], "granted_capability_score": assessment.get("granted_capability_score", 0), "corroboration_score": assessment.get("corroboration_score", 0), "dangerous_granted_count": assessment.get("dangerous_granted_count", 0), "permission_combination_count": assessment.get("permission_combination_count", 0), "evidence_quality": assessment.get("evidence_quality", "unknown"), "active_roles": assessment.get("active_roles", []), "signals": assessment["signals"], "apk_paths": metadata.get("apk_paths", []), "apk_sha256": metadata.get("apk_sha256", {})}})

    runtime = collect_runtime(client, resolved)
    runtime_summary = summarize_runtime(runtime, packages)
    runtime["intelligence"] = runtime_summary
    runtime["security_events"] = correlate_security_events(runtime.get("logcat_security", []), packages)
    network = collect_network_state(client, resolved, runtime.get("processes", []))
    network["intelligence"] = correlate_network(network, runtime_summary)
    timeline = build_install_timeline(package_metadata)
    component_graph = build_component_graph(package_metadata, security)
    telephony = audit_call_forwarding(client, resolved)
    permission_summary = {
        "packages_with_granted_dangerous_permissions": sum(1 for item in package_metadata if item.get("permission_intelligence", {}).get("dangerous_granted")),
        "packages_with_sensitive_combinations": sum(1 for item in package_metadata if item.get("permission_intelligence", {}).get("suspicious_combinations")),
        "granted_permissions_observed": sum(len(item.get("granted_permissions", [])) for item in package_metadata),
    }
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device": {"serial": resolved, "manufacturer": props.get("ro.product.manufacturer"), "model": props.get("ro.product.model"), "android": props.get("ro.build.version.release"), "sdk": props.get("ro.build.version.sdk"), "security_patch": props.get("ro.build.version.security_patch")},
        "packages": packages,
        "third_party_packages": third_party,
        "metadata_coverage": {"packages_total": len(packages), "third_party_total": len(third_party), "packages_analyzed": len(package_metadata), "packages_with_collection_errors": sum(1 for item in package_metadata if item.get("collection_error")), "packages_with_hash_errors": sum(1 for item in package_metadata if item.get("apk_hash_error")), "packages_unanalyzed": len(unanalyzed_packages), "unanalyzed_packages": unanalyzed_packages, "analysis_limit": analysis_limit, "analysis_complete": not unanalyzed_packages, "hash_apks": hash_apks, "permission_intelligence": "enabled"},
        "package_metadata": package_metadata,
        "package_assessments": package_assessments,
        "permission_summary": permission_summary,
        "security": security,
        "component_graph": component_graph,
        "install_timeline": timeline,
        "runtime": runtime,
        "network": network,
        "telephony": telephony,
        "findings": findings,
    }
    report["risk"] = correlate(report)
    report["hardening"] = recommendations(report)
    report["posture"] = assess_posture(report)
    report["explainability"] = explain_report(report)
    report["incident_timeline"] = build_incident_timeline(report)
    return report
