from __future__ import annotations

from datetime import datetime, timezone
import re

from .adb import AdbClient
from .classifier import classify_package
from .collectors import collect_package_metadata, collect_runtime, collect_security_state
from .component_graph import build_component_graph
from .detection import correlate
from .diff import compare_reports
from .hardening import recommendations
from .network import collect_network_state
from .telephony import audit_call_forwarding
from .timeline import build_install_timeline
from .rules import package_findings


PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")


def _component_packages(values: list[str] | str | None) -> list[str]:
    if isinstance(values, str):
        values = [values]
    result = set()
    for value in values or []:
        for token in re.split(r"[:\s,]+", value):
            token = token.strip()
            if "/" in token:
                package = token.split("/", 1)[0]
            else:
                package = token
            if PACKAGE_RE.fullmatch(package):
                result.add(package)
    return sorted(result)


def _collect_one(
    client: AdbClient,
    serial: str,
    package: str,
    hash_apk: bool,
) -> dict:
    try:
        return collect_package_metadata(
            client,
            serial,
            package,
            hash_apk=hash_apk,
        )
    except Exception as exc:
        return {
            "package": package,
            "permissions": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "apk_paths": [],
            "apk_sha256": {},
            "collection_error": str(exc),
            "raw_size": 0,
        }


def scan_device(
    client: AdbClient,
    serial: str | None = None,
    hash_apks: bool = False,
) -> dict:
    resolved = client.resolve_serial(serial)
    props = client.properties(resolved)
    packages = client.packages(resolved)

    try:
        third_party = client.third_party_packages(resolved)
    except Exception:
        third_party = []

    third_party_set = set(third_party)
    target_packages = (
        sorted(third_party_set)
        + [p for p in packages if p not in third_party_set][:100]
    )[:500]

    findings = package_findings(packages)
    security = collect_security_state(client, resolved)
    package_metadata = [
        _collect_one(
            client,
            resolved,
            package,
            hash_apk=hash_apks and package in third_party_set,
        )
        for package in target_packages
    ]
    package_assessments = [
        classify_package(item["package"], item)
        for item in package_metadata
    ]

    security["active_component_packages"] = {
        "accessibility": _component_packages(security.get("accessibility_services")),
        "device_policy": _component_packages(security.get("device_policy")),
        "overlay": _component_packages(security.get("overlay_appops")),
        "notification": _component_packages(security.get("notification_listeners")),
        "launcher": _component_packages(security.get("default_launcher")),
    }

    for item in package_metadata:
        if item.get("collection_error"):
            findings.append({
                "severity": "LOW",
                "title": "Package metadata could not be collected",
                "description": (
                    "The package was discovered, but some forensic metadata could not "
                    "be collected. Investigate the error before treating the package as clean."
                ),
                "package": item["package"],
                "evidence": {"error": item["collection_error"]},
            })

    for assessment in package_assessments:
        if assessment["level"] == "HIGH" and not assessment["protected_system"]:
            metadata = next(
                item for item in package_metadata
                if item["package"] == assessment["package"]
            )
            findings.append({
                "severity": "MEDIUM",
                "title": "High-risk app capability combination",
                "description": (
                    "This third-party package requests multiple sensitive capabilities. "
                    "Review its provenance and whether each capability is expected."
                ),
                "package": assessment["package"],
                "evidence": {
                    "score": assessment["score"],
                    "signals": assessment["signals"],
                    "apk_paths": metadata.get("apk_paths", []),
                    "apk_sha256": metadata.get("apk_sha256", {}),
                },
            })

    runtime = collect_runtime(client, resolved)
    network = collect_network_state(client, resolved, runtime.get("processes", []))
    timeline = build_install_timeline(package_metadata)
    component_graph = build_component_graph(package_metadata, security)
    telephony = audit_call_forwarding(client, resolved)

    report = {
        "schema_version": "0.6",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device": {
            "serial": resolved,
            "manufacturer": props.get("ro.product.manufacturer"),
            "model": props.get("ro.product.model"),
            "android": props.get("ro.build.version.release"),
            "sdk": props.get("ro.build.version.sdk"),
            "security_patch": props.get("ro.build.version.security_patch"),
        },
        "packages": packages,
        "third_party_packages": third_party,
        "metadata_coverage": {
            "packages_total": len(packages),
            "third_party_total": len(third_party),
            "packages_analyzed": len(package_metadata),
            "packages_with_collection_errors": sum(
                1 for item in package_metadata if item.get("collection_error")
            ),
            "hash_apks": hash_apks,
        },
        "package_metadata": package_metadata,
        "package_assessments": package_assessments,
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
    return report
