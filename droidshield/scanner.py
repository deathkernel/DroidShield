from __future__ import annotations

from datetime import datetime, timezone
import re

from .adb import AdbClient
from .classifier import classify_package
from .collectors import collect_package_metadata, collect_runtime, collect_security_state
from .detection import correlate
from .hardening import recommendations
from .telephony import audit_call_forwarding
from .rules import package_findings


def _component_packages(values: list[str] | str | None) -> list[str]:
    if isinstance(values, str):
        values = [values]
    result = set()
    for value in values or []:
        for token in re.split(r"[:\\s,]+", value):
            token = token.strip()
            if "/" in token:
                package = token.split("/", 1)[0]
            else:
                package = token
            if re.fullmatch(r"[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+", package):
                result.add(package)
    return sorted(result)


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

    target_packages = (
        sorted(set(third_party))
        + [p for p in packages if p not in set(third_party)][:100]
    )
    target_packages = target_packages[:500]

    findings = package_findings(packages)
    security = collect_security_state(client, resolved)
    package_metadata = [
        collect_package_metadata(
            client,
            resolved,
            package,
            hash_apk=hash_apks and package in set(third_party),
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

    for assessment in package_assessments:
        if assessment["level"] == "HIGH" and not assessment["protected_system"]:
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
                    "apk_paths": next(
                        (
                            item.get("apk_paths", [])
                            for item in package_metadata
                            if item["package"] == assessment["package"]
                        ),
                        [],
                    ),
                },
            })

    runtime = collect_runtime(client, resolved)
    telephony = audit_call_forwarding(client, resolved)

    report = {
        "schema_version": "0.4",
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
            "hash_apks": hash_apks,
        },
        "package_metadata": package_metadata,
        "package_assessments": package_assessments,
        "security": security,
        "runtime": runtime,
        "telephony": telephony,
        "findings": findings,
    }
    report["risk"] = correlate(report)
    report["hardening"] = recommendations(report)
    return report
