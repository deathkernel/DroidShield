from __future__ import annotations

from datetime import datetime, timezone

from .adb import AdbClient
from .collectors import collect_package_metadata, collect_runtime, collect_security_state
from .risk import score_findings
from .rules import package_findings
from .telephony import audit_call_forwarding


def scan_device(client: AdbClient, serial: str | None = None) -> dict:
    resolved = client.resolve_serial(serial)
    props = client.properties(resolved)
    packages = client.packages(resolved)

    findings = package_findings(packages)
    security = collect_security_state(client, resolved)
    package_metadata = [
        collect_package_metadata(client, resolved, package)
        for package in packages[:300]
    ]
    runtime = collect_runtime(client, resolved)
    telephony = audit_call_forwarding(client, resolved)

    report = {
        "schema_version": "0.2",
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
        "package_metadata": package_metadata,
        "security": security,
        "runtime": runtime,
        "telephony": telephony,
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "package": f.package,
                "evidence": f.evidence or {},
            }
            for f in findings
        ],
    }
    report["risk"] = score_findings(report)
    return report
