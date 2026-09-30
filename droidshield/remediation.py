"""Guarded remediation primitives for authorized Android devices."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json

from .adb import AdbClient


class RemediationRefused(RuntimeError):
    pass


PROTECTED_PREFIXES = (
    "com.android.", "com.google.android.", "com.qualcomm.",
    "com.samsung.android.", "com.miui.", "com.xiaomi.", "com.oneplus.",
)


@dataclass
class RemediationResult:
    package: str
    action: str
    success: bool
    output: str


def _assert_safe_package(package: str) -> None:
    if package.lower().startswith(PROTECTED_PREFIXES):
        raise RemediationRefused(
            f"Refusing destructive action against protected system package: {package}"
        )


def snapshot_package(client: AdbClient, serial: str, package: str, directory: Path) -> Path:
    _assert_safe_package(package)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"{package.replace('.', '_')}-{stamp}.json"
    metadata = client.shell(f"dumpsys package {package}", serial=serial)
    path.write_text(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "serial": serial,
        "package": package,
        "dumpsys_package": metadata,
    }, indent=2), encoding="utf-8")
    return path


def disable_package(client: AdbClient, serial: str, package: str, confirmed: bool = False) -> RemediationResult:
    _assert_safe_package(package)
    if not confirmed:
        raise RemediationRefused("Explicit confirmation is required before disabling a package.")
    output = client.shell(f"pm disable-user --user 0 {package}", serial=serial)
    return RemediationResult(package, "disable-user", "disabled" in output.lower(), output.strip())


def uninstall_package(client: AdbClient, serial: str, package: str, confirmed: bool = False) -> RemediationResult:
    _assert_safe_package(package)
    if not confirmed:
        raise RemediationRefused("Explicit confirmation is required before uninstalling a package.")
    output = client.shell(f"pm uninstall --user 0 {package}", serial=serial)
    return RemediationResult(package, "uninstall-user", "success" in output.lower(), output.strip())


def verify_absent(client: AdbClient, serial: str, package: str) -> bool:
    return not client.shell(f"pm path {package}", serial=serial).strip()


def explain_remediation_policy() -> str:
    return (
        "Evidence must be preserved before remediation; destructive actions require "
        "explicit confirmation; protected system package prefixes are refused; "
        "post-action verification is required."
    )
