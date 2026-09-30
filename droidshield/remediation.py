"""Guarded remediation primitives for authorized Android devices."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex

from .adb import AdbClient


PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
SYSTEM_PATH_PREFIXES = (
    "/system/",
    "/system_ext/",
    "/product/",
    "/vendor/",
    "/odm/",
    "/apex/",
)
SYSTEM_PREFIXES = (
    "com.android.",
    "com.google.android.",
    "com.qualcomm.",
    "com.samsung.android.",
    "com.miui.",
    "com.xiaomi.",
    "com.oneplus.",
)


class RemediationRefused(RuntimeError):
    pass


@dataclass
class RemediationResult:
    package: str
    action: str
    success: bool
    output: str


def _validate_package(package: str) -> None:
    if not PACKAGE_RE.fullmatch(package):
        raise RemediationRefused(f"Invalid Android package name: {package!r}")


def _package_is_protected(client: AdbClient, serial: str, package: str) -> tuple[bool, str]:
    _validate_package(package)
    paths = client.package_paths(serial, package)
    system_paths = [
        path for path in paths
        if any(path.startswith(prefix) for prefix in SYSTEM_PATH_PREFIXES)
    ]
    dump = client.package_dump(serial, package)
    flag_match = re.search(
        r"pkgFlags=\[([^\]]+)\]",
        dump,
        flags=re.IGNORECASE,
    )
    flag_text = flag_match.group(1) if flag_match else ""
    if system_paths:
        return True, f"system APK path: {system_paths[0]}"
    if "SYSTEM" in flag_text.upper():
        return True, "PackageManager pkgFlags contains SYSTEM"
    if package.lower().startswith(SYSTEM_PREFIXES):
        return True, "protected package prefix fallback"
    return False, "no protected-system evidence"


def _assert_safe_package(client: AdbClient, serial: str, package: str) -> None:
    protected, reason = _package_is_protected(client, serial, package)
    if protected:
        raise RemediationRefused(
            f"Refusing destructive action against protected system package {package}: {reason}"
        )


def snapshot_package(client: AdbClient, serial: str, package: str, directory: Path) -> Path:
    _assert_safe_package(client, serial, package)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"{package.replace('.', '_')}-{stamp}.json"
    metadata = client.package_dump(serial, package)
    apk_paths = client.package_paths(serial, package)
    path.write_text(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "serial": serial,
        "package": package,
        "apk_paths": apk_paths,
        "dumpsys_package": metadata,
    }, indent=2), encoding="utf-8")
    return path


def disable_package(
    client: AdbClient,
    serial: str,
    package: str,
    confirmed: bool = False,
) -> RemediationResult:
    _assert_safe_package(client, serial, package)
    if not confirmed:
        raise RemediationRefused(
            "Explicit confirmation is required before disabling a package."
        )
    output = client.shell(
        f"pm disable-user --user 0 {shlex.quote(package)}",
        serial=serial,
    )
    return RemediationResult(
        package,
        "disable-user",
        "new state: disabled" in output.lower() or "disabled" in output.lower(),
        output.strip(),
    )


def uninstall_package(
    client: AdbClient,
    serial: str,
    package: str,
    confirmed: bool = False,
) -> RemediationResult:
    _assert_safe_package(client, serial, package)
    if not confirmed:
        raise RemediationRefused(
            "Explicit confirmation is required before uninstalling a package."
        )
    output = client.shell(
        f"pm uninstall --user 0 {shlex.quote(package)}",
        serial=serial,
    )
    return RemediationResult(
        package,
        "uninstall-user",
        "success" in output.lower(),
        output.strip(),
    )


def verify_absent(client: AdbClient, serial: str, package: str) -> bool:
    _validate_package(package)
    return not client.package_paths(serial, package)


def verify_disabled(client: AdbClient, serial: str, package: str) -> bool:
    _validate_package(package)
    output = client.shell("pm list packages -d", serial=serial)
    disabled = {
        line[len("package:"):].strip()
        for line in output.splitlines()
        if line.startswith("package:")
    }
    return package in disabled


def explain_remediation_policy() -> str:
    return (
        "Evidence is preserved before remediation; destructive actions require explicit "
        "confirmation; Android package evidence is checked for system protection; and "
        "post-action verification is mandatory."
    )
