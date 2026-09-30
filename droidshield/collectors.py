from __future__ import annotations

import re

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


def _lines(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if line.strip()]


def _safe_shell(client: AdbClient, command: str, serial: str) -> tuple[str, str | None]:
    try:
        return client.shell(command, serial=serial), None
    except Exception as exc:
        return "", str(exc)


def collect_security_state(client: AdbClient, serial: str) -> dict:
    settings = {}
    errors = {}

    for namespace in ("secure", "global"):
        out, error = _safe_shell(client, f"settings list {namespace}", serial)
        if error:
            settings[namespace] = {}
            errors[f"settings_{namespace}"] = error
        else:
            settings[namespace] = dict(
                line.split("=", 1) for line in _lines(out) if "=" in line
            )

    accessibility_out, error = _safe_shell(
        client,
        "settings get secure enabled_accessibility_services",
        serial,
    )
    if error:
        errors["accessibility_services"] = error
    accessibility = _lines(accessibility_out)

    admins_out, error = _safe_shell(
        client,
        "dumpsys device_policy | grep -E 'admin=|ComponentInfo' || true",
        serial,
    )
    if error:
        errors["device_policy"] = error
    admins = _lines(admins_out)

    overlays_out, error = _safe_shell(
        client,
        "cmd appops query-op SYSTEM_ALERT_WINDOW allow",
        serial,
    )
    if error:
        errors["overlay_appops"] = error
    overlays = _lines(overlays_out)

    notification_out, error = _safe_shell(
        client,
        "settings get secure enabled_notification_listeners",
        serial,
    )
    if error:
        errors["notification_listeners"] = error
    notification = _lines(notification_out)

    launcher, error = _safe_shell(
        client,
        "cmd package resolve-activity --brief -a android.intent.action.MAIN "
        "-c android.intent.category.HOME || true",
        serial,
    )
    if error:
        errors["default_launcher"] = error

    return {
        "settings": settings,
        "accessibility_services": accessibility,
        "device_policy": admins,
        "overlay_appops": overlays,
        "notification_listeners": notification,
        "default_launcher": launcher.strip(),
        "collection_errors": errors,
    }


def _first_match(pattern: str, text: str, flags: int = 0) -> str | None:
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else None


def _all_paths_system(paths: list[str]) -> bool:
    return bool(paths) and all(
        any(path.startswith(prefix) for prefix in SYSTEM_PATH_PREFIXES)
        for path in paths
    )


def collect_package_metadata(
    client: AdbClient,
    serial: str,
    package: str,
    hash_apk: bool = False,
) -> dict:
    if not PACKAGE_RE.fullmatch(package):
        raise ValueError(f"Invalid Android package name: {package!r}")

    dump = client.package_dump(serial, package)
    paths = client.package_paths(serial, package)

    permissions = sorted(
        set(re.findall(r"android\.permission\.[A-Z0-9_]+", dump))
    )

    version_name = _first_match(r"versionName=([^\s}]+)", dump)
    version_code = _first_match(r"versionCode=(\d+)", dump)
    first_install = _first_match(r"firstInstallTime=([^\n}]+)", dump)
    last_update = _first_match(r"lastUpdateTime=([^\n}]+)", dump)
    installer = _first_match(r"installerPackageName=([^\s}]+)", dump)
    uid = _first_match(r"userId=(\d+)", dump)
    enabled_raw = _first_match(r"enabled=(true|false)", dump)

    pkg_flags_match = re.search(
        r"pkgFlags=\[([^\]]+)\]",
        dump,
        flags=re.IGNORECASE,
    )
    pkg_flags = (
        pkg_flags_match.group(1).strip().split()
        if pkg_flags_match else []
    )

    try:
        hashes = client.package_sha256(serial, package) if hash_apk else {}
    except Exception:
        hashes = {}

    system_path_evidence = _all_paths_system(paths)
    system_flag_evidence = any(flag.upper() == "SYSTEM" for flag in pkg_flags)

    return {
        "package": package,
        "permissions": permissions,
        "apk_paths": paths,
        "apk_sha256": hashes,
        "version_name": version_name,
        "version_code": int(version_code) if version_code else None,
        "first_install_time": first_install,
        "last_update_time": last_update,
        "installer_package": installer,
        "uid": int(uid) if uid else None,
        "enabled": enabled_raw != "false",
        "pkg_flags": pkg_flags,
        "system_path_evidence": system_path_evidence,
        "system_flag_evidence": system_flag_evidence,
        "raw_size": len(dump),
    }


def collect_runtime(client: AdbClient, serial: str) -> dict:
    processes, process_error = _safe_shell(client, "ps -A", serial)
    services, services_error = _safe_shell(
        client,
        "dumpsys activity services",
        serial,
    )
    errors = {}
    if process_error:
        errors["processes"] = process_error
    if services_error:
        errors["services"] = services_error
    return {
        "processes": _lines(processes)[:500],
        "services": _lines(services)[:500],
        "collection_errors": errors,
    }
