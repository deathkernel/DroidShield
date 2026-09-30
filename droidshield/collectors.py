from __future__ import annotations

import re
from .adb import AdbClient


def _lines(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if line.strip()]


def collect_security_state(client: AdbClient, serial: str) -> dict:
    settings = {}
    for namespace in ("secure", "global"):
        try:
            out = client.shell(f"settings list {namespace}", serial=serial)
            settings[namespace] = dict(
                line.split("=", 1) for line in _lines(out) if "=" in line
            )
        except Exception:
            settings[namespace] = {}

    accessibility = _lines(
        client.shell("settings get secure enabled_accessibility_services", serial=serial)
    )
    admins = _lines(
        client.shell("dumpsys device_policy | grep -E 'admin=|ComponentInfo' || true", serial=serial)
    )
    overlays = _lines(
        client.shell("cmd appops query-op SYSTEM_ALERT_WINDOW allow", serial=serial)
    )
    notification = _lines(
        client.shell("settings get secure enabled_notification_listeners", serial=serial)
    )
    launcher = client.shell(
        "cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME || true",
        serial=serial,
    ).strip()

    return {
        "settings": settings,
        "accessibility_services": accessibility,
        "device_policy": admins,
        "overlay_appops": overlays,
        "notification_listeners": notification,
        "default_launcher": launcher,
    }


def collect_package_metadata(client: AdbClient, serial: str, package: str) -> dict:
    dump = client.shell(f"dumpsys package {package}", serial=serial)
    permissions = sorted(
        set(re.findall(r"android\.permission\.[A-Z0-9_]+", dump))
    )
    return {
        "package": package,
        "permissions": permissions,
        "raw_size": len(dump),
    }


def collect_runtime(client: AdbClient, serial: str) -> dict:
    return {
        "processes": _lines(client.shell("ps -A", serial=serial))[:500],
        "services": _lines(client.shell("dumpsys activity services", serial=serial))[:500],
    }
