from __future__ import annotations

from .adb import AdbClient


def collect_network_state(client: AdbClient, serial: str) -> dict:
    commands = {
        "sockets": "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true",
        "connectivity": "dumpsys connectivity 2>/dev/null || true",
    }
    outputs = {}
    errors = {}

    for name, command in commands.items():
        try:
            outputs[name] = client.shell(command, serial=serial).splitlines()[:500]
        except Exception as exc:
            outputs[name] = []
            errors[name] = str(exc)

    return {
        "sockets": outputs["sockets"],
        "connectivity": outputs["connectivity"],
        "collection_errors": errors,
    }
