from __future__ import annotations

import re

from .adb import AdbClient


_PID_RE = re.compile(r"pid=(\d+)")


def _process_map(process_lines: list[str]) -> dict[str, str]:
    mapping = {}
    for line in process_lines:
        match = re.search(r"^\S+\s+(\d+)\s+", line)
        if not match:
            continue
        pid = match.group(1)
        mapping[pid] = line
    return mapping


def collect_network_state(
    client: AdbClient,
    serial: str,
    process_lines: list[str] | None = None,
) -> dict:
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

    process_map = _process_map(process_lines or [])
    socket_processes = []
    for line in outputs["sockets"]:
        for pid in _PID_RE.findall(line):
            socket_processes.append({
                "pid": pid,
                "process": process_map.get(pid),
                "socket_line": line.strip(),
            })

    return {
        "sockets": outputs["sockets"],
        "connectivity": outputs["connectivity"],
        "socket_processes": socket_processes[:500],
        "collection_errors": errors,
    }
