from __future__ import annotations

import re
from typing import Any

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+")
_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}")


def _process_name(line: str) -> str | None:
    parts = line.split()
    if len(parts) < 2:
        return None
    return parts[-1]


def attribute_processes(process_lines: list[str], packages: set[str]) -> list[dict[str, Any]]:
    result = []
    for line in process_lines:
        match = re.search(r"^\S+\s+(\d+)\s+", line)
        if not match:
            continue
        pid = match.group(1)
        name = _process_name(line)
        package = None
        if name in packages:
            package = name
        else:
            candidates = [pkg for pkg in packages if pkg in line]
            if len(candidates) == 1:
                package = candidates[0]
        result.append({"pid": pid, "process": name, "package": package, "attribution": "exact-name" if package == name else "line-match" if package else "unattributed"})
    return result[:1000]


def summarize_runtime(runtime: dict[str, Any], packages: list[str]) -> dict[str, Any]:
    processes = runtime.get("processes", [])
    attributed = attribute_processes(processes, set(packages))
    package_counts: dict[str, int] = {}
    for item in attributed:
        if item["package"]:
            package_counts[item["package"]] = package_counts.get(item["package"], 0) + 1
    return {"process_count": len(attributed), "attributed_processes": attributed, "package_process_counts": package_counts, "attributed_package_count": len(package_counts)}


def correlate_network(network: dict[str, Any], runtime_summary: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for item in network.get("socket_processes", []):
        process = item.get("process")
        package = None
        for candidate in runtime_summary.get("attributed_processes", []):
            if candidate.get("pid") == item.get("pid"):
                package = candidate.get("package")
                break
        rows.append({**item, "package": package, "attribution": "runtime-pid" if package else "unattributed"})
    return {"socket_attribution": rows[:500], "attributed_socket_count": sum(1 for row in rows if row.get("package")), "unattributed_socket_count": sum(1 for row in rows if not row.get("package"))}


def correlate_security_events(
    log_lines: list[str],
    packages: list[str],
    max_events: int = 500,
) -> dict[str, Any]:
    events = []
    package_set = set(packages)
    patterns = {
        "install": re.compile(r"(?i)\b(?:install|installed|packageinstaller|PackageManager)\b"),
        "permission": re.compile(r"(?i)\bpermission\b"),
        "denied": re.compile(r"(?i)\bdenied\b"),
        "security": re.compile(r"(?i)\bsecurity\b"),
        "accessibility": re.compile(r"(?i)\baccessibility\b"),
        "overlay": re.compile(r"(?i)\boverlay\b"),
    }
    for line in log_lines:
        categories = [name for name, pattern in patterns.items() if pattern.search(line)]
        if not categories:
            continue
        matched = [package for package in package_set if package in line]
        events.append({
            "event_type": categories[0],
            "categories": categories,
            "package": matched[0] if len(matched) == 1 else None,
            "packages_in_line": sorted(matched),
            "line": line,
        })
        if len(events) >= max_events:
            break
    return {
        "event_count": len(events),
        "package_attributed_count": sum(1 for event in events if event.get("package")),
        "events": events,
    }
