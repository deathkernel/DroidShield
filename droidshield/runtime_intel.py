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
