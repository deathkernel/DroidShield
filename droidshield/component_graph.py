from __future__ import annotations

import re
from typing import Any

COMPONENT_KEYS = ("activities", "services", "receivers", "providers")


def _component_records(package: str, dump: str, pattern: str, kind: str) -> list[dict[str, Any]]:
    names = sorted(set(re.findall(pattern, dump, re.IGNORECASE)))
    return [{"name": name, "package": package, "type": kind} for name in names]


def extract_components(package: str, dump: str) -> dict[str, list[dict[str, Any]]]:
    return {
        "activities": _component_records(package, dump, r"Activity\{[^}]*\s([A-Za-z0-9_.$]+)", "activity"),
        "services": _component_records(package, dump, r"ServiceInfo\{[^}]*\s([A-Za-z0-9_.$]+)", "service"),
        "receivers": _component_records(package, dump, r"ReceiverList\{[^}]*\s([A-Za-z0-9_.$]+)", "receiver"),
        "providers": _component_records(package, dump, r"ProviderInfo\{[^}]*\s([A-Za-z0-9_.$]+)", "provider"),
    }


def build_component_graph(package_metadata: list[dict[str, Any]], security: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    active = security.get("active_component_packages", {})
    for item in package_metadata:
        package = item.get("package")
        if not package:
            continue
        node = nodes.setdefault(package, {"package": package, "components": {key: [] for key in COMPONENT_KEYS}, "permissions": item.get("permissions", []), "active_roles": []})
        for key in COMPONENT_KEYS:
            values = item.get(key, [])
            node["components"][key] = values
            for component in values:
                name = component.get("name") if isinstance(component, dict) else component
                edges.append({"from": package, "to": name, "type": key[:-1]})
    for role, packages in active.items():
        role_name = "default-launcher" if role == "launcher" else role
        for package in packages:
            node = nodes.setdefault(package, {"package": package, "components": {key: [] for key in COMPONENT_KEYS}, "permissions": [], "active_roles": []})
            if role_name not in node["active_roles"]:
                node["active_roles"].append(role_name)
            edges.append({"from": package, "to": role_name, "type": "active-role"})
    for node in nodes.values():
        node["active_roles"] = sorted(node["active_roles"])
    exported = []
    for node in nodes.values():
        for key in COMPONENT_KEYS:
            exported.extend({"package": node["package"], "component": item["name"], "type": key[:-1]} for item in node["components"][key] if isinstance(item, dict) and item.get("exported") is True)
    return {"nodes": sorted(nodes.values(), key=lambda item: item["package"]), "edges": edges, "exported_components": exported, "node_count": len(nodes), "edge_count": len(edges)}
