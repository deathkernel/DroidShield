from __future__ import annotations

import re
from typing import Any

COMPONENT_KEYS = ("activities", "services", "receivers", "providers")


def _component_records(package: str, dump: str, pattern: str, kind: str) -> list[dict[str, Any]]:
    records = []
    for name in sorted(set(re.findall(pattern, dump, re.IGNORECASE))):
        escaped = re.escape(name)
        nearby = re.search(rf"(?s).{{0,300}}{escaped}.{{0,300}}", dump, re.IGNORECASE)
        text = nearby.group(0) if nearby else ""
        exported_match = re.search(r"\bexported=(true|false)\b", text, re.IGNORECASE)
        records.append({
            "name": name,
            "package": package,
            "type": kind,
            "exported": (exported_match.group(1).lower() == "true") if exported_match else None,
            "intent_filter_count": len(re.findall(r"<intent-filter\\b|intent-filter", text, re.IGNORECASE)),
        })
    return records


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
        details = item.get("component_details", {}) or {}
        for key in COMPONENT_KEYS:
            values = details.get(key) if isinstance(details.get(key), list) else item.get(key, [])
            names = [
                component.get("name") if isinstance(component, dict) else component
                for component in values
                if (component.get("name") if isinstance(component, dict) else component)
            ]
            node["components"][key] = sorted(set(names))
            for component in values:
                name = component.get("name") if isinstance(component, dict) else component
                if name:
                    edges.append({"from": package, "to": name, "type": key[:-1]})
        node["component_details"] = {
            key: (details.get(key) if isinstance(details.get(key), list) else [])
            for key in COMPONENT_KEYS
        }
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
            details = node.get("component_details", {}).get(key, [])
            exported.extend({"package": node["package"], "component": item["name"], "type": key[:-1]} for item in details if isinstance(item, dict) and item.get("exported") is True)
    return {"nodes": sorted(nodes.values(), key=lambda item: item["package"]), "edges": edges, "exported_components": exported, "node_count": len(nodes), "edge_count": len(edges)}
