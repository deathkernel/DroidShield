from __future__ import annotations

from typing import Any


COMPONENT_KEYS = ("services", "receivers", "providers")


def build_component_graph(
    package_metadata: list[dict[str, Any]],
    security: dict[str, Any],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    active = security.get("active_component_packages", {})

    for item in package_metadata:
        package = item.get("package")
        if not package:
            continue
        node = nodes.setdefault(
            package,
            {
                "package": package,
                "components": {"services": [], "receivers": [], "providers": []},
                "permissions": item.get("permissions", []),
                "active_roles": [],
            },
        )
        for key in COMPONENT_KEYS:
            node["components"][key] = sorted(set(item.get(key, [])))
            for component in node["components"][key]:
                edges.append({
                    "from": package,
                    "to": component,
                    "type": key[:-1],
                })

    for role, packages in active.items():
        if role == "launcher":
            role_name = "default-launcher"
        else:
            role_name = role
        for package in packages:
            node = nodes.setdefault(
                package,
                {
                    "package": package,
                    "components": {"services": [], "receivers": [], "providers": []},
                    "permissions": [],
                    "active_roles": [],
                },
            )
            if role_name not in node["active_roles"]:
                node["active_roles"].append(role_name)
            edges.append({
                "from": package,
                "to": role_name,
                "type": "active-role",
            })

    for node in nodes.values():
        node["active_roles"] = sorted(node["active_roles"])

    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["package"]),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
