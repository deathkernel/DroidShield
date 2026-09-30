from droidshield.component_graph import build_component_graph


def test_component_graph_links_components_and_active_roles():
    metadata = [
        {
            "package": "com.example.bad",
            "services": ["com.example.bad.BadService"],
            "receivers": ["com.example.bad.BootReceiver"],
            "providers": [],
            "permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        }
    ]
    security = {
        "active_component_packages": {
            "accessibility": ["com.example.bad"],
            "device_policy": [],
            "overlay": [],
            "notification": [],
            "launcher": [],
        }
    }

    result = build_component_graph(metadata, security)
    node = result["nodes"][0]

    assert node["package"] == "com.example.bad"
    assert node["active_roles"] == ["accessibility"]
    assert "com.example.bad.BadService" in node["components"]["services"]
    assert result["edge_count"] >= 2
