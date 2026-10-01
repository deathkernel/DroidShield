from droidshield.component_graph import build_component_graph


def test_component_graph_links_components_and_active_roles():
    metadata = [
        {
            "package": "com.example.bad",
            "services": ["com.example.bad.BadService"],
            "receivers": ["com.example.bad.BootReceiver"],
            "providers": [],
            "activities": ["com.example.bad.MainActivity"],
            "component_details": {
                "activities": [{"name": "com.example.bad.MainActivity", "package": "com.example.bad", "type": "activity", "exported": True}],
                "services": [{"name": "com.example.bad.BadService", "package": "com.example.bad", "type": "service", "exported": False}],
                "receivers": [{"name": "com.example.bad.BootReceiver", "package": "com.example.bad", "type": "receiver", "exported": False}],
                "providers": [],
            },
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


def test_component_graph_surfaces_exported_components():
    result = build_component_graph([
        {
            "package": "com.example.app",
            "component_details": {
                "activities": [{"name": "com.example.app.Main", "exported": True}],
                "services": [], "receivers": [], "providers": [],
            },
        }
    ], {"active_component_packages": {}})
    assert result["exported_components"][0]["component"] == "com.example.app.Main"
