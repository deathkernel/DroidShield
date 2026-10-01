from pathlib import Path
import json

from droidshield.apk_indicators import analyze_source_text
from droidshield.evidence import build_manifest, verify_manifest
from droidshield.explain import explain_assessment
from droidshield.posture import assess_posture


def test_behavior_indicators_detect_sensitive_patterns(tmp_path: Path):
    (tmp_path / "Example.java").write_text("DexClassLoader(x); setJavaScriptEnabled(true); System.loadLibrary(\"x\");", encoding="utf-8")
    result = analyze_source_text(tmp_path)
    assert result["indicator_counts"]["dynamic-code-loading"] == 1
    assert result["indicator_counts"]["webview-javascript"] == 1
    assert result["indicator_counts"]["native-loading"] == 1


def test_evidence_manifest_round_trip(tmp_path: Path):
    (tmp_path / "report.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
    manifest = build_manifest(tmp_path)
    assert manifest["files"][0]["sha256"]
    assert verify_manifest(tmp_path, manifest)["valid"]
    (tmp_path / "report.json").write_text("changed", encoding="utf-8")
    assert verify_manifest(tmp_path, manifest)["valid"] is False


def test_explain_assessment_is_traceable():
    result = explain_assessment({"package": "com.example", "level": "MEDIUM", "score": 42, "signals": ["camera-capable", "camera-granted", "active-overlay", "sensitive-permission-combination"]})
    assert result["package"] == "com.example"
    assert any("granted sensitive capability" in item for item in result["why"])
    assert result["next_steps"]


def test_posture_reports_active_security_controls():
    report = {"device": {"security_patch": "2026-08-01"}, "security": {"accessibility_services": ["x"], "device_policy": [], "overlay_appops": ["y"], "notification_listeners": []}, "metadata_coverage": {"packages_with_collection_errors": 0}}
    result = assess_posture(report)
    assert result["attention_count"] == 2
    assert result["coverage"]["packages_with_collection_errors"] == 0
