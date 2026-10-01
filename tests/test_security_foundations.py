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


from droidshield.runtime_intel import summarize_runtime, correlate_network
from droidshield.detection import correlate


def test_runtime_process_and_socket_attribution():
    processes = ["u0_a1 123 1 100 0 0 S com.example", "u0_a2 456 1 100 0 0 S com.other"]
    runtime = {"processes": processes}
    summary = summarize_runtime(runtime, ["com.example", "com.other"])
    network = {"socket_processes": [{"pid": "123", "process": processes[0]}, {"pid": "999", "process": None}]}
    correlated = correlate_network(network, summary)
    assert correlated["attributed_socket_count"] == 1
    assert correlated["socket_attribution"][0]["package"] == "com.example"


def test_network_correlation_adds_signal_for_sensitive_package():
    report = {
        "package_assessments": [{"package": "com.example", "level": "MEDIUM"}],
        "third_party_packages": ["com.example"],
        "security": {},
        "network": {"intelligence": {"socket_attribution": [{"pid": "123", "package": "com.example"}]}},
    }
    result = correlate(report)
    assert "network-active-sensitive:com.example" in result["signals"]


from droidshield.provenance import normalize_digest, certificate_identity, compare_certificate_identity
from droidshield.case import build_case_bundle


def test_certificate_normalization_and_comparison():
    assert normalize_digest("AA:BB" + ":00" * 30) is not None
    left = {"available": True, "returncode": 0, "certificates": {"sha256": ["AA:BB:" + "00:" * 30]}}
    right = {"available": True, "returncode": 0, "certificates": {"sha256": ["aabb" + "00" * 30]}}
    result = compare_certificate_identity(left, right)
    assert result["comparable"] is True
    assert result["same_signer"] is True


def test_case_bundle_records_metadata_and_notes(tmp_path: Path):
    report = {"device": {"serial": "test"}, "findings": [{"package": "com.example"}], "risk": {"level": "MEDIUM", "score": 42}}
    result = build_case_bundle(tmp_path, report, notes=["Review installer provenance"])
    assert (tmp_path / "case.json").exists()
    assert (tmp_path / "notes.jsonl").exists()
    assert result["artifacts"]
