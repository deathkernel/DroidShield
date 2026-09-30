import json

from droidshield.case import build_case_bundle


def test_case_bundle_builds_hash_manifest(tmp_path):
    report = {"schema_version": "0.6", "risk": {"score": 12}}
    manifest = build_case_bundle(
        tmp_path,
        report,
        markdown="# Report\n",
        html="<html></html>",
    )

    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
    loaded = json.loads((tmp_path / "evidence-manifest.json").read_text())
    names = {item["path"] for item in loaded["artifacts"]}
    assert {"report.json", "report.md", "report.html"} <= names
    assert all(len(item["sha256"]) == 64 for item in loaded["artifacts"])
