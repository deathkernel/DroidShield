from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_case_bundle(
    case_dir: Path,
    report: dict[str, Any],
    markdown: str | None = None,
    html: str | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    case_dir.mkdir(parents=True, exist_ok=True)
    report_path = case_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if markdown is not None:
        (case_dir / "report.md").write_text(markdown, encoding="utf-8")
    if html is not None:
        (case_dir / "report.html").write_text(html, encoding="utf-8")
    notes_path = case_dir / "notes.jsonl"
    existing = []
    if notes_path.exists():
        existing = [line for line in notes_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for note in notes or []:
        existing.append(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": str(note),
        }, ensure_ascii=False))
    if existing:
        notes_path.write_text("\n".join(existing) + "\n", encoding="utf-8")

    case_metadata = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "device": report.get("device", {}),
        "finding_count": len(report.get("findings", [])),
        "risk": report.get("risk", {}),
        "analyst_notes": len(existing),
        "scope": "authorized defensive Android investigation",
    }
    (case_dir / "case.json").write_text(json.dumps(case_metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    artifacts = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.name in {
            "evidence-manifest.json",
            "evidence-manifest.sha256",
        }:
            continue
        artifacts.append({
            "path": str(path.relative_to(case_dir)).replace("\\", "/"),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        })

    manifest = {
        "schema_version": "1.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": artifacts,
    }
    manifest_path = case_dir / "evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    manifest_hash = _sha256(manifest_path)
    hash_path = case_dir / "evidence-manifest.sha256"
    hash_path.write_text(f"{manifest_hash}  evidence-manifest.json\n", encoding="utf-8")

    return {
        **manifest,
        "manifest_sha256": manifest_hash,
    }
