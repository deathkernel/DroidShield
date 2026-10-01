from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict:
    root = root.resolve()
    entries = []
    if not root.exists():
        return {"schema_version": "1.0", "root": str(root), "files": [], "manifest_sha256": None}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            rel = path.relative_to(root).as_posix()
            if rel in {"evidence-manifest.json", "evidence-manifest.sha256"}:
                continue
            entries.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
        except OSError:
            continue
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(), "root": str(root), "files": entries, "manifest_sha256": hashlib.sha256(payload).hexdigest()}


def verify_manifest(root: Path, manifest: dict) -> dict:
    current = build_manifest(root)
    expected = {item["path"]: item["sha256"] for item in manifest.get("files", [])}
    actual = {item["path"]: item["sha256"] for item in current.get("files", [])}
    missing = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    changed = sorted(path for path in set(expected) & set(actual) if expected[path] != actual[path])
    expected_manifest_hash = manifest.get("manifest_sha256")
    actual_manifest_hash = current.get("manifest_sha256")
    manifest_hash_valid = (
        expected_manifest_hash is None
        or expected_manifest_hash == actual_manifest_hash
    )
    sidecar_valid = True
    sidecar = root / "evidence-manifest.sha256"
    if sidecar.is_file() and expected_manifest_hash:
        try:
            recorded = sidecar.read_text(encoding="utf-8").strip().split()[0]
            sidecar_valid = recorded == expected_manifest_hash
        except (OSError, IndexError):
            sidecar_valid = False
    valid = not (missing or added or changed) and manifest_hash_valid and sidecar_valid
    return {
        "valid": valid,
        "missing": missing,
        "added": added,
        "changed": changed,
        "manifest_hash_valid": manifest_hash_valid,
        "sidecar_valid": sidecar_valid,
    }


def write_manifest(root: Path, output: Path | None = None) -> dict:
    manifest = build_manifest(root)
    target = output or (root / "evidence-manifest.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
