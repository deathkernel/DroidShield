from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json


def save_evidence(report: dict, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"droidshield-{stamp}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
