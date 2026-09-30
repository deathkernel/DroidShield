from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def scan_with_yara(path: Path, rules: Path | None = None) -> dict:
    if shutil.which("yara") is None:
        return {"available": False, "matches": [], "error": "yara not installed"}

    command = ["yara", "-r"]
    if rules:
        command.append(str(rules))
    else:
        return {
            "available": True,
            "matches": [],
            "error": "No rule file supplied; refusing to run an undefined signature set.",
        }

    command.append(str(path))
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return {
        "available": True,
        "returncode": proc.returncode,
        "matches": proc.stdout.splitlines(),
        "error": proc.stderr[:4000],
    }
