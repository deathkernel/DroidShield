from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path


class ApkToolError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def inspect_apk(path: Path) -> dict:
    if not path.is_file():
        raise ApkToolError(f"APK not found: {path}")

    result = {
        "path": str(path),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "tools": {
            name: tool_available(name)
            for name in ("aapt2", "apktool", "jadx", "yara")
        },
    }

    if result["tools"]["aapt2"]:
        proc = subprocess.run(
            ["aapt2", "dump", "badging", str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
        result["aapt2"] = {
            "returncode": proc.returncode,
            "output": proc.stdout[:20000],
            "error": proc.stderr[:4000],
        }

    return result
