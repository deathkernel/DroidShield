from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

WINDOWS_TOOLS = ("adb.exe", "fastboot.exe", "aapt2.exe", "apksigner.bat", "apktool.bat", "jadx.bat", "yara.exe")

def is_windows() -> bool:
    return os.name == "nt"

def find_executable(name: str) -> str | None:
    return shutil.which(name)

def capabilities() -> dict[str, bool]:
    return {name: find_executable(name) is not None for name in WINDOWS_TOOLS}

def run_command(command: Sequence[str], *, timeout: int = 30, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, shell=False)

def adb_path() -> str | None:
    return find_executable("adb.exe") or find_executable("adb")

def list_adb_devices() -> list[tuple[str, str]]:
    adb = adb_path()
    if not adb:
        raise RuntimeError("ADB was not found. Install Android platform-tools and add its directory to PATH.")
    result = run_command([adb, "devices"])
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or "adb devices failed")
    devices = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line or "\\t" not in line:
            continue
        serial, state = line.split("\\t", 1)
        devices.append((serial.strip(), state.strip()))
    return devices

def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def windows_environment_report() -> dict:
    return {"platform": platform.platform(), "system": platform.system(), "release": platform.release(), "python": platform.python_version(), "architecture": platform.machine(), "is_windows": is_windows(), "adb": adb_path(), "tools": capabilities()}
