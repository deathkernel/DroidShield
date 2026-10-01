from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


_WINDOWS_TOOL_FILENAMES = {
    "aapt2": "aapt2.exe",
    "apksigner": "apksigner.bat",
    "adb": "adb.exe",
    "fastboot": "fastboot.exe",
}


def _version_key(name: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", name)
    return tuple(int(part) for part in parts) if parts else (0,)


def _android_sdk_roots() -> list[Path]:
    roots: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value).expanduser())

    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            roots.append(Path(local_appdata) / "Android" / "Sdk")

    seen: set[Path] = set()
    unique: list[Path] = []
    for root in roots:
        resolved = root.resolve() if root.exists() else root
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def resolve_tool(name: str) -> str | None:
    """Resolve a defensive analysis tool from PATH or the local Android SDK.

    Android SDK build-tools ship AAPT2 and apksigner, but they are often not
    added to PATH on Windows. This resolver keeps normal PATH behavior first
    and then searches installed SDK build-tools directories, newest-first.
    """
    direct = shutil.which(name)
    if direct:
        return direct

    filename = _WINDOWS_TOOL_FILENAMES.get(name)
    if not filename:
        return None

    candidates: list[tuple[tuple[int, ...], Path]] = []
    for sdk_root in _android_sdk_roots():
        build_tools = sdk_root / "build-tools"
        if not build_tools.is_dir():
            continue
        for version_dir in build_tools.iterdir():
            if not version_dir.is_dir():
                continue
            candidate = version_dir / filename
            if candidate.is_file():
                candidates.append((_version_key(version_dir.name), candidate))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    return str(candidates[0][1])


def tool_available(name: str) -> bool:
    return resolve_tool(name) is not None


def resolved_tools(names: tuple[str, ...]) -> dict[str, str | None]:
    return {name: resolve_tool(name) for name in names}
