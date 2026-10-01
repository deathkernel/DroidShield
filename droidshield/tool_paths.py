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


def _unique_paths(roots: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for root in roots:
        resolved = root.resolve() if root.exists() else root
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def _explicit_android_sdk_roots() -> list[Path]:
    roots: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value).expanduser())
    return _unique_paths(roots)


def _default_android_sdk_roots() -> list[Path]:
    roots: list[Path] = []
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            roots.append(Path(local_appdata) / "Android" / "Sdk")
    return _unique_paths(roots)


def _sdk_tool_path(name: str, sdk_roots: list[Path]) -> str | None:
    filename = _WINDOWS_TOOL_FILENAMES.get(name)
    if not filename:
        return None

    candidates: list[tuple[tuple[int, ...], Path]] = []
    for sdk_root in sdk_roots:
        # Platform-tools (adb/fastboot) are versioned independently from
        # build-tools. Prefer the SDK-managed copy before falling back to PATH.
        if name in {"adb", "fastboot"}:
            platform_candidate = sdk_root / "platform-tools" / filename
            if platform_candidate.is_file():
                candidates.append(((10**9,), platform_candidate))
            continue
        for tool_dir_name in ("build-tools",):
            tool_dir = sdk_root / tool_dir_name
            if not tool_dir.is_dir():
                continue
            for version_dir in tool_dir.iterdir():
                if not version_dir.is_dir():
                    continue
                candidate = version_dir / filename
                if candidate.is_file():
                    candidates.append((_version_key(version_dir.name), candidate))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    return str(candidates[0][1])


def resolve_tool(name: str) -> str | None:
    """Resolve a defensive analysis tool with explicit SDK precedence.

    When ANDROID_SDK_ROOT or ANDROID_HOME is set, that SDK is authoritative.
    This matters on Windows where Android SDK Build Tools are commonly not on
    PATH. If no explicit SDK tool is found, DroidShield falls back to PATH and
    finally to the conventional per-user Android SDK location.
    """
    explicit = _sdk_tool_path(name, _explicit_android_sdk_roots())
    if explicit:
        return explicit

    direct = shutil.which(name)
    if direct:
        return direct

    return _sdk_tool_path(name, _default_android_sdk_roots())


def tool_available(name: str) -> bool:
    return resolve_tool(name) is not None


def resolved_tools(names: tuple[str, ...]) -> dict[str, str | None]:
    return {name: resolve_tool(name) for name in names}
