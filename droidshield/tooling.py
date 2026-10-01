from __future__ import annotations

from .tool_adapters import tool_inventory
from .tool_paths import resolve_tool

TOOLS = {
    "adb": "adb",
    "aapt2": "aapt2",
    "apksigner": "apksigner",
    "apktool": "apktool",
    "jadx": "jadx",
    "yara": "yara",
    "sha256sum": "sha256sum",
}


def capabilities() -> dict[str, bool]:
    return {name: resolve_tool(binary) is not None for name, binary in TOOLS.items()}


def inventory() -> list[dict]:
    return tool_inventory()
