from __future__ import annotations

from .tool_adapters import tool_inventory

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
    import shutil
    return {name: shutil.which(binary) is not None for name, binary in TOOLS.items()}


def inventory() -> list[dict]:
    return tool_inventory()
