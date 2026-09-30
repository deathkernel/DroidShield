from __future__ import annotations

import shutil


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
    return {name: shutil.which(binary) is not None for name, binary in TOOLS.items()}
