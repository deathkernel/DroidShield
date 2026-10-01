from __future__ import annotations

from dataclasses import dataclass

from .tool_paths import resolve_tool


@dataclass(frozen=True)
class ToolAdapter:
    name: str
    binary: str
    purpose: str

    def path(self) -> str | None:
        return resolve_tool(self.binary)

    def available(self) -> bool:
        return self.path() is not None

    def describe(self) -> dict:
        return {
            "name": self.name,
            "binary": self.binary,
            "path": self.path(),
            "available": self.available(),
            "purpose": self.purpose,
        }


ADAPTERS = (
    ToolAdapter("ADB", "adb", "Android device transport and evidence collection"),
    ToolAdapter("AAPT2", "aapt2", "APK manifest/package metadata inspection"),
    ToolAdapter("apksigner", "apksigner", "APK signature and certificate verification"),
    ToolAdapter("apktool", "apktool", "APK resource and manifest decoding"),
    ToolAdapter("JADX", "jadx", "DEX to source-oriented static analysis"),
    ToolAdapter("YARA", "yara", "Rule-based malware indicator scanning"),
)


def tool_inventory() -> list[dict]:
    return [adapter.describe() for adapter in ADAPTERS]


def available_tools() -> list[str]:
    return [adapter.name for adapter in ADAPTERS if adapter.available()]
