from pathlib import Path
import zipfile

from droidshield.static_artifacts import inspect_apk_archive
from droidshield.tool_paths import resolve_tool


def test_apk_archive_reports_truncation(tmp_path: Path):
    apk = tmp_path / "large.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        for index in range(5):
            archive.writestr(f"res/raw/file{index}.txt", "x")
    result = inspect_apk_archive(apk, max_entries=3)
    assert result["archive_entry_count"] == 5
    assert result["entry_count"] == 3
    assert result["truncated"] is True


def test_sdk_platform_tools_take_precedence(monkeypatch, tmp_path: Path):
    sdk = tmp_path / "sdk"
    platform_tools = sdk / "platform-tools"
    platform_tools.mkdir(parents=True)
    adb = platform_tools / "adb.exe"
    adb.write_bytes(b"")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    monkeypatch.setattr("droidshield.tool_paths.os", __import__("os"))
    assert resolve_tool("adb") == str(adb)
