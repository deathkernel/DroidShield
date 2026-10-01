from pathlib import Path

from droidshield.tool_paths import resolve_tool


def test_resolve_tool_prefers_newest_android_sdk_build_tool(tmp_path, monkeypatch):
    sdk = tmp_path / "sdk"
    old = sdk / "build-tools" / "35.0.0"
    new = sdk / "build-tools" / "37.0.0"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    (old / "aapt2.exe").write_text("old", encoding="utf-8")
    (new / "aapt2.exe").write_text("new", encoding="utf-8")

    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    monkeypatch.delenv("ANDROID_HOME", raising=False)

    assert resolve_tool("aapt2") == str(new / "aapt2.exe")


def test_resolve_tool_finds_apksigner_from_android_sdk(tmp_path, monkeypatch):
    sdk = tmp_path / "sdk"
    build_tools = sdk / "build-tools" / "36.1.0"
    build_tools.mkdir(parents=True)
    signer = build_tools / "apksigner.bat"
    signer.write_text("@echo off", encoding="utf-8")

    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    monkeypatch.delenv("ANDROID_HOME", raising=False)

    assert resolve_tool("apksigner") == str(signer)
