from pathlib import Path
import zipfile

from droidshield.static_artifacts import inspect_apk_archive


def test_static_apk_archive_reports_dex_and_native_entries(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex\n039\x00" + b"\x00" * 32)
        archive.writestr("classes2.dex", b"dex\n040\x00" + b"\x00" * 16)
        archive.writestr("lib/arm64-v8a/libsample.so", b"\x7fELF" + b"\x02\x01" + b"\x00" * 20)
        archive.writestr("assets/config.json", b"{}")
    result = inspect_apk_archive(apk)
    assert result["opened"] is True
    assert result["dex_count"] == 2
    assert result["dex_files"][0]["magic_valid"] is True
    assert result["native_library_count"] == 1
    assert result["native_libraries"][0]["is_elf"] is True
    assert result["asset_count"] == 1
