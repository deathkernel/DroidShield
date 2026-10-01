from __future__ import annotations

import hashlib
import os
import platform
import sys

from droidshield.windows import capabilities, is_windows, sha256_file, windows_environment_report


def test_is_windows_matches_runtime():
    assert is_windows() is (os.name == "nt")

def test_capabilities_are_boolean_map():
    result = capabilities()
    assert result
    assert all(isinstance(value, bool) for value in result.values())

def test_environment_report_is_non_sensitive():
    report = windows_environment_report()
    assert report["system"] == platform.system()
    assert "PATH" not in report
    assert "USERNAME" not in report

def test_sha256_file(tmp_path):
    path = tmp_path / "sample.bin"
    payload = b"DroidShield Windows\n"
    path.write_bytes(payload)
    assert sha256_file(path) == hashlib.sha256(payload).hexdigest()

def test_windows_module_imports_off_windows():
    from droidshield import windows
    assert windows.is_windows() is (sys.platform == "win32")
