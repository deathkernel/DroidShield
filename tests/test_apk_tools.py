from pathlib import Path

from droidshield.apk import _run_tool


def test_run_tool_handles_non_cp1252_output():
    result = _run_tool(
        [
            "python",
            "-c",
            "import sys; sys.stdout.buffer.write(b'prefix\\x8d\\xffsuffix')",
        ]
    )
    assert result["returncode"] == 0
    assert "prefix" in result["output"]
    assert "suffix" in result["output"]
