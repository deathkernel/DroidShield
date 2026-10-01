from droidshield import __version__
from droidshield.cli import build_parser


def test_cli_exposes_version_flag():
    parser = build_parser()
    assert parser.parse_args(["--version"]) is not None


def test_cli_has_core_tool_commands():
    parser = build_parser()
    for command in ("devices", "capabilities", "scan", "apk", "package-apk", "yara", "case", "case-verify", "remediate"):
        args = parser.parse_args([command] + (["--output", "x"] if command == "case" else []))
        assert args.command == command
    assert __version__
