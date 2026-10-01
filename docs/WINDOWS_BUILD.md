# Building DroidShield for Windows

## Development install

    py -3 -m venv .venv
    .venv\\Scripts\\activate
    python -m pip install -e ".[test]"
    droidshield windows

## Test suite

    python -m pytest -q

The Windows adapter is intentionally importable on Linux/Kali too, so the shared test suite can exercise its portable logic before a Windows CI runner is used.

## Executable packaging

The project can be packaged with a Windows Python application bundler such as PyInstaller. The generated executable should be tested on a clean Windows machine with Android Platform-Tools installed separately. Do not bundle a private ADB authorization database or device credentials.
