# DroidShield Windows executable

## Build

    .venv\\Scripts\\python.exe -m pip install -e ".[test,windows]"
    .venv\\Scripts\\python.exe -m PyInstaller --name DroidShield --onedir --windowed --collect-all rich droidshield/windows_launcher.py

The generated application is placed under `dist\\DroidShield\\`.

Android Platform-Tools are intentionally not bundled. Install them separately and put `adb.exe` on PATH.

## Verification

On the target Windows machine:

    dist\\DroidShield\\DroidShield.exe

Then connect an authorized Android device and use **Refresh** followed by **START DEEP SCAN**.

## Dashboard

The Windows console provides:

- connected-device selection and ADB status
- risk score, confidence, findings, and analyzed-package cards
- overview with hardening recommendations and security state
- findings explorer with severity/evidence details
- package inventory and per-package metadata
- evidence summary and evidence-folder access
- JSON and HTML report export
- in-memory scan history
- APK hashing toggle for deeper evidence collection

The desktop UI is a presentation layer over the existing scanner. It does not execute APKs, bypass ADB authorization, or change the device during a scan.
