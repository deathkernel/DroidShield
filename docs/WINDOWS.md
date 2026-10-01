# DroidShield on Windows

DroidShield's Windows edition keeps the defensive Android triage engine and adds a Windows-native host layer.

## Requirements

- Windows 10/11
- Python 3.10+
- Android SDK Platform-Tools (`adb.exe`)
- USB debugging enabled on the Android device
- The device must be owned by, or authorized for assessment by, the operator

Optional analysis tools: AAPT2, apksigner, apktool, JADX, and YARA. Missing tools are reported as unavailable.

## First run

In PowerShell:

    adb version
    adb devices
    droidshield windows

If the phone shows `unauthorized`, unlock it and accept the USB debugging authorization prompt. MTP/file-transfer mode is separate from ADB debugging.

## Design

The Windows layer uses `subprocess` with `shell=False`, so package names and paths are not interpreted as PowerShell/cmd syntax. Existing ADB, APK, YARA, evidence, reporting, and guarded-remediation modules remain the shared source of truth.

## Troubleshooting

### `adb` is not recognized
Install Android Platform-Tools, add its directory to PATH, and open a new PowerShell window.

### Device is `unauthorized`
Unlock the phone, enable USB debugging, accept the RSA prompt, then run `adb kill-server`, `adb start-server`, and `adb devices`.

### Device is missing
Try a known-good data cable and USB port. Check Windows Device Manager for an Android/ADB device and install the manufacturer's USB driver when required.

## Safety

Scanning is read-only by default. Remediation remains guarded by the existing `--confirm` workflow. A heuristic score is not proof of malware; review package provenance and collected evidence before changing a device.
