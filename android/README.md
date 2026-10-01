# DroidShield Android companion

This branch contains the native Android scan UI and its authenticated transport to the DroidShield host scanner.

## Run the scanner host

On the Windows/Kali machine that has the authorized Android device connected:

    droidshield devices
    droidshield mobile-server --host 0.0.0.0 --port 8765 --token YOUR_LONG_RANDOM_TOKEN

On the Android app, enter the host's LAN URL and the same bearer token, then start a deep scan.

## Security

- The Android companion does not claim to scan when the host scanner is unavailable.
- The API requires a bearer token.
- The host performs the existing read-only DroidShield scan engine.
- The Android UI displays the returned risk and findings without inventing detections.
- For production deployment, prefer HTTPS or a trusted private network/VPN.

## Current scope

The mobile UI currently renders device model/Android version, analyzed-package count, risk level, findings, and scan progress. APK acquisition/deep static analysis remains a host-side operation.