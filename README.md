# DroidShield

DroidShield is a defensive Android security and incident-response toolkit designed to run on Kali Linux.

## Mission

Identify potentially malicious or abusive Android applications and configurations, preserve useful evidence, safely remediate supported findings, and verify the result.

DroidShield is **not** an attacker-hunting framework. Its primary focus is malware identification, device/app integrity, remediation, and hardening.

## Current capabilities

- ADB device discovery and authorized-device selection
- Device inventory and Android build/security-patch metadata
- Complete installed-package inventory with third-party package separation
- Package permission and component triage
- APK paths, version/install/update metadata, installer package, UID, and optional SHA-256 evidence
- System-package protection using APK path / PackageManager flags with a conservative package-name fallback
- Accessibility, device-policy, overlay, notification-listener, and default-launcher indicators
- Correlation between active privileged components and the packages that declare sensitive capabilities
- Runtime process/service collection
- Telephony/call-forwarding audit framework with explicit verification status
- APK SHA-256 hashing and AAPT2 metadata inspection
- Optional YARA scanning with user-supplied rules
- Heuristic risk scoring with confidence and explicit heuristic labeling
- Hardening recommendations
- Timestamped JSON forensic evidence
- Human-readable Markdown and HTML reports
- Guarded package remediation with dry-run, evidence snapshot, explicit confirmation, and post-action verification
- Local tool capability detection

## Kali toolchain

DroidShield can integrate with tools installed on the host, including:

- Android platform-tools / ADB
- AAPT2
- apktool
- JADX
- YARA
- standard hashing and shell utilities

Missing tools are reported as unavailable; DroidShield does not fabricate results.

## Quick start

Install:

```bash
python3 -m pip install -e .
```

Check the environment:

```bash
droidshield capabilities
```

Connect an authorized Android device with USB debugging enabled:

```bash
droidshield devices
droidshield scan --output report.json --evidence-dir evidence/
```

For deeper APK evidence, including remote SHA-256 hashes for analyzed third-party APKs when the device supports hashing:

```bash
droidshield scan --hash-apks --output report.json --evidence-dir evidence/ --markdown report.md --html report.html
```

Inspect an APK without executing it:

```bash
droidshield apk sample.apk
```

Run an explicit YARA rule set:

```bash
droidshield yara sample.apk --rules rules/android.yar
```

## Guarded remediation

Remediation is **dry-run by default** and requires an evidence directory plus an explicit confirmation flag.

Preview and preserve evidence without changing the device:

```bash
droidshield remediate --package com.example.suspicious --action disable --evidence-dir evidence/
```

Actually disable the package:

```bash
droidshield remediate --package com.example.suspicious --action disable --evidence-dir evidence/ --confirm
```

For a user-installed package that should be removed from the primary user:

```bash
droidshield remediate --package com.example.suspicious --action uninstall --evidence-dir evidence/ --confirm
```

DroidShield refuses destructive actions for packages that appear to belong to protected Android system components. It also validates package names before building ADB commands, preserves a dumpsys package snapshot before changes, records the action result, and performs a post-action verification.

## Safety model

DroidShield separates collection, analysis, remediation, and verification. A sensitive permission is **not** proof of malware: accessibility, overlays, SMS, microphone, camera, and package-install capabilities can be legitimate. Risk scoring is therefore heuristic and should be reviewed alongside package provenance, active component state, APK evidence, and the observed device behavior.

Call forwarding is carrier/network dependent. DroidShield does not automatically place calls or trigger USSD/MMI actions. Reports include standard query codes and mark forwarding as **unverified** until a carrier/device-specific or manual verification supplies an authoritative result.

Run only against devices you own or are authorized to assess.

## Evidence and limitations

Regular scans prioritize third-party packages and a bounded sample of system packages for detailed metadata. Use --hash-apks when you want package APK hashes collected from the device where supported.

Some Android vendors expose different diagnostics through dumpsys, cmd, or settings. Collection errors are retained in the report instead of being treated as negative security results.

DroidShield does not pull private application data or execute APKs as part of the scan.

## Roadmap

1. Deep APK manifest/code analysis with AAPT2, apktool, and JADX
2. Curated defensive YARA rule packs and signature management
3. Stronger privilege-abuse correlation across Android component declarations
4. APK artifact acquisition for selected suspicious packages only
5. Post-remediation automatic rescan and before/after diffing
6. Vendor-specific telephony verification adapters
7. Rich incident timelines and evidence-chain hashing
8. Regression tests using controlled Android lab fixtures
