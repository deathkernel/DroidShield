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
- Runtime process/service collection with vendor-command failure recording
- Telephony/call-forwarding audit framework with explicit verification status
- APK SHA-256 hashing and AAPT2 metadata inspection
- Offline deep APK analysis with apktool and JADX when installed
- Optional YARA scanning with user-supplied rules
- Selected installed-package APK acquisition for offline analysis
- Heuristic risk scoring with confidence and explicit heuristic labeling
- Hardening recommendations
- Timestamped JSON forensic evidence
- Human-readable Markdown and HTML reports
- Guarded package remediation with dry-run, evidence snapshot, explicit confirmation, post-action verification, and before/after rescan diff
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
python3 -m pip install -e ".[test]"
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

For deeper package evidence, including remote SHA-256 hashes for analyzed third-party APKs when the device supports hashing:

```bash
droidshield scan --hash-apks --output report.json --evidence-dir evidence/ --markdown report.md --html report.html
```

Inspect an APK without executing it:

```bash
droidshield apk sample.apk
```

Run offline static analysis with apktool and JADX:

```bash
droidshield apk sample.apk --deep --work-dir evidence/sample-analysis
```

Run an explicit YARA rule set:

```bash
droidshield yara sample.apk --rules rules/android.yar
```

## Acquire an installed APK for analysis

For a package already installed on an authorized device, DroidShield can pull only the APK artifacts exposed by PackageManager. It does not pull private application data.

```bash
droidshield package-apk --package com.example.suspicious --evidence-dir evidence/apk-case
```

For deeper offline analysis of every successfully pulled APK:

```bash
droidshield package-apk --package com.example.suspicious --evidence-dir evidence/apk-case --deep
```

Add a defensive YARA ruleset to the same analysis:

```bash
droidshield package-apk --package com.example.suspicious --evidence-dir evidence/apk-case --deep --rules rules/android.yar
```

Acquisition records retain remote APK paths, local artifact paths, SHA-256 hashes, sizes, and pull failures.

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

DroidShield refuses destructive actions for packages that appear to belong to protected Android system components. It validates package names before building ADB commands, preserves a dumpsys package snapshot before changes, records the action result, and performs a post-action verification.

## Before/after remediation evidence

After a confirmed remediation action, DroidShield captures a pre-remediation scan, runs the requested change, verifies the package state, captures a post-remediation scan, and records a structured diff of package changes, active security components, findings, and heuristic risk score.

## Safety model

DroidShield separates collection, analysis, remediation, and verification. A sensitive permission is **not** proof of malware: accessibility, overlays, SMS, microphone, camera, and package-install capabilities can be legitimate. Risk scoring is therefore heuristic and should be reviewed alongside package provenance, active component state, APK evidence, and the observed device behavior.

Call forwarding is carrier/network dependent. DroidShield does not automatically place calls or trigger USSD/MMI actions. Reports include standard query codes and mark forwarding as **unverified** until a carrier/device-specific or manual verification supplies an authoritative result.

Run only against devices you own or are authorized to assess.

## Evidence and limitations

Regular scans prioritize third-party packages and a bounded sample of system packages for detailed metadata. Use --hash-apks when you want package APK hashes collected from the device where supported.

Deep APK analysis runs locally against acquired APK artifacts. apktool/JADX failures, timeouts, unsupported vendor diagnostics, and other collection errors are recorded instead of being treated as evidence of a clean device.

DroidShield does not execute APKs and does not pull private application data as part of the package acquisition workflow.

## Roadmap

1. Rich manifest/component graphing across APK and device state
2. Curated defensive YARA rule packs and signature management
3. Stronger privilege-abuse correlation across Android component declarations
4. Selected artifact diffing across app updates/reinstalls
5. Post-remediation automatic rescan and before/after comparison
6. Vendor-specific telephony verification adapters
7. Evidence-chain hashing and incident timelines
8. Controlled Android emulator/device integration tests
