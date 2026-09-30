# DroidShield

DroidShield is a defensive Android security and incident-response toolkit designed to run on Kali Linux.

## Mission

Identify potentially malicious or abusive Android applications and configurations, preserve useful evidence, safely remediate supported findings, and verify the result.

DroidShield is **not** an attacker-hunting framework. Its primary focus is malware identification, device/app integrity, remediation, and hardening.

## Current capabilities

- ADB device discovery
- Device inventory and Android build/security-patch metadata
- Installed-package inventory
- Package permission/component triage
- Accessibility, device-policy, overlay and notification-listener indicators
- Default launcher inspection
- Runtime process/service collection
- Telephony/call-forwarding audit framework with explicit verification status
- APK SHA-256 hashing and AAPT2 metadata inspection
- Optional YARA scanning
- Correlated risk scoring
- Hardening recommendations
- Timestamped JSON forensic evidence
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

Inspect an APK without executing it:

```bash
droidshield apk sample.apk
```

Run an explicit YARA rule set:

```bash
droidshield yara sample.apk --rules rules/android.yar
```

## Safety model

DroidShield separates collection, analysis, remediation, and verification. It should never blindly remove system packages or modify a device based on a single weak indicator.

Call forwarding is carrier/network dependent. A failed or unsupported query is reported as **unverified**, not as proof that forwarding is disabled.

Run only against devices you own or are authorized to assess.

## Roadmap

1. Deep APK manifest/code analysis
2. Curated YARA rule packs and signature management
3. Stronger Android privilege-abuse correlation
4. Controlled quarantine/remediation with explicit confirmation
5. Post-remediation verification
6. HTML/Markdown incident reports
7. Device/vendor-specific telephony verification adapters
8. Regression tests using controlled Android lab fixtures
