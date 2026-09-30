# DroidShield

DroidShield is a defensive Android security and incident-response toolkit designed to run on Kali Linux.

## Mission

Identify potentially malicious or abusive Android applications and configurations, preserve useful evidence, safely remediate supported findings, and verify the result.

DroidShield is **not** an attacker-hunting framework. Its primary focus is malware identification, device/app integrity, remediation, and hardening.

## Current MVP

- ADB device discovery
- Device inventory
- Installed-package inventory
- Risk scoring based on observable package metadata
- Evidence collection
- JSON report generation
- Safe read-only diagnostics

## Planned modules

- APK static analysis (AAPT2/apktool/JADX)
- YARA scanning
- Accessibility / Device Admin / overlay analysis
- Launcher/UI hijack detection
- Telephony and call-forwarding audit
- Network/VPN/proxy checks
- Runtime indicators
- Quarantine/remediation workflows
- Post-remediation verification
- HTML/Markdown reports

## Safety model

DroidShield separates **collection**, **analysis**, **remediation**, and **verification**. It should never blindly remove system packages or modify a device based on a single weak indicator.

Run only against devices you own or are authorized to assess.

## Quick start

```bash
python3 -m pip install -e .
droidshield devices
droidshield scan
droidshield scan --output report.json
```
