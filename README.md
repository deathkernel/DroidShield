# DroidShield

DroidShield is a defensive Android security and incident-response toolkit designed to run on Kali Linux.

## Mission

Identify potentially malicious or abusive Android applications and configurations, preserve useful evidence, safely remediate supported findings, and verify the result.

DroidShield is not an attacker-hunting framework. Its primary focus is malware identification, device/app integrity, remediation, and hardening.

## Current capabilities

- ADB device discovery and authorized-device selection
- Device inventory and Android build/security-patch metadata
- Installed-package inventory with third-party package separation
- Package permission and component triage
- APK paths, version/install/update metadata, installer package, UID, and optional SHA-256 evidence
- Conservative system-package protection using APK path, PackageManager flags, and package-prefix fallback
- Accessibility, device-policy, overlay, notification-listener, and default-launcher indicators
- Active privileged component to package correlation
- Component graph of packages, services, receivers, providers, and active roles
- Install/update timeline reconstruction from PackageManager metadata
- Runtime process/service collection
- Filtered security-focused logcat evidence
- Socket/connectivity collection where exposed by the device
- Telephony/call-forwarding audit framework with explicit verification status
- APK SHA-256 hashing and AAPT2 metadata inspection
- APK signing certificate analysis with apksigner when installed
- Offline deep APK analysis with apktool and JADX when installed
- Optional YARA scanning with user-supplied rules
- Included defensive Android YARA triage rules
- Selected installed-package APK acquisition for offline analysis
- Heuristic risk scoring with confidence and explicit heuristic labeling
- Hardening recommendations
- Timestamped JSON forensic evidence
- Human-readable Markdown and HTML reports
- Guarded package remediation with dry-run, evidence snapshot, explicit confirmation, post-action verification, and before/after rescan diff
- Reversible user-package enable workflow after a controlled disable
- One-command incident-response case bundles with SHA-256 evidence manifests
- Regression tests for collection, analysis, correlation, remediation, acquisition, and case integrity
- Local Kali tool capability detection

## Kali toolchain

DroidShield can integrate with tools installed on the host, including:

- Android platform-tools / ADB
- AAPT2
- apksigner
- apktool
- JADX
- YARA
- standard hashing and shell utilities

Missing tools are reported as unavailable; DroidShield does not fabricate results.

## Installation

    python3 -m pip install -e ".[test]"

Check the environment:

    droidshield capabilities

## Device scan

Connect an authorized Android device with USB debugging enabled:

    droidshield devices
    droidshield scan --output report.json --evidence-dir evidence/

For deeper package evidence, including device-side SHA-256 hashes for analyzed third-party APKs when supported:

    droidshield scan --hash-apks --output report.json --evidence-dir evidence/ --markdown report.md --html report.html

## APK analysis

Inspect an APK without executing it:

    droidshield apk sample.apk

Run apktool/JADX offline static analysis:

    droidshield apk sample.apk --deep --work-dir evidence/sample-analysis

Run an explicit YARA ruleset:

    droidshield yara sample.apk --rules rules/android_triage.yar

APK analysis records the SHA-256 of the local artifact. When apksigner is installed, certificate digest information is also collected.

## Acquire an installed APK

For a selected package already installed on an authorized device:

    droidshield package-apk --package com.example.suspicious --evidence-dir evidence/apk-case

For deeper offline analysis:

    droidshield package-apk --package com.example.suspicious --evidence-dir evidence/apk-case --deep --rules rules/android_triage.yar

Only APK artifacts exposed by PackageManager are requested. Private application data is not pulled.

## Guarded remediation

Remediation is dry-run by default:

    droidshield remediate --package com.example.suspicious --action disable --evidence-dir evidence/

Actually disable the package:

    droidshield remediate --package com.example.suspicious --action disable --evidence-dir evidence/ --confirm

Remove a user-installed package from the primary user:

    droidshield remediate --package com.example.suspicious --action uninstall --evidence-dir evidence/ --confirm

Restore a package previously disabled by a controlled workflow:

    droidshield remediate --package com.example.suspicious --action restore --evidence-dir evidence/ --confirm

Before a confirmed destructive action, DroidShield records a package snapshot and a pre-remediation scan. After the action it verifies package state, performs a post-remediation scan, computes a before/after diff, and records the complete remediation result.

## Incident-response case bundle

Create a complete case directory from one scan:

    droidshield case --output case-001 --hash-apks --markdown --html

The case bundle includes report.json, optional report.md, optional report.html, and evidence-manifest.json with SHA-256 hashes for case artifacts.

## Safety model

A sensitive permission is not proof of malware. Accessibility, overlays, SMS, microphone, camera, and package-install capabilities can all be legitimate. Risk scoring is heuristic and should be reviewed alongside package provenance, active component state, APK evidence, and observed device behavior.

DroidShield does not execute APKs during analysis.

Call forwarding is carrier/network dependent. DroidShield does not automatically place calls or trigger USSD/MMI actions. Reports include standard query codes and mark forwarding as unverified until a carrier/device-specific or manual verification supplies an authoritative result.

Run only against devices you own or are authorized to assess.

## Evidence and limitations

Some Android vendors expose different diagnostics through dumpsys, cmd, settings, or PackageManager. Collection errors are retained in reports instead of being treated as negative security results.

Regular scans deeply analyze third-party packages plus a bounded sample of system packages. Use selected APK acquisition for deeper analysis of a specific package.

Runtime/network observations are snapshots, not continuous monitoring, and a lack of visible evidence does not prove that no malicious activity exists.

The included YARA rules are triage signatures, not malware verdicts.

## Roadmap

1. Stronger component export/intent-filter graphing
2. Signature/certificate comparison across app updates
3. More vendor-specific telephony adapters
4. Richer network endpoint and UID-to-process attribution
5. Android emulator/device integration fixtures in CI
6. Expanded defensive YARA regression corpus
7. Evidence timelines combining package, privilege, runtime, and remediation events
