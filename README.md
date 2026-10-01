# DroidShield

DroidShield is a defensive Android security and incident-response toolkit designed for Kali Linux and Windows hosts.

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
- Safe APK archive inspection for DEX, native ELF libraries, assets, resources, and archive-path indicators
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

## Windows edition\n\nDroidShield also supports a Windows-native host workflow. See [docs/WINDOWS.md](docs/WINDOWS.md). After installing Android Platform-Tools and connecting an authorized device, run:\n\n    droidshield windows\n\nFor the desktop interface on Windows:\n\n    droidshield gui\n\nThe Windows layer uses safe, non-shell subprocess execution and reuses the existing ADB, APK, YARA, evidence, reporting, and guarded-remediation engines. MTP/file-transfer mode is separate from ADB debugging.\n\n## Kali toolchain

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

    droidshield case --output case-001 --hash-apks --markdown --html --note "Review installer provenance"

Verify that case evidence has not changed after collection or review:

    droidshield case-verify case-001

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

The following roadmap captures the planned expansion of DroidShield across detection, explainability, forensics, device hardening, Windows UX, and advanced analysis.

### Phase A — Advanced Detection Engine

- [ ] Explainable multi-signal malware detection engine
- [x] APK signing-key and certificate verification
- [x] Certificate comparison across app updates
- [ ] APK hash/reputation integration points
- [x] Suspicious Android API and behavior indicators
- [x] Embedded URL, domain, and IP extraction
- [x] WebView abuse indicators
- [x] Dynamic code-loading indicators
- [x] Reflection-heavy code indicators
- [x] Native library analysis
- [ ] Expanded DEX/static analysis
- [ ] Permission + behavior correlation
- [x] Stronger component export and intent-filter graphing
- [ ] Expanded defensive YARA regression corpus

### Phase B — Explainable Risk & Findings

- [ ] Separate overall heuristic risk from individual finding severity
- [ ] Why-is-this-risky evidence breakdown
- [x] Per-signal score contribution and provenance
- [ ] Evidence-quality explanation
- [ ] Confidence explanation
- [ ] Clear confirmed-malware versus not-established distinction
- [ ] Finding correlation graph
- [ ] Risk changes between scans
- [ ] Package-level investigation states without treating heuristics as proof

### Phase C — Per-App Investigation Center

- [x] Dedicated package investigation workspace
- [ ] Overview, permissions, and granted-permission analysis
- [ ] Services, receivers, providers, and activities
- [ ] Active roles and privileged components
- [ ] APK artifacts and split inventory
- [ ] APK SHA-256 hashes
- [ ] Signing certificates
- [ ] DEX indicators
- [ ] Native libraries
- [ ] URLs, domains, and IP indicators
- [ ] YARA results
- [x] Package timeline
- [ ] Evidence file browser

### Phase D — Device Security Posture

- [ ] Device security posture dashboard
- [ ] USB/ADB debugging state
- [ ] Unknown-source/install configuration indicators
- [ ] Accessibility service inventory
- [ ] Device-admin inventory
- [ ] Overlay inventory
- [ ] Notification-listener inventory
- [ ] VPN inventory
- [ ] Default launcher analysis
- [ ] Security-patch and build posture
- [ ] Hardening recommendations with evidence
- [ ] Vendor-specific security checks

### Phase E — Permission Intelligence

- [ ] Full permission matrix across installed applications
- [ ] Filters for SMS, camera, microphone, overlay, accessibility, notification, install, and other sensitive capabilities
- [ ] Granted-vs-declared permission comparison
- [ ] Permission change tracking between scans
- [ ] Suspicious permission-combination explanations
- [ ] App role + permission correlation
- [ ] Permission review workflow

### Phase F — Forensics & Case Management

- [x] Full forensic case workspace
- [x] Evidence collection manifest
- [x] Evidence SHA-256 integrity tracking
- [x] Scan history
- [ ] Package timeline
- [ ] Privilege/component timeline
- [ ] Runtime event timeline
- [ ] Remediation timeline
- [ ] Before/after scan comparison
- [ ] Before/after package and permission diff
- [x] Case notes and analyst annotations
- [x] Exportable case bundle
- [ ] Professional forensic HTML report

### Phase G — Windows Security Console

- [ ] Polished Windows desktop dashboard
- [ ] Device selector and connection state
- [ ] Deep-scan progress and status
- [ ] Overview, Findings, Packages, Evidence, and History views
- [x] Investigation center integrated into the desktop UI
- [ ] Permission matrix UI
- [ ] Timeline UI
- [ ] Before/after comparison UI
- [ ] Structured security-posture cards
- [ ] Why-is-this-risky UI
- [ ] One-click evidence/report export
- [ ] Improved accessibility and keyboard navigation
- [ ] Packaged Windows executable workflow

### Phase H — Network & Runtime Intelligence

- [ ] Richer network endpoint collection
- [x] UID-to-process attribution
- [x] Process-to-package attribution
- [x] Socket-to-package attribution
- [ ] Runtime service attribution
- [ ] Security-focused event correlation
- [ ] Optional live device event monitoring
- [ ] Package install/update event detection
- [ ] Permission-state change detection
- [ ] Privileged-service state change detection

### Phase I — Advanced APK & Dynamic Analysis

- [x] Deeper DEX inspection
- [x] Native ELF and shared-library inspection
- [x] Manifest/component anomaly detection
- [x] Embedded resource and payload inspection
- [ ] More advanced YARA integration
- [ ] Isolated APK dynamic-analysis workflow
- [ ] Process/file/network behavior observation in an isolated environment
- [ ] Dynamic-analysis evidence capture
- [ ] Static-vs-dynamic evidence correlation

Dynamic analysis must remain isolated from the host and must never turn DroidShield into an offensive execution framework.

### Phase J — Remediation & Recovery

- [x] Evidence-first remediation wizard
- [ ] Safer disable workflow
- [ ] Controlled uninstall workflow
- [ ] Restore workflow
- [x] Permission-change tracking around remediation
- [x] Post-remediation verification
- [x] Automated before/after evidence package
- [ ] Recovery guidance for supported device states
- [ ] Stronger protection against accidental system-package modification

### Phase K — Testing, CI & Reliability

- [ ] Expanded Android device fixtures
- [ ] Emulator/device integration tests in CI
- [ ] Vendor-specific fixture coverage
- [ ] Regression corpus for APK analysis
- [ ] Regression corpus for YARA
- [x] Windows GUI regression tests
- [x] Remediation safety tests
- [x] Evidence-integrity tests
- [x] Performance tests for large package inventories
- [ ] Failure/partial-collection test coverage
## APK before/after comparison

Compare two preserved APK artifacts to identify hash changes, size deltas, and signer-certificate changes when apksigner is available:

    droidshield apk-diff before.apk after.apk --output apk-diff.json

A changed APK hash is expected after an application update. A signer change is a separate provenance signal that should be reviewed in context.
\n\n## Cross-platform safety\n\nWindows support does not change the defensive scope: scanning and analysis are read-only by default, APKs are not executed, and package remediation requires explicit confirmation. Use DroidShield only on devices you own or are authorized to assess.\n

## Deep scan and safe malware removal

DroidShield is designed to investigate Android devices using a read-only deep scan first. A high heuristic risk score or a sensitive permission is **not by itself proof of malware**. Review the finding evidence, package provenance, APK evidence, and device state before remediation.

### 1. Check the connected device

On Windows:

    .venv\Scripts\activate.bat
    droidshield devices

Confirm that the intended device is shown as `device` before scanning.

### 2. Run a deep scan

Run a normal deep security inventory:

    droidshield scan --serial YOUR_DEVICE_SERIAL --output deep-scan.json --markdown deep-scan.md

For additional third-party APK SHA-256 evidence:

    droidshield scan --serial YOUR_DEVICE_SERIAL --hash-apks --output deep-scan.json --markdown deep-scan.md

Example:

    droidshield scan --serial 12f565ccdead --hash-apks --output deep-scan.json --markdown deep-scan.md

The scan collects package metadata, permissions, granted permissions, sensitive component state, runtime observations, network observations, timelines, and heuristic risk signals. APK hashing does not execute APKs.

### 3. Investigate a suspicious package

First acquire the installed APK artifacts for offline analysis:

    droidshield package-apk --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --evidence-dir evidence/apk-case

If the local analysis tools are installed, run deeper static analysis:

    droidshield package-apk --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --evidence-dir evidence/apk-case --deep --output apk-investigation.json

Optional YARA rules can also be supplied:

    droidshield package-apk --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --evidence-dir evidence/apk-case --deep --rules rules/android_triage.yar --output apk-investigation.json

DroidShield does not execute the acquired APK. Missing static-analysis tools are reported as unavailable rather than treated as clean evidence.

### 4. Safely remove or disable a confirmed malicious user package

**Do not start with uninstall.** First run the remediation command without `--confirm`:

    droidshield remediate --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --action disable --evidence-dir evidence/remediation

This is a dry run. It captures package evidence and shows the DroidShield assessment without changing the device.

If the evidence supports disabling the package, explicitly confirm:

    droidshield remediate --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --action disable --evidence-dir evidence/remediation --confirm

DroidShield then records a pre-remediation scan, performs the guarded action, verifies the package state, runs a post-remediation scan, and records a before/after result when possible.

### 5. Uninstall a confirmed malicious user package

For a user-installed package that has been investigated and confirmed as malicious:

    droidshield remediate --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --action uninstall --evidence-dir evidence/remediation --confirm

Protected/system packages are blocked by DroidShield's remediation safeguards.

### 6. Restore a package disabled by DroidShield

If a package was disabled by the controlled workflow and needs to be restored:

    droidshield remediate --serial YOUR_DEVICE_SERIAL --package PACKAGE_NAME --action restore --evidence-dir evidence/remediation --confirm

### Important safety notes

- A heuristic `HIGH` score is not a confirmed malware verdict.
- Sensitive permissions such as SMS, camera, microphone, overlay, or accessibility can be legitimate.
- Preserve evidence before changing a suspicious device.
- Do not uninstall a package solely because it appears in a heuristic finding.
- Only assess and remediate devices you own or are authorized to assess.

### Bulk implementation status

The current `android-ui` branch includes the first integrated investigation stack: evidence integrity, explainability, security posture, permission intelligence, component metadata, runtime/network attribution, normalized APK signing provenance, forensic case metadata/analyst notes, and a Windows package investigation workspace. These features remain evidence-producing triage capabilities; heuristic risk is not a malware verdict.

Forensic case notes can be attached from the CLI with repeated `--note` options:

    droidshield case --output case-001 --note "Capture installer provenance" --note "Review active privileged roles"

The case directory records `case.json`, `notes.jsonl`, `report.json`, optional human-readable reports, and the evidence manifest.
