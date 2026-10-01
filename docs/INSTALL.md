# DroidShield installation

DroidShield installs as a normal command-line security tool. After installation, the command is available as `droidshield`.

## Kali Linux

Recommended installation uses pipx so DroidShield does not modify Kali's system Python environment.

    sudo apt update
    sudo apt install -y adb python3-pip pipx
    pipx install git+https://github.com/deathkernel/DroidShield.git

Verify:

    droidshield --version
    droidshield capabilities
    droidshield devices

Optional deep-analysis tools:

    sudo apt install -y apktool jadx yara

For AAPT2 and apksigner, install/configure an Android SDK. DroidShield automatically discovers supported SDK tool locations.

### From a checkout

    git clone https://github.com/deathkernel/DroidShield.git
    cd DroidShield
    pipx install .

### Debian/Kali package

The repository also contains Debian packaging. Build it with:

    dpkg-buildpackage -us -uc

Then install the generated package with apt. The installed command remains simply `droidshield`.

## Windows

Install Python 3.10+ and Android Platform-Tools, then:

    py -m pip install "git+https://github.com/deathkernel/DroidShield.git"

Verify:

    droidshield --version
    droidshield windows
    droidshield devices

Launch the Windows desktop interface with:

    droidshield gui

If the command is not on PATH, use:

    py -m droidshield --help

## Basic workflow

    droidshield devices
    droidshield capabilities
    droidshield scan --hash-apks --output report.json --evidence-dir evidence/

For an installed package:

    droidshield package-apk --package com.example.app --evidence-dir evidence/app --deep

For a forensic case:

    droidshield case --output case-001 --hash-apks --markdown --html

Remediation is dry-run by default. Review evidence before using `--confirm`.

## Scope

DroidShield is for authorized defensive Android assessment. Static analysis does not execute APKs, and heuristic signals are not a confirmed malware verdict.
