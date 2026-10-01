# DroidShield APT repository

DroidShield now has Debian packaging and a workflow for publishing an APT
repository.

The intended end-user command, after the repository has been configured, is:

    sudo apt update
    sudo apt install droidshield

For a local Debian package build:

    dpkg-buildpackage -us -uc -b

Then install the generated package with:

    sudo apt install ./droidshield_0.2.0-1_all.deb

The installed commands are:

    droidshield --help
    droidshield devices
    droidshield scan
    man droidshield

The APT repository workflow currently publishes package metadata to the
gh-pages branch. A production repository should use a signed Release file
and a dedicated repository signing key before being presented as a trusted
system-wide APT source.

DroidShield is defensive software for authorized Android assessment.
