import pytest

from droidshield.remediation import (
    RemediationRefused,
    disable_package,
    snapshot_package,
    verify_disabled,
)


class FakeClient:
    def __init__(self, protected=False):
        self.protected = protected
        self.shell_calls = []

    def package_paths(self, serial, package):
        if self.protected:
            return ["/system/app/Foo/Foo.apk"]
        return [f"/data/app/{package}/base.apk"]

    def package_dump(self, serial, package):
        return "pkgFlags=[ HAS_CODE ]"

    def shell(self, command, serial=None):
        self.shell_calls.append(command)
        if command.startswith("pm disable-user"):
            return "Package " + command.rsplit(" ", 1)[-1] + " new state: disabled"
        if command == "pm list packages -d":
            return "package:com.example.bad\n"
        return ""


def test_destructive_action_requires_confirmation():
    client = FakeClient()
    with pytest.raises(RemediationRefused):
        disable_package(client, "serial", "com.example.bad", confirmed=False)
    assert client.shell_calls == []


def test_system_apk_is_refused():
    client = FakeClient(protected=True)
    with pytest.raises(RemediationRefused):
        disable_package(client, "serial", "com.example.bad", confirmed=True)


def test_disable_and_verify():
    client = FakeClient()
    result = disable_package(client, "serial", "com.example.bad", confirmed=True)
    assert result.success is True
    assert verify_disabled(client, "serial", "com.example.bad") is True


def test_snapshot_preserves_package_evidence(tmp_path):
    client = FakeClient()
    path = snapshot_package(client, "serial", "com.example.bad", tmp_path)
    assert path.exists()
    assert "com.example.bad" in path.read_text(encoding="utf-8")
