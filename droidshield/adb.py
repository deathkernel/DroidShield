from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+$")


class AdbError(RuntimeError):
    pass


@dataclass
class AdbClient:
    adb_path: str = "adb"

    def run(self, *args: str, serial: str | None = None) -> str:
        command = [self.adb_path]
        if serial:
            command += ["-s", serial]
        command += list(args)
        try:
            proc = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise AdbError("adb was not found. Install Android platform-tools.") from exc

        if proc.returncode != 0:
            raise AdbError(proc.stderr.strip() or "adb command failed")
        return proc.stdout

    def devices(self) -> list[tuple[str, str]]:
        output = self.run("devices")
        rows = []
        for line in output.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                rows.append((parts[0], parts[1]))
        return rows

    def resolve_serial(self, requested: str | None) -> str:
        devices = self.devices()
        if requested:
            states = {serial: state for serial, state in devices}
            if requested not in states:
                raise AdbError(f"Device {requested!r} is not connected.")
            if states[requested] != "device":
                raise AdbError(f"Device {requested!r} is not ready: {states[requested]}")
            return requested

        ready = [serial for serial, state in devices if state == "device"]
        if not ready:
            raise AdbError("No authorized/ready ADB device found.")
        if len(ready) > 1:
            raise AdbError("Multiple devices found; use --serial.")
        return ready[0]

    def shell(self, command: str, serial: str | None = None) -> str:
        return self.run("shell", command, serial=serial)

    def properties(self, serial: str) -> dict[str, str]:
        output = self.shell("getprop", serial=serial)
        props = {}
        for line in output.splitlines():
            if "]: [" not in line:
                continue
            key, value = line.split("]: [", 1)
            props[key.lstrip("[").strip()] = value.rstrip("]").strip()
        return props

    def packages(self, serial: str) -> list[str]:
        output = self.shell("pm list packages -f", serial=serial)
        result = []
        for line in output.splitlines():
            if line.startswith("package:"):
                path_and_pkg = line[len("package:"):]
                if "=" in path_and_pkg:
                    package = path_and_pkg.rsplit("=", 1)[1].strip()
                    if PACKAGE_RE.fullmatch(package):
                        result.append(package)
        return sorted(set(result))

    def third_party_packages(self, serial: str) -> list[str]:
        output = self.shell("pm list packages -3", serial=serial)
        result = []
        for line in output.splitlines():
            if line.startswith("package:"):
                package = line[len("package:"):].strip()
                if PACKAGE_RE.fullmatch(package):
                    result.append(package)
        return sorted(set(result))

    def package_paths(self, serial: str, package: str) -> list[str]:
        if not PACKAGE_RE.fullmatch(package):
            raise AdbError(f"Invalid Android package name: {package!r}")
        output = self.shell(f"pm path {package}", serial=serial)
        paths = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                path = line[len("package:"):].strip()
                if path:
                    paths.append(path)
        return sorted(set(paths))

    def package_sha256(self, serial: str, package: str) -> dict[str, str]:
        hashes = {}
        for apk_path in self.package_paths(serial, package):
            try:
                output = self.shell(
                    f"sha256sum '{apk_path}'",
                    serial=serial,
                ).strip()
            except AdbError:
                continue
            parts = output.split()
            if parts and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
                hashes[apk_path] = parts[0].lower()
        return hashes

    def package_dump(self, serial: str, package: str) -> str:
        if not PACKAGE_RE.fullmatch(package):
            raise AdbError(f"Invalid Android package name: {package!r}")
        return self.shell(f"dumpsys package {package}", serial=serial)
