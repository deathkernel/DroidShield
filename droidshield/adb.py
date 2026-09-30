from __future__ import annotations

import subprocess
from dataclasses import dataclass


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
                    result.append(path_and_pkg.rsplit("=", 1)[1].strip())
        return sorted(set(result))
