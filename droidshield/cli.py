from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .adb import AdbError, AdbClient
from .apk import ApkToolError, inspect_apk
from .scanner import scan_device
from .yara import scan_with_yara

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="droidshield",
        description="Defensive Android malware triage and remediation toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("devices", help="List connected Android devices.")

    scan = sub.add_parser("scan", help="Run a deep read-only security inventory.")
    scan.add_argument("--serial", help="ADB device serial.")
    scan.add_argument("--output", type=Path, help="Write the full JSON report.")

    apk = sub.add_parser("apk", help="Inspect an APK without executing it.")
    apk.add_argument("path", type=Path)
    apk.add_argument("--output", type=Path)

    yara = sub.add_parser("yara", help="Scan a file/APK with an explicit YARA rule file.")
    yara.add_argument("path", type=Path)
    yara.add_argument("--rules", type=Path, required=True)
    yara.add_argument("--output", type=Path)

    return parser


def cmd_devices(client: AdbClient) -> int:
    devices = client.devices()
    table = Table(title="DroidShield - Connected Devices")
    table.add_column("Serial")
    table.add_column("State")
    for serial, state in devices:
        table.add_row(serial, state)
    if not devices:
        console.print("[yellow]No ADB devices detected.[/yellow]")
    else:
        console.print(table)
    return 0


def cmd_scan(client: AdbClient, serial: str | None, output: Path | None) -> int:
    report = scan_device(client, serial)
    console.print(f"[bold]Device:[/bold] {report['device']['serial']}")
    console.print(f"[bold]Packages:[/bold] {len(report['packages'])}")
    console.print(f"[bold]Risk:[/bold] {report['risk']['level']} ({report['risk']['score']}/100)")
    console.print(f"[bold]Findings:[/bold] {len(report['findings'])}")

    for finding in report["findings"]:
        style = "red" if finding["severity"] == "HIGH" else "yellow"
        console.print(f"[{style}]{finding['severity']}: {finding['title']}[/]")

    if output:
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"[green]Evidence report written to {output}[/green]")
    return 0


def write_json(data: dict, output: Path | None) -> None:
    if output:
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print_json(json.dumps(data))


def main() -> int:
    args = build_parser().parse_args()
    client = AdbClient()
    try:
        if args.command == "devices":
            return cmd_devices(client)
        if args.command == "scan":
            return cmd_scan(client, args.serial, args.output)
        if args.command == "apk":
            write_json(inspect_apk(args.path), args.output)
            return 0
        if args.command == "yara":
            write_json(scan_with_yara(args.path, args.rules), args.output)
            return 0
    except (AdbError, ApkToolError) as exc:
        console.print(f"[red]DroidShield error:[/red] {exc}")
        return 2
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130
    return 1


if __name__ == "__main__":
    sys.exit(main())
