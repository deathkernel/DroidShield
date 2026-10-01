from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .adb import AdbError, AdbClient
from .case import build_case_bundle, verify_case_bundle
from .apk import (
    ApkToolError,
    acquire_package_apks,
    compare_apks,
    inspect_apk,
)
from .classifier import classify_package
from .collectors import collect_package_metadata
from .diff import compare_reports
from .forensics import save_evidence
from .evidence import write_manifest, verify_manifest
from .remediation import (
    RemediationRefused,
    disable_package,
    snapshot_package,
    uninstall_package,
    verify_absent,
    verify_disabled,
    enable_package,
    verify_enabled,
)
from .report import html_report, markdown_report
from .scanner import scan_device
from .tooling import capabilities
from .yara import scan_with_yara
from .windows import windows_environment_report, list_adb_devices
from .mobile_api import serve_mobile

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="droidshield",
        description="Defensive Android malware triage and remediation toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("devices", help="List connected Android devices.")
    sub.add_parser("capabilities", help="Show available local analysis tools.")
    sub.add_parser("windows", help="Show Windows host and Android tooling status.")
    sub.add_parser("gui", help="Launch the Windows desktop interface.")

    mobile = sub.add_parser("mobile-server", help="Expose the scanner to the DroidShield Android companion.")
    mobile.add_argument("--host", default="0.0.0.0")
    mobile.add_argument("--port", type=int, default=8765)
    mobile.add_argument("--token", required=True, help="Bearer token required by Android clients.")

    scan = sub.add_parser("scan", help="Run a deep read-only security inventory.")
    scan.add_argument("--serial", help="ADB device serial.")
    scan.add_argument("--output", type=Path, help="Write the full JSON report.")
    scan.add_argument("--evidence-dir", type=Path, help="Also save timestamped evidence.")
    scan.add_argument("--markdown", type=Path, help="Write a Markdown report.")
    scan.add_argument("--html", type=Path, help="Write an HTML report.")
    scan.add_argument(
        "--hash-apks",
        action="store_true",
        help="Hash analyzed third-party APKs from the device when supported.",
    )

    remediate = sub.add_parser(
        "remediate",
        help="Safely disable or uninstall one package after evidence capture.",
    )
    remediate.add_argument("--serial", help="ADB device serial.")
    remediate.add_argument("--package", required=True, help="Android package name.")
    remediate.add_argument(
        "--action",
        choices=("disable", "uninstall", "restore"),
        default="disable",
    )
    remediate.add_argument(
        "--evidence-dir",
        type=Path,
        required=True,
        help="Directory where the before/after remediation record is stored.",
    )
    remediate.add_argument(
        "--confirm",
        action="store_true",
        help="Actually perform the requested action. Without this, the command is dry-run only.",
    )

    package_apk = sub.add_parser(
        "package-apk",
        help="Acquire selected package APKs from a device for offline analysis.",
    )
    package_apk.add_argument("--serial", help="ADB device serial.")
    package_apk.add_argument("--package", required=True, help="Android package name.")
    package_apk.add_argument(
        "--evidence-dir",
        type=Path,
        required=True,
        help="Directory for pulled APKs and analysis evidence.",
    )
    package_apk.add_argument(
        "--deep",
        action="store_true",
        help="Run apktool and JADX static analysis when installed.",
    )
    package_apk.add_argument(
        "--rules",
        type=Path,
        help="Optional YARA rule file for the pulled APKs.",
    )
    package_apk.add_argument("--output", type=Path, help="Write the JSON acquisition/analysis report.")

    apk_diff = sub.add_parser(
        "apk-diff",
        help="Compare two APK artifacts without executing either one.",
    )
    apk_diff.add_argument("before", type=Path)
    apk_diff.add_argument("after", type=Path)
    apk_diff.add_argument("--output", type=Path)

    apk = sub.add_parser("apk", help="Inspect an APK without executing it.")
    apk.add_argument("path", type=Path)
    apk.add_argument("--output", type=Path)
    apk.add_argument(
        "--deep",
        action="store_true",
        help="Run apktool and JADX static analysis when installed.",
    )
    apk.add_argument(
        "--work-dir",
        type=Path,
        help="Working directory for decoded/decompiled analysis.",
    )
    apk.add_argument(
        "--rules",
        type=Path,
        help="Optional YARA rule file.",
    )

    case = sub.add_parser(
        "case",
        help="Create a complete incident-response case bundle from a device scan.",
    )
    case.add_argument("--serial", help="ADB device serial.")
    case.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Case directory for report, evidence manifest, and supporting artifacts.",
    )
    case.add_argument("--hash-apks", action="store_true")
    case.add_argument("--markdown", action="store_true")
    case.add_argument("--html", action="store_true")
    case.add_argument("--note", action="append", default=[], help="Add an analyst note to the case bundle.")

    case_verify = sub.add_parser("case-verify", help="Verify forensic case evidence integrity.")
    case_verify.add_argument("path", type=Path, help="Case directory containing evidence-manifest.json.")

    yara = sub.add_parser("yara", help="Scan a file/APK with an explicit YARA rule file.")
    yara.add_argument("path", type=Path)
    yara.add_argument("--rules", type=Path, required=True)
    yara.add_argument("--output", type=Path)

    return parser


def cmd_windows() -> int:
    report = windows_environment_report()
    table = Table(title="DroidShield - Windows Environment")
    table.add_column("Component")
    table.add_column("Status / Value")
    table.add_row("Platform", report["platform"])
    table.add_row("Python", report["python"])
    table.add_row("Architecture", report["architecture"])
    table.add_row("ADB", report["adb"] or "NOT FOUND")
    for name, available in report["tools"].items():
        table.add_row(name, "YES" if available else "NO")
    console.print(table)
    try:
        devices = list_adb_devices()
        console.print(f"[bold]ADB devices:[/bold] {len(devices)}")
        for serial, state in devices:
            console.print(f"  {serial}: {state}")
    except RuntimeError as exc:
        console.print(f"[yellow]ADB status:[/yellow] {exc}")
    return 0


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


def cmd_capabilities() -> int:
    table = Table(title="DroidShield - Analysis Capabilities")
    table.add_column("Tool")
    table.add_column("Available")
    for name, available in capabilities().items():
        table.add_row(name, "YES" if available else "NO")
    console.print(table)
    return 0


def cmd_scan(
    client: AdbClient,
    serial: str | None,
    output: Path | None,
    evidence_dir: Path | None,
    markdown: Path | None,
    html: Path | None,
    hash_apks: bool,
) -> int:
    report = scan_device(client, serial, hash_apks=hash_apks)
    console.print(f"[bold]Device:[/bold] {report['device']['serial']}")
    console.print(f"[bold]Packages:[/bold] {len(report['packages'])}")
    console.print(
        f"[bold]Analyzed:[/bold] {report['metadata_coverage']['packages_analyzed']}"
    )
    console.print(
        f"[bold]Risk:[/bold] {report['risk']['level']} "
        f"({report['risk']['score']}/100; {report['risk']['confidence']} confidence)"
    )
    console.print(f"[bold]Findings:[/bold] {len(report['findings'])}")

    for finding in report["findings"]:
        style = "red" if finding["severity"] == "HIGH" else "yellow"
        package = f" [{finding['package']}]" if finding.get("package") else ""
        console.print(
            f"[{style}]{finding['severity']}: {finding['title']}{package}[/]"
        )

    if report["hardening"]:
        console.print("\n[bold]Hardening recommendations[/bold]")
        for item in report["hardening"]:
            console.print(f"  • {item}")

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    if evidence_dir:
        path = save_evidence(report, evidence_dir)
        console.print(f"[green]Evidence saved to {path}[/green]")
    if markdown:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(markdown_report(report), encoding="utf-8")
        console.print(f"[green]Markdown report written to {markdown}[/green]")
    if html:
        html.parent.mkdir(parents=True, exist_ok=True)
        html.write_text(html_report(report), encoding="utf-8")
        console.print(f"[green]HTML report written to {html}[/green]")
    return 0


def cmd_case(client: AdbClient, serial: str | None, output: Path, hash_apks: bool, markdown: bool, html: bool, notes: list[str] | None = None) -> int:
    output.mkdir(parents=True, exist_ok=True)
    report = scan_device(client, serial, hash_apks=hash_apks)
    md = markdown_report(report) if markdown else None
    html_text = html_report(report) if html else None
    manifest = build_case_bundle(output, report, md, html_text, notes=notes or [])
    console.print(f"[green]Case bundle created:[/green] {output}")
    console.print(f"[green]Artifacts:[/green] {len(manifest['artifacts'])}")
    return 0


def cmd_remediate(
    client: AdbClient,
    serial: str | None,
    package: str,
    action: str,
    evidence_dir: Path,
    confirm: bool,
) -> int:
    resolved = client.resolve_serial(serial)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    metadata = collect_package_metadata(
        client, resolved, package, hash_apk=False
    )
    assessment = classify_package(package, metadata)
    console.print(f"[bold]Package:[/bold] {package}")
    console.print(f"[bold]Assessment:[/bold] {assessment['level']} ({assessment['score']})")
    console.print(f"[bold]Signals:[/bold] {', '.join(assessment['signals']) or 'none'}")
    console.print(f"[bold]Remediation allowed:[/bold] {assessment['remediation_allowed']}")

    snapshot = snapshot_package(client, resolved, package, evidence_dir)
    console.print(f"[green]Before-action evidence:[/green] {snapshot}")

    if not confirm:
        console.print(
            "[yellow]DRY RUN: no device change made. Re-run with --confirm to perform the action.[/yellow]"
        )
        return 0

    if not assessment["remediation_allowed"]:
        raise RemediationRefused(
            "The package is protected by Android system evidence and cannot be remediated by DroidShield."
        )

    pre_scan = scan_device(client, resolved, hash_apks=False)
    pre_scan_path = save_evidence(pre_scan, evidence_dir / "pre-remediation")
    console.print(f"[green]Pre-remediation scan:[/green] {pre_scan_path}")

    if action == "restore":
        result = enable_package(client, resolved, package, confirmed=True)
    elif action == "disable":
        result = disable_package(client, resolved, package, confirmed=True)
    else:
        result = uninstall_package(client, resolved, package, confirmed=True)
    verified = (
        verify_enabled(client, resolved, package)
        if action == "restore"
        else verify_disabled(client, resolved, package)
        if action == "disable"
        else verify_absent(client, resolved, package)
    )

    post_scan = None
    post_scan_path = None
    diff = None
    post_scan_error = None
    try:
        post_scan = scan_device(client, resolved, hash_apks=False)
        post_scan_path = save_evidence(post_scan, evidence_dir / "post-remediation")
        diff = compare_reports(pre_scan, post_scan)
        console.print(
            f"[bold]Risk delta:[/bold] {diff['risk']['score_delta']:+d}"
        )
    except Exception as exc:
        post_scan_error = str(exc)
        console.print(
            f"[yellow]Post-remediation rescan unavailable: {post_scan_error}[/yellow]"
        )

    record = {
        "schema_version": "1.1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "serial": resolved,
        "package": package,
        "action": action,
        "before_snapshot": str(snapshot),
        "pre_scan": str(pre_scan_path),
        "post_scan": str(post_scan_path) if post_scan_path else None,
        "assessment": assessment,
        "result": {
            "success": result.success,
            "output": result.output,
        },
        "verified": verified,
        "post_scan_error": post_scan_error,
        "diff": diff,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    record_path = evidence_dir / f"{package.replace('.', '_')}-remediation-{stamp}.json"
    record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    manifest = write_manifest(evidence_dir)
    record["evidence_manifest"] = str(evidence_dir / "evidence-manifest.json")
    record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    if result.success and verified and post_scan_error is None:
        console.print(f"[green]Remediation completed and verified: {action}[/green]")
        console.print(f"[green]Record: {record_path}[/green]")
        return 0

    console.print(
        f"[red]Remediation requires review: action_success={result.success}, "
        f"verified={verified}, post_scan_ok={post_scan_error is None}[/red]"
    )
    console.print(f"[red]Record: {record_path}[/red]")
    return 3


def cmd_package_apk(
    client: AdbClient,
    serial: str | None,
    package: str,
    evidence_dir: Path,
    deep: bool,
    rules: Path | None,
    output: Path | None,
) -> int:
    resolved = client.resolve_serial(serial)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    acquisition = acquire_package_apks(
        client,
        resolved,
        package,
        evidence_dir,
    )

    analyses = []
    for artifact in acquisition["artifacts"]:
        if artifact.get("status") != "pulled":
            continue
        apk_path = Path(artifact["local_path"])
        work_dir = apk_path.parent / (apk_path.stem + "-analysis")
        analysis = inspect_apk(
            apk_path,
            deep=deep,
            work_dir=work_dir,
            yara_rules=rules,
        )
        analyses.append(analysis)

    signer_sets = [
        tuple(
            tuple(item.get("signing", {}).get("identity", {}).get("sha256", []))
        )
        for item in analyses
        if item.get("signing")
    ]
    signing_consistent = len(set(signer_sets)) <= 1 if signer_sets else None

    signing_identities = [
        item.get("signing", {}).get("identity")
        for item in analyses
        if item.get("signing", {}).get("identity")
    ]
    report = {
        "schema_version": "1.2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "serial": resolved,
        "package": package,
        "acquisition": acquisition,
        "analyses": analyses,
        "signing_consistency": signing_consistent,
        "signing_identities": signing_identities,
        "private_app_data_pulled": False,
    }
    write_json(report, output)
    return 0


def write_json(data: dict, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
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
        if args.command == "capabilities":
            return cmd_capabilities()
        if args.command == "windows":
            return cmd_windows()
        if args.command == "gui":
            from .windows_gui import launch
            launch()
            return 0
        if args.command == "mobile-server":
            serve_mobile(args.host, args.port, args.token)
            return 0
        if args.command == "scan":
            return cmd_scan(
                client,
                args.serial,
                args.output,
                args.evidence_dir,
                args.markdown,
                args.html,
                args.hash_apks,
            )
        if args.command == "case":
            return cmd_case(
                client,
                args.serial,
                args.output,
                args.hash_apks,
                args.markdown,
                args.html,
                args.note,
            )
        if args.command == "case-verify":
            result = verify_case_bundle(args.path)
            console.print_json(json.dumps(result))
            return 0 if result.get("valid") else 3
        if args.command == "remediate":
            return cmd_remediate(
                client,
                args.serial,
                args.package,
                args.action,
                args.evidence_dir,
                args.confirm,
            )
        if args.command == "package-apk":
            return cmd_package_apk(
                client,
                args.serial,
                args.package,
                args.evidence_dir,
                args.deep,
                args.rules,
                args.output,
            )
        if args.command == "apk-diff":
            write_json(
                compare_apks(args.before, args.after),
                args.output,
            )
            return 0
        if args.command == "apk":
            write_json(
                inspect_apk(
                    args.path,
                    deep=args.deep,
                    work_dir=args.work_dir,
                    yara_rules=args.rules,
                ),
                args.output,
            )
            return 0
        if args.command == "yara":
            write_json(scan_with_yara(args.path, args.rules), args.output)
            return 0
    except (AdbError, ApkToolError, RemediationRefused, ValueError) as exc:
        console.print(f"[red]DroidShield error:[/red] {exc}")
        return 2
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130
    return 1


if __name__ == "__main__":
    sys.exit(main())
