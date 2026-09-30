from __future__ import annotations

import json
from html import escape


def markdown_report(report: dict) -> str:
    lines = [
        "# DroidShield Security Report",
        "",
        f"- Generated: {report.get('generated_at', 'unknown')}",
        f"- Device: {report.get('device', {}).get('model', 'unknown')}",
        f"- Risk: {report.get('risk', {}).get('level', 'unknown')} ({report.get('risk', {}).get('score', 0)}/100)",
        "",
        "## Findings",
    ]
    findings = report.get("findings", [])
    if not findings:
        lines.append("No rule-based findings were generated.")
    for item in findings:
        lines.append(f"- **{item.get('severity')}** — {item.get('title')} — {item.get('description')}")
    lines += ["", "## Hardening", ""]
    lines.extend(f"- {item}" for item in report.get("hardening", []))
    return "\n".join(lines) + "\n"


def html_report(report: dict) -> str:
    data = json.dumps(report, indent=2)
    return "<!doctype html><html><body><h1>DroidShield Security Report</h1><pre>" + escape(data) + "</pre></body></html>"
