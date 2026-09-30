from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    description: str
    package: str | None = None
    evidence: dict | None = None


def package_findings(packages: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    # Conservative heuristic: these are triage signals, not proof of malware.
    for package in packages:
        lower = package.lower()
        if any(token in lower for token in ("fake", "hack", "crack", "modmenu")):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    title="Suspicious package name",
                    description="Package name matches a weak malware/modification triage heuristic.",
                    package=package,
                    evidence={"heuristic": "suspicious-name"},
                )
            )
    return findings
