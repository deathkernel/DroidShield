"""Safe remediation primitives.

This module intentionally starts empty of destructive operations. Future remediation
commands must require explicit user confirmation and must preserve evidence first.
"""

from __future__ import annotations


class RemediationRefused(RuntimeError):
    """Raised when a remediation action cannot be safely performed."""


def explain_remediation_policy() -> str:
    return (
        "DroidShield does not blindly delete packages. Future remediation will "
        "require explicit confirmation, package classification, evidence capture, "
        "and a post-action verification step."
    )
