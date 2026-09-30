from __future__ import annotations

from .adb import AdbClient


FORWARDING_CODES = {
    "unconditional": "*#21#",
    "busy": "*#67#",
    "no_answer": "*#61#",
    "unreachable": "*#62#",
}


def audit_call_forwarding(client: AdbClient, serial: str) -> dict:
    # DroidShield deliberately does not place or trigger calls/USSD automatically.
    # Carrier/MMI behavior is vendor- and network-dependent, so the report supplies
    # the standard query codes and records the state as unverified until the user or
    # a vendor-specific adapter obtains an authoritative response.
    return {
        "verified": False,
        "verification_method": "manual_MMI_or_carrier",
        "note": (
            "Call forwarding is carrier/network dependent. DroidShield does not "
            "automatically trigger CALL/USSD actions and never infers disabled "
            "forwarding from a missing or failed response."
        ),
        "checks": {
            name: {
                "code": code,
                "status": "manual/carrier verification required",
            }
            for name, code in FORWARDING_CODES.items()
        },
    }
