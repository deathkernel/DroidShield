from __future__ import annotations

from .adb import AdbClient


FORWARDING_CODES = {
    "unconditional": "*#21#",
    "busy": "*#67#",
    "no_answer": "*#61#",
    "unreachable": "*#62#",
}


def audit_call_forwarding(client: AdbClient, serial: str) -> dict:
    results = {}
    for name, code in FORWARDING_CODES.items():
        try:
            # USSD support varies by Android build/carrier. We only collect what
            # the device exposes and never claim a negative result when it cannot
            # be verified.
            output = client.shell(
                f"am start -a android.intent.action.CALL -d tel:{code} >/dev/null 2>&1 || true",
                serial=serial,
            )
            results[name] = {
                "code": code,
                "status": "carrier/device verification required",
                "raw_trigger_result": output.strip(),
            }
        except Exception as exc:
            results[name] = {
                "code": code,
                "status": "unverified",
                "error": str(exc),
            }
    return {
        "verified": False,
        "note": "Call forwarding is carrier/network dependent; DroidShield never infers disabled forwarding from a failed query.",
        "checks": results,
    }
