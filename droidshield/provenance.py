from __future__ import annotations

import re
from typing import Any

_HEX = re.compile(r"^[0-9a-fA-F]{64}$")


def normalize_digest(value: str | None) -> str | None:
    if not value:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    return compact if _HEX.fullmatch(compact) else None


def normalize_certificate_set(digests: list[str] | None) -> list[str]:
    return sorted({item for value in digests or [] if (item := normalize_digest(value))})


def certificate_identity(signing: dict[str, Any] | None) -> dict[str, Any]:
    signing = signing or {}
    certs = signing.get("certificates", {})
    sha256 = normalize_certificate_set(certs.get("sha256", []))
    sha1 = sorted({re.sub(r"[^0-9a-fA-F]", "", value).lower() for value in certs.get("sha1", []) if value})
    md5 = sorted({re.sub(r"[^0-9a-fA-F]", "", value).lower() for value in certs.get("md5", []) if value})
    return {
        "available": bool(signing.get("available")),
        "verified": signing.get("returncode") == 0 if signing.get("returncode") is not None else None,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "identity_key": sha256[0] if sha256 else None,
    }


def compare_certificate_identity(before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
    left = certificate_identity(before)
    right = certificate_identity(after)
    comparable = bool(left["sha256"] and right["sha256"])
    return {
        "comparable": comparable,
        "same_signer": left["sha256"] == right["sha256"] if comparable else None,
        "before": left,
        "after": right,
    }
