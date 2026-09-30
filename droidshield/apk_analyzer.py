from __future__ import annotations

import re
from pathlib import Path


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": 15,
    "android.permission.RECEIVE_SMS": 15,
    "android.permission.SEND_SMS": 20,
    "android.permission.READ_CALL_LOG": 10,
    "android.permission.WRITE_CALL_LOG": 10,
    "android.permission.READ_CONTACTS": 5,
    "android.permission.RECORD_AUDIO": 10,
    "android.permission.CAMERA": 5,
    "android.permission.ACCESS_FINE_LOCATION": 8,
    "android.permission.SYSTEM_ALERT_WINDOW": 20,
    "android.permission.REQUEST_INSTALL_PACKAGES": 20,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
    "android.permission.BIND_DEVICE_ADMIN": 25,
}


def analyze_manifest_text(text: str) -> dict:
    permissions = sorted(set(re.findall(
        r'(?:uses-permission[^>]+android:name=["\']([^"\']+))',
        text,
        flags=re.IGNORECASE,
    )))
    services = sorted(set(re.findall(
        r'<service[^>]+android:name=["\']([^"\']+)',
        text,
        flags=re.IGNORECASE,
    )))
    receivers = sorted(set(re.findall(
        r'<receiver[^>]+android:name=["\']([^"\']+)',
        text,
        flags=re.IGNORECASE,
    )))
    providers = sorted(set(re.findall(
        r'<provider[^>]+android:name=["\']([^"\']+)',
        text,
        flags=re.IGNORECASE,
    )))

    permission_score = sum(DANGEROUS_PERMISSIONS.get(p, 0) for p in permissions)
    indicators = []

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        indicators.append("accessibility-capable")
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        indicators.append("overlay-capable")
    if "android.permission.BIND_DEVICE_ADMIN" in permissions:
        indicators.append("device-admin-capable")
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        indicators.append("can-request-package-installation")
    if any(p in permissions for p in ("android.permission.READ_SMS", "android.permission.SEND_SMS")):
        indicators.append("sms-capable")

    return {
        "permissions": permissions,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "permission_score": min(permission_score, 100),
        "indicators": indicators,
    }


def extract_urls(text: str) -> list[str]:
    urls = re.findall(r'https?://[^\s"\'<>]+', text, flags=re.IGNORECASE)
    return sorted(set(urls))[:1000]


def analyze_strings(text: str) -> dict:
    urls = extract_urls(text)
    suspicious_terms = [
        term for term in (
            "accessibility", "deviceadmin", "overlay", "keylogger",
            "credential", "password", "sms", "forwarding", "wallet",
        )
        if term in text.lower()
    ]
    return {"urls": urls, "suspicious_terms": sorted(set(suspicious_terms))}


def analyze_text_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return {
        "path": str(path),
        "manifest": analyze_manifest_text(text),
        "strings": analyze_strings(text),
    }
