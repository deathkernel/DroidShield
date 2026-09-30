from droidshield.apk import _extract_cert_digests


def test_extract_cert_digests():
    text = """
    Signer #1 certificate SHA-256 digest: AA:BB:CC:DD
    Signer #1 certificate SHA-1 digest: 11:22:33
    """
    result = _extract_cert_digests(text)
    assert result["sha256"] == ["AA:BB:CC:DD"]
    assert result["sha1"] == ["11:22:33"]
