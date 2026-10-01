from pathlib import Path

from droidshield.apk import compare_apks


def test_apk_diff_detects_changed_artifact(tmp_path, monkeypatch):
    before = tmp_path / "before.apk"
    after = tmp_path / "after.apk"
    before.write_bytes(b"before")
    after.write_bytes(b"after")

    monkeypatch.setattr(
        "droidshield.apk._signer_identity",
        lambda path: {
            "available": True,
            "certificates": {"sha256": ["AA:BB"]},
        },
    )

    result = compare_apks(before, after)
    assert result["changed"] is True
    assert result["signer_changed"] is False
    assert result["size_delta"] == -1
