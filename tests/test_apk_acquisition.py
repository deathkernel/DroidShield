from pathlib import Path

from droidshield.apk import acquire_package_apks


class FakeClient:
    def package_paths(self, serial, package):
        return [
            "/data/app/com.example.bad/base.apk",
            "/data/app/com.example.bad/split_config.arm64_v8a.apk",
        ]

    def pull(self, serial, remote_path, local_path):
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes((Path(remote_path).name + "\n").encode())
        return local_path


def test_acquire_package_apks_records_hashes(tmp_path):
    result = acquire_package_apks(
        FakeClient(),
        "serial",
        "com.example.bad",
        tmp_path,
    )
    assert result["package"] == "com.example.bad"
    assert len(result["artifacts"]) == 2
    assert all(item["status"] == "pulled" for item in result["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in result["artifacts"])
