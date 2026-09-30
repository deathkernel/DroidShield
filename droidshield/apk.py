from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

from .adb import AdbClient
from .apk_analyzer import analyze_manifest_text, analyze_strings
from .yara import scan_with_yara


class ApkToolError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_tool(command: list[str], timeout: int = 120) -> dict:
    try:
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return {
            "returncode": proc.returncode,
            "output": proc.stdout[:20000],
            "error": proc.stderr[:4000],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": None,
            "output": (exc.stdout or "")[:20000] if isinstance(exc.stdout, str) else "",
            "error": "analysis command timed out",
        }


def _extract_cert_digests(output: str) -> dict[str, list[str]]:
    sha256 = sorted(set(re.findall(
        r"(?i)(?:Signer #\d+ certificate SHA-256 digest|SHA-256 digest):\s*([0-9A-F:]{32,})",
        output,
    )))
    sha1 = sorted(set(re.findall(
        r"(?i)(?:Signer #\d+ certificate SHA-1 digest|SHA-1 digest):\s*([0-9A-F:]{16,})",
        output,
    )))
    md5 = sorted(set(re.findall(
        r"(?i)(?:Signer #\d+ certificate MD5 digest|MD5 digest):\s*([0-9A-F:]{16,})",
        output,
    )))
    return {"sha256": sha256, "sha1": sha1, "md5": md5}


def _signer_identity(path: Path) -> dict:
    if not tool_available("apksigner"):
        return {"available": False}
    result = _run_tool(
        ["apksigner", "verify", "--verbose", "--print-certs", str(path)],
        timeout=60,
    )
    return {
        "available": True,
        "returncode": result["returncode"],
        "certificates": _extract_cert_digests(result["output"]),
        "error": result["error"],
    }


def _analyze_text_tree(
    root: Path,
    max_files: int = 500,
    max_total_bytes: int = 32 * 1024 * 1024,
) -> dict:
    scanned = 0
    total_bytes = 0
    urls = set()
    terms = set()
    manifests = []

    extensions = {".xml", ".smali", ".java", ".kt", ".txt", ".json", ".properties"}
    for path in sorted(root.rglob("*")):
        if scanned >= max_files or total_bytes >= max_total_bytes:
            break
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        try:
            size = path.stat().st_size
            if size <= 0 or size > 512 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        total_bytes += len(text.encode("utf-8", errors="ignore"))
        info = analyze_strings(text)
        urls.update(info["urls"])
        terms.update(info["suspicious_terms"])

        if path.name == "AndroidManifest.xml":
            manifests.append(analyze_manifest_text(text))

    return {
        "files_scanned": scanned,
        "bytes_scanned": total_bytes,
        "urls": sorted(urls)[:1000],
        "suspicious_terms": sorted(terms),
        "manifests": manifests[:5],
    }


def inspect_apk(
    path: Path,
    deep: bool = False,
    work_dir: Path | None = None,
    yara_rules: Path | None = None,
) -> dict:
    if not path.is_file():
        raise ApkToolError(f"APK not found: {path}")

    result = {
        "path": str(path),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "tools": {
            name: tool_available(name)
            for name in ("aapt2", "apksigner", "apktool", "jadx", "yara")
        },
    }

    if result["tools"]["aapt2"]:
        result["aapt2"] = _run_tool(
            ["aapt2", "dump", "badging", str(path)],
            timeout=60,
        )

    if result["tools"]["apksigner"]:
        signer = _signer_identity(path)
        result["signing"] = signer

    if yara_rules is not None:
        result["yara"] = scan_with_yara(path, yara_rules)

    if not deep:
        return result

    work = work_dir or path.with_name(path.stem + "-droidshield-work")
    work.mkdir(parents=True, exist_ok=True)
    result["deep"] = {
        "work_dir": str(work),
        "apktool": None,
        "jadx": None,
        "decoded_analysis": None,
    }

    if result["tools"]["apktool"]:
        decoded = work / "apktool"
        result["deep"]["apktool"] = _run_tool(
            ["apktool", "d", "-f", str(path), "-o", str(decoded)],
        )
        if result["deep"]["apktool"]["returncode"] == 0 and decoded.is_dir():
            result["deep"]["decoded_analysis"] = _analyze_text_tree(decoded)

    if result["tools"]["jadx"]:
        source = work / "jadx"
        result["deep"]["jadx"] = _run_tool(
            ["jadx", "-q", "-d", str(source), str(path)],
        )
        if result["deep"]["jadx"]["returncode"] == 0 and source.is_dir():
            result["deep"]["source_analysis"] = _analyze_text_tree(source)

    return result


def compare_apks(before: Path, after: Path) -> dict:
    if not before.is_file() or not after.is_file():
        raise ApkToolError("Both APK files must exist for comparison.")

    before_hash = sha256_file(before)
    after_hash = sha256_file(after)
    before_signer = _signer_identity(before)
    after_signer = _signer_identity(after)

    before_certs = before_signer.get("certificates", {}).get("sha256", [])
    after_certs = after_signer.get("certificates", {}).get("sha256", [])

    return {
        "before": {
            "path": str(before),
            "sha256": before_hash,
            "size": before.stat().st_size,
            "signing": before_signer,
        },
        "after": {
            "path": str(after),
            "sha256": after_hash,
            "size": after.stat().st_size,
            "signing": after_signer,
        },
        "changed": before_hash != after_hash,
        "signer_changed": (
            before_certs != after_certs
            if before_certs and after_certs
            else None
        ),
        "size_delta": after.stat().st_size - before.stat().st_size,
    }


def acquire_package_apks(
    client: AdbClient,
    serial: str,
    package: str,
    directory: Path,
) -> dict:
    paths = client.package_paths(serial, package)
    if not paths:
        raise ApkToolError(f"No APK paths exposed for package: {package}")

    target = directory / package.replace(".", "_")
    target.mkdir(parents=True, exist_ok=True)

    artifacts = []
    for index, remote_path in enumerate(paths, start=1):
        filename = Path(remote_path).name or f"split-{index}.apk"
        local_path = target / f"{index:02d}-{filename}"
        try:
            pulled = client.pull(serial, remote_path, local_path)
            artifacts.append({
                "remote_path": remote_path,
                "local_path": str(pulled),
                "sha256": sha256_file(pulled),
                "size": pulled.stat().st_size,
                "status": "pulled",
            })
        except Exception as exc:
            artifacts.append({
                "remote_path": remote_path,
                "local_path": str(local_path),
                "status": "pull_failed",
                "error": str(exc),
            })

    return {
        "package": package,
        "directory": str(target),
        "artifacts": artifacts,
    }
