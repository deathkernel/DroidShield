from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any


DEX_MAGIC = bytes((0x64, 0x65, 0x78, 0x0A))
ELF_MAGIC = bytes((0x7F, 0x45, 0x4C, 0x46))


def _dex_version(data: bytes) -> str | None:
    if len(data) < 8 or data[:4] != DEX_MAGIC:
        return None
    raw = data[4:7]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _elf_identity(data: bytes) -> dict[str, Any]:
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        return {"is_elf": False}
    elf_class = {1: "ELF32", 2: "ELF64"}.get(data[4], f"ELF-class-{data[4]}")
    endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
    machine = None
    if endian == "little":
        machine = struct.unpack_from("<H", data, 18)[0]
    elif endian == "big":
        machine = struct.unpack_from(">H", data, 18)[0]
    return {"is_elf": True, "class": elf_class, "endianness": endian, "machine": machine}


def inspect_apk_archive(path: Path, max_entries: int = 20000) -> dict[str, Any]:
    result: dict[str, Any] = {
        "opened": False,
        "entry_count": 0,
        "dex_files": [],
        "native_libraries": [],
        "asset_entries": [],
        "resource_entries": [],
        "certificate_entries": [],
        "suspicious_archive_paths": [],
        "errors": [],
        "max_entries": max_entries,
        "truncated": False,
    }
    try:
        with zipfile.ZipFile(path) as archive:
            result["opened"] = True
            all_infos = archive.infolist()
            result["truncated"] = len(all_infos) > max_entries
            infos = all_infos[:max_entries]
            result["entry_count"] = len(infos)
            result["archive_entry_count"] = len(all_infos)
            for info in infos:
                name = info.filename.replace("\\\\", "/")
                lower = name.lower()
                if name.startswith("classes") and lower.endswith(".dex"):
                    with archive.open(info) as handle:
                        magic = handle.read(8)
                    result["dex_files"].append({
                        "path": name,
                        "size": info.file_size,
                        "version": _dex_version(magic),
                        "magic_valid": magic[:4] == DEX_MAGIC,
                    })
                elif lower.startswith("lib/") and lower.endswith(".so"):
                    with archive.open(info) as handle:
                        header = handle.read(64)
                    result["native_libraries"].append({
                        "path": name,
                        "size": info.file_size,
                        **_elf_identity(header),
                    })
                elif lower.startswith("assets/"):
                    result["asset_entries"].append({"path": name, "size": info.file_size})
                elif "/res/" in lower or lower.startswith("res/"):
                    result["resource_entries"].append({"path": name, "size": info.file_size})
                elif lower.startswith("meta-inf/") and lower.endswith((".rsa", ".dsa", ".ec", ".sf")):
                    result["certificate_entries"].append(name)
                if any(token in lower for token in ("payload", "dropper", "stage2", "shell.dex", "inject")):
                    result["suspicious_archive_paths"].append(name)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        result["errors"].append(str(exc))
    result["dex_count"] = len(result["dex_files"])
    result["native_library_count"] = len(result["native_libraries"])
    result["asset_count"] = len(result["asset_entries"])
    result["resource_count"] = len(result["resource_entries"])
    result["certificate_entry_count"] = len(result["certificate_entries"])
    result["suspicious_archive_path_count"] = len(result["suspicious_archive_paths"])
    return result
