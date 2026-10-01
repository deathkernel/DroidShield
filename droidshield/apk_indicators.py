from __future__ import annotations

import re
from pathlib import Path


DYNAMIC_PATTERNS = {
    "dynamic-code-loading": re.compile(
        r"(?i)(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadDex|loadClass)"
    ),
    "reflection": re.compile(
        r"(?i)(java\.lang\.reflect|Class\.forName|getDeclaredMethod|getDeclaredField)"
    ),
    "webview-javascript": re.compile(
        r"(?i)(setJavaScriptEnabled|addJavascriptInterface|evaluateJavascript)"
    ),
    "native-loading": re.compile(
        r"(?i)(System\.loadLibrary|System\.load\()"
    ),
    "shell-execution": re.compile(
        r"(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|/system/bin/sh)"
    ),
}


def analyze_source_text(
    root: Path,
    max_files: int = 1000,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict:
    counts = {name: 0 for name in DYNAMIC_PATTERNS}
    examples = {name: [] for name in DYNAMIC_PATTERNS}
    scanned = 0
    total = 0
    truncated = False
    extensions = {
        ".java",
        ".kt",
        ".smali",
        ".xml",
        ".txt",
        ".json",
        ".properties",
    }

    for path in sorted(root.rglob("*")):
        if scanned >= max_files or total >= max_bytes:
            break
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        total += len(text.encode("utf-8", errors="ignore"))
        for name, pattern in DYNAMIC_PATTERNS.items():
            matches = list(pattern.finditer(text))
            if not matches:
                continue
            counts[name] += len(matches)
            if len(examples[name]) < 5:
                examples[name].append(path.as_posix())

    truncated = scanned >= max_files or total >= max_bytes
    return {
        "files_scanned": scanned,
        "bytes_scanned": total,
        "indicator_counts": counts,
        "examples": examples,
        "truncated": truncated,
        "limits": {"max_files": max_files, "max_bytes": max_bytes},
    }
