#!/usr/bin/env python3
"""Bağımlılıksız, regex tabanlı hassas veri tarayıcısı."""

import argparse
import json
import os
from pathlib import Path
import re
import sys


RULES = (
    ("Private key", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Bearer token", re.compile(
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)),
)
ASSIGNMENT = re.compile(
    r"(?<![\w-])['\"]?(?P<name>api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|token|password|passwd|pwd|secret)['\"]?\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s,;#}\]]+)",
    re.IGNORECASE,
)


def assignment_type(name):
    """Atama adını okunabilir bir bulgu türüne dönüştür."""
    name = name.lower().replace("_", "").replace("-", "")
    if name in {"password", "passwd", "pwd"}:
        return "Parola"
    if "token" in name:
        return "Token"
    if "key" in name:
        return "API key"
    return "Secret"


def scan_line(line):
    """Bir satırdaki türleri bul; değerleri dışarıya taşıma."""
    types = {kind for kind, pattern in RULES if pattern.search(line)}
    for match in ASSIGNMENT.finditer(line):
        value = match.group("value").strip("\"'")
        if value and value.lower() not in {"null", "none", "true", "false"}:
            types.add(assignment_type(match.group("name")))
    return sorted(types)


def read_text(path):
    """NUL, kontrol baytları veya geçersiz UTF-8 içeren dosyaları atla."""
    data = path.read_bytes()
    if any(byte < 32 and byte not in (9, 10, 12, 13) for byte in data):
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def scan_directory(root):
    """Klasörü dolaş ve yalnızca maskeli bulgular döndür."""
    findings, errors = [], []

    def walk_error(error):
        errors.append({"file": str(error.filename or root),
                       "error": "Klasör okunamadı"})

    for directory, dirs, files in os.walk(root, onerror=walk_error,
                                          followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git"
                         and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if name == ".git" or path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            try:
                content = read_text(path)
            except OSError:
                errors.append({"file": relative, "error": "Dosya okunamadı"})
                continue
            if content is None:
                continue
            for number, line in enumerate(content.splitlines(), start=1):
                for kind in scan_line(line):
                    findings.append({"file": relative, "line": number,
                                     "type": kind, "value": "********"})
    return {"findings": findings, "errors": errors}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="SecretGuard: klasörlerde olası hassas verileri bulur.")
    parser.add_argument("directory", nargs="?", default=".",
                        help="Taranacak klasör (varsayılan: geçerli klasör)")
    parser.add_argument("--json", action="store_true",
                        help="Maskeli JSON raporunu standart çıktıya yaz")
    args = parser.parse_args(argv)
    root = Path(args.directory).resolve()
    if not root.is_dir() or root.name == ".git":
        parser.error("Geçerli bir tarama klasörü belirtin (.git hariç).")
    report = scan_directory(root)
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        for item in report["findings"]:
            # JSON kaçışları dosya adlarındaki terminal kontrol karakterlerini gizler.
            filename = json.dumps(item["file"], ensure_ascii=True)
            print(f'{filename}:{item["line"]} | {item["type"]} | {item["value"]}')
        print(f'{len(report["findings"])} olası hassas veri bulundu.')
        for error in report["errors"]:
            print(json.dumps(error, ensure_ascii=True), file=sys.stderr)
    if report["errors"]:
        return 2
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
