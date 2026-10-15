#!/usr/bin/env python3
"""ArchiveSentry: read-only security inspection for ZIP and TAR archives.

The tool never extracts files. Findings are triage indicators, not proof of malware.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".hta", ".msi", ".jar", ".lnk", ".iso",
}
DOUBLE_EXTENSIONS = {".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".txt", ".xlsx"}


def classify_member(name: str) -> list[dict[str, str]]:
    """Return path-related findings without writing or extracting the member."""
    findings: list[dict[str, str]] = []
    normalized = name.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(name)
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if normalized.startswith("/") or windows.is_absolute() or windows.drive:
        findings.append({"rule": "ABSOLUTE_PATH", "severity": "HIGH", "evidence": "Archive member uses an absolute or drive-qualified path."})
    if ".." in parts:
        findings.append({"rule": "PATH_TRAVERSAL", "severity": "HIGH", "evidence": "Archive member contains a parent-directory traversal component."})
    suffixes = [s.lower() for s in posix.suffixes]
    if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
        findings.append({"rule": "EXECUTABLE_OR_SCRIPT", "severity": "MEDIUM", "evidence": f"Member has potentially executable/script extension {suffixes[-1]}."})
    if len(suffixes) >= 2 and suffixes[-1] in RISKY_EXTENSIONS and suffixes[-2] in DOUBLE_EXTENSIONS:
        findings.append({"rule": "DOUBLE_EXTENSION", "severity": "HIGH", "evidence": "Member uses a document/image-like extension followed by an executable/script extension."})
    return findings


def inspect_zip(path: Path, max_members: int) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > max_members:
            findings.append({"rule": "MEMBER_LIMIT", "severity": "MEDIUM", "member": None, "evidence": f"Archive contains {len(infos)} members, above configured limit {max_members}."})
        for info in infos[:max_members]:
            if info.is_dir():
                continue
            member_findings = classify_member(info.filename)
            ratio = (info.file_size / info.compress_size) if info.compress_size else (math.inf if info.file_size else 1.0)
            if info.file_size >= 1_000_000 and ratio >= 100:
                member_findings.append({"rule": "HIGH_COMPRESSION_RATIO", "severity": "HIGH", "evidence": f"Declared size-to-compressed-size ratio is {ratio:.1f}:1."})
            elif info.file_size >= 10_000_000 and ratio >= 20:
                member_findings.append({"rule": "HIGH_COMPRESSION_RATIO", "severity": "MEDIUM", "evidence": f"Declared size-to-compressed-size ratio is {ratio:.1f}:1."})
            if info.flag_bits & 0x1:
                member_findings.append({"rule": "ENCRYPTED_MEMBER", "severity": "LOW", "evidence": "ZIP member is marked as encrypted; contents were not inspected."})
            for finding in member_findings:
                finding["member"] = info.filename
                findings.append(finding)
            members.append({"name": info.filename, "size_bytes": info.file_size, "compressed_bytes": info.compress_size, "findings": [f["rule"] for f in member_findings]})
    return {"archive": str(path), "format": "zip", "members_checked": len(members), "members": members, "findings": findings}


def inspect_tar(path: Path, max_members: int) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    with tarfile.open(path, mode="r:*") as archive:
        for index, info in enumerate(archive):
            if index >= max_members:
                findings.append({"rule": "MEMBER_LIMIT", "severity": "MEDIUM", "member": None, "evidence": f"Archive exceeds configured member limit {max_members}."})
                break
            if info.isdir():
                continue
            member_findings = classify_member(info.name)
            if info.issym() or info.islnk():
                member_findings.append({"rule": "LINK_MEMBER", "severity": "MEDIUM", "evidence": "Archive member is a symbolic or hard link; target was not followed."})
            for finding in member_findings:
                finding["member"] = info.name
                findings.append(finding)
            members.append({"name": info.name, "size_bytes": info.size, "compressed_bytes": None, "findings": [f["rule"] for f in member_findings]})
    return {"archive": str(path), "format": "tar", "members_checked": len(members), "members": members, "findings": findings}


def inspect_archive(path: str | Path, max_members: int = 10000) -> dict[str, Any]:
    target = Path(path)
    if max_members < 1:
        raise ValueError("max_members must be at least 1")
    if not target.is_file():
        raise FileNotFoundError(f"Archive not found: {target}")
    if zipfile.is_zipfile(target):
        report = inspect_zip(target, max_members)
    elif tarfile.is_tarfile(target):
        report = inspect_tar(target, max_members)
    else:
        raise ValueError("Unsupported or invalid archive; supported formats: ZIP and TAR/TAR.GZ/TGZ")
    report["status"] = "FINDINGS" if report["findings"] else "NO_FINDINGS"
    report["note"] = "Read-only metadata inspection. No files were extracted; findings are heuristics, not proof of malware."
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only ZIP/TAR archive security inspector.")
    parser.add_argument("archive", help="Path to a ZIP, TAR, TAR.GZ, or TGZ archive")
    parser.add_argument("--json", dest="json_path", help="Write full report to this JSON path")
    parser.add_argument("--max-members", type=int, default=10000, help="Maximum archive members to inspect (default: 10000)")
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(args.archive, args.max_members)
        print(f"ArchiveSentry: {report['status']}")
        print(f"Format: {report['format']} | Members checked: {report['members_checked']} | Findings: {len(report['findings'])}")
        for finding in report["findings"]:
            print(f"[{finding['severity']}] {finding['rule']} | {finding.get('member') or '-'} | {finding['evidence']}")
        if args.json_path:
            out = Path(args.json_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"JSON report: {out}")
        return 1 if report["findings"] else 0
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, RuntimeError) as exc:
        print(f"ArchiveSentry error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
