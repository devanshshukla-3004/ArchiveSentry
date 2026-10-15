from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def scan_paths(root: Path, exclude: set[str] | None = None) -> dict[str, str]:
    root = root.resolve()
    excluded = exclude or set()
    result: dict[str, str] = {}
    if root.is_file():
        if root.name not in excluded:
            result[root.name] = sha256_file(root)
        return result
    if not root.is_dir():
        raise ValueError(f"Path does not exist or is not readable: {root}")
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not (Path(current) / d).is_symlink())
        for name in sorted(files):
            path = Path(current) / name
            if name in excluded or path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            try:
                result[rel] = sha256_file(path)
            except OSError as exc:
                print(f"WARN: could not read {rel}: {exc}", file=sys.stderr)
    return dict(sorted(result.items()))

def create_baseline(root: Path, output: Path, exclude: set[str] | None = None) -> dict[str, Any]:
    files = scan_paths(root, exclude)
    document = {"format": "HashVault baseline v1", "algorithm": "sha256", "root_name": root.name, "files": files}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document

def verify_baseline(root: Path, baseline_path: Path, exclude: set[str] | None = None) -> dict[str, Any]:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    if baseline.get("format") != "HashVault baseline v1" or baseline.get("algorithm") != "sha256" or not isinstance(baseline.get("files"), dict):
        raise ValueError("Unsupported or malformed baseline format")
    expected: dict[str, str] = baseline["files"]
    actual = scan_paths(root, exclude)
    expected_names, actual_names = set(expected), set(actual)
    added = sorted(actual_names - expected_names)
    deleted = sorted(expected_names - actual_names)
    modified = sorted(name for name in expected_names & actual_names if expected[name] != actual[name])
    return {"format": "HashVault report v1", "root": str(root), "baseline": str(baseline_path),
            "summary": {"checked": len(expected_names & actual_names), "added": len(added), "deleted": len(deleted), "modified": len(modified),
                        "status": "CHANGED" if added or deleted or modified else "CLEAN"},
            "added": added, "deleted": deleted, "modified": modified}

def main() -> int:
    parser = argparse.ArgumentParser(description="HashVault — SHA-256 file integrity verification")
    sub = parser.add_subparsers(dest="command", required=True)
    baseline_cmd = sub.add_parser("baseline", help="Create a SHA-256 baseline manifest")
    baseline_cmd.add_argument("target", type=Path)
    baseline_cmd.add_argument("-o", "--output", type=Path, default=Path("reports/baseline.json"))
    baseline_cmd.add_argument("--exclude", action="append", default=[], help="File or directory name to exclude (repeatable)")
    verify_cmd = sub.add_parser("verify", help="Compare current files with a trusted baseline")
    verify_cmd.add_argument("target", type=Path)
    verify_cmd.add_argument("-b", "--baseline", type=Path, default=Path("reports/baseline.json"))
    verify_cmd.add_argument("-o", "--output", type=Path, default=Path("reports/verification.json"))
    verify_cmd.add_argument("--exclude", action="append", default=[], help="File or directory name to exclude (repeatable)")
    args = parser.parse_args()
    try:
        if args.command == "baseline":
            doc = create_baseline(args.target, args.output, set(args.exclude))
            print(f"Baseline created: {args.output} ({len(doc['files'])} files)")
            return 0
        report = verify_baseline(args.target, args.baseline, set(args.exclude))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        s = report["summary"]
        print(f"HashVault verification: {s['status']}")
        print(f"Checked: {s['checked']} | Added: {s['added']} | Modified: {s['modified']} | Deleted: {s['deleted']}")
        print(f"JSON report: {args.output}")
        return 1 if s["status"] == "CHANGED" else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
