# HashVault — File Integrity Verification

**Day 12/100 · 100 Days, 100 Cybersecurity Projects**

HashVault is a lightweight, offline-first Python CLI that creates SHA-256 manifests and compares a directory against a trusted baseline. It reports files that are **added, modified, or deleted** and exports JSON reports.

## Features
- SHA-256 hashing using Python's standard library
- Deterministic baseline manifest
- Added / modified / deleted file detection
- JSON verification reports and meaningful exit codes
- Repeatable exclusions by file or directory name
- Skips symbolic links and does not follow symlinked directories
- Automated tests for clean, modified, added, and deleted files

## Requirements
- Python 3.10+
- No third-party runtime dependencies

## Quick start

### 1. Create a baseline

    python hashvault.py baseline ./samples -o ./reports/baseline.json

### 2. Verify integrity

    python hashvault.py verify ./samples -b ./reports/baseline.json -o ./reports/verification.json

### 3. Detect changes
Modify or add a file under samples/, then run the verification command again. HashVault will print CHANGED and list the differences. Verification exits with 0 for a clean baseline, 1 when files changed, and 2 for invalid input, baseline, or filesystem errors.

### Exclusions

    python hashvault.py baseline ./target --exclude .git --exclude __pycache__

Exclusions match a file or directory name wherever it appears beneath the target.

### Run tests

    python -m unittest discover -s tests -v

## Example report
The following values are illustrative, not output from a live system:

    {
      "format": "HashVault report v1",
      "summary": {"checked": 2, "added": 1, "deleted": 0, "modified": 1, "status": "CHANGED"},
      "added": ["new.txt"],
      "deleted": [],
      "modified": ["notes.txt"]
    }

## Security notes and limitations
- **Protect the baseline.** A hash only detects changes relative to a trustworthy baseline. If an attacker can alter both the files and the manifest, they may hide tampering. Store the baseline somewhere access-controlled or sign it.
- SHA-256 provides integrity comparison, not confidentiality or proof of who changed a file.
- HashVault is a local, read-only scanner. It does not remediate files, monitor continuously, or contact external services.
- Permission errors are reported as warnings on stderr; inaccessible files may be absent from the resulting scan, so review warnings before trusting a report.
- This is a learning project, not a certified compliance or forensic tool.

## Project structure

    HashVault/
    ├── hashvault.py
    ├── tests/test_hashvault.py
    ├── samples/
    ├── reports/
    ├── requirements.txt
    ├── .gitignore
    └── LICENSE

## License
MIT
