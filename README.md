# ArchiveSentry — Archive Security Inspector

**Day 12/100 · 100 Days • 100 Cybersecurity Projects**

ArchiveSentry is a read-only Python utility that inspects ZIP and TAR-family archives for potentially dangerous archive metadata before extraction. It flags path traversal, absolute/drive-qualified member paths, executable or script extensions, double extensions, suspicious ZIP compression ratios, encrypted ZIP entries, and TAR link entries.

## Why this project?

Archives are common delivery formats for software, documents, and evidence. Before extracting an untrusted archive, a defender can review its member paths and metadata for common warning signs.

## Features

- ZIP, TAR, TAR.GZ and TGZ metadata inspection
- Path traversal and absolute-path indicators
- Executable/script extension and double-extension heuristics
- ZIP declared size/compression-ratio checks
- Encrypted ZIP entry and TAR link indicators
- Member-count limit to bound metadata processing
- Terminal findings with severity and evidence
- Optional JSON report
- No extraction, execution, network requests, or third-party runtime dependencies
- Automated unit tests

## Quick start

Python 3.10+ recommended.

```bash
git clone https://github.com/devanshshukla-3004/HashVault.git
cd HashVault
python -m unittest discover -s tests -v
python hashvault.py samples/demo.zip --json reports/archive-report.json
```

The repository slug currently remains HashVault; rename the GitHub repository to **ArchiveSentry** in Settings → General → Repository name when ready. GitHub normally redirects the old URL after a rename.

## Usage

```bash
python hashvault.py path/to/untrusted.zip
python hashvault.py path/to/archive.tar.gz --json reports/inspection.json
python hashvault.py path/to/archive.zip --max-members 2000
```

Exit codes: `0` no findings; `1` findings detected; `2` invalid input or inspection error.

## Detection logic and limitations

- **PATH_TRAVERSAL / ABSOLUTE_PATH:** member names contain parent traversal, absolute paths, or drive-qualified paths.
- **EXECUTABLE_OR_SCRIPT / DOUBLE_EXTENSION:** file extensions may deserve review; benign installers and scripts can also trigger.
- **HIGH_COMPRESSION_RATIO:** compares declared ZIP sizes; this is a heuristic, not a decompression-bomb verdict.
- **ENCRYPTED_MEMBER / LINK_MEMBER:** flags metadata that can complicate review.

ArchiveSentry does **not** extract or execute archive members and does not scan file contents for malware. Metadata may be forged, and safe-looking names do not guarantee safety. Review findings in context and use an isolated environment for further analysis.

## Project layout

```text
HashVault/
├── hashvault.py
├── tests/
│   └── test_hashvault.py
├── samples/
├── reports/
├── requirements.txt
└── README.md
```

## Security use

Use only on archives you are authorized to inspect. Keep the original archive unchanged if it may be evidence, and preserve its source and acquisition details separately.

**Author:** Devansh Shukla  
**Challenge:** Day 12/100
