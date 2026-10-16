# Bitguard

Bitguard builds a SHA-256 baseline for files in a directory tree and checks later scans for changed or missing files. The baseline is stored in SQLite.

## Setup

Install [uv](https://docs.astral.sh/uv/), then install the project and development tools:

```sh
uv sync --locked --all-groups
uv run pre-commit install
```

## Usage

Scan the current directory:

```sh
uv run bitguard
```

Scan a different directory or choose a database file:

```sh
uv run bitguard --directory /path/to/files
uv run bitguard --directory /path/to/files --database /path/to/baseline.sqlite
```

## What It Detects

- **Added files (`A`):** Not in the baseline yet; their hashes are recorded.
- **Changed files (`E`):** Their SHA-256 no longer matches the baseline; the command exits with an error.
- **Missing files (`D`):** In the baseline but absent from the scan; the command exits with an error.
- **Ignored baseline files (`I`):** Now matched by `.bitguardignore` but still recorded in the baseline; the command exits with an error.
- **Updated files (`U`):** Changed files whose hashes are replaced during `--force-update`.
- **Removed baseline records (`R`):** Missing or ignored paths removed from the baseline during `--force-update`.

Files matched by `.bitguardignore` are excluded from scanning and missing-file reports.

The default database is `.bitguard.sqlite` in the scan directory. Relative database paths are resolved from that directory. If a custom database is inside the scan tree, add it to `.bitguardignore` to keep Bitguard from scanning its own database. The ignore file uses Git-ignore patterns and applies relative to the scan root.

Changed hashes and missing files are reported as errors. To update the baseline, replace hashes for changed files, and remove records for missing files, run:

```sh
uv run bitguard --force-update
```
