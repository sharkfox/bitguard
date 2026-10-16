"""Scan directory trees and maintain SHA-256 file baselines."""

from __future__ import annotations

import datetime
import hashlib
import multiprocessing
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import click
from pathspec import GitIgnoreSpec
from tqdm import tqdm

DATABASE_FILE = ".bitguard.sqlite"
IGNORE_FILE = ".bitguardignore"
ScanResult = tuple[str, str | None, str]
DatabaseEntry = tuple[str, str, str, str]


@dataclass
class ScanSummary:
    """Hold categorized results from one scan."""

    files_added: list[ScanResult]
    files_error: list[ScanResult]
    files_missing: list[str]
    files_ignored: list[str]
    file_count: int


class ExcludeFilter:  # pylint: disable=too-few-public-methods
    """Match Git-ignore patterns from the scan root's ignore file."""

    def __init__(self, root: Path) -> None:
        """Load .bitguardignore patterns using Git's ignore syntax."""
        ignore_file = root / IGNORE_FILE
        lines = ignore_file.read_text(encoding="utf-8").splitlines() if ignore_file.is_file() else []
        self.spec = GitIgnoreSpec.from_lines(lines)

    def matches(self, value: str) -> bool:
        """Return whether a filename or full path should be excluded."""
        return self.spec.match_file(value)


def sha256(filename: str) -> str:
    """Return the SHA-256 digest of a file's contents."""
    digest = hashlib.sha256()
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(1 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def format_timestamp(value: float) -> str:
    """Format a Unix timestamp as a UTC ISO-8601 value."""
    return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def hash_file(filename: str) -> tuple[str, str, str, str]:
    """Return a filename, digest, modification time, and hash time."""
    metadata = os.stat(filename)
    modified_at = metadata.st_mtime
    digest = sha256(filename)
    hashed_at = datetime.datetime.now(datetime.timezone.utc).timestamp()
    return (
        filename,
        digest,
        format_timestamp(modified_at),
        format_timestamp(hashed_at),
    )


def collect_files(root: Path, exclude_filter: ExcludeFilter) -> list[str]:
    """Collect scan-eligible files under the root directory."""
    files = []
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [
            name
            for name in subdirectories
            if not exclude_filter.matches(f"{relative_path(os.path.join(directory, name), root)}/")
        ]
        for name in filenames:
            filename = os.path.join(directory, name)
            if not exclude_filter.matches(relative_path(filename, root)):
                files.append(filename)
    return files


def relative_path(filename: str, root: Path) -> str:
    """Return a root-relative path using database-stable separators."""
    return os.path.relpath(filename, root).replace(os.sep, "/")


def read_stored_hashes(database_path: Path) -> dict[str, str]:
    """Create or migrate the database and return its stored file hashes."""
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS files "
            "(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, modified_at TEXT, hashed_at TEXT)"
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(files)")}
        for column in ("modified_at", "hashed_at"):
            if column not in columns:
                connection.execute(f"ALTER TABLE files ADD COLUMN {column} TEXT")
        return dict(connection.execute("SELECT path, sha256 FROM files").fetchall())
    finally:
        connection.close()


def hash_scan_files(filenames: list[str]) -> dict[str, tuple[str, str, str]]:
    """Hash all files in parallel and return metadata keyed by filename."""
    with multiprocessing.Pool() as pool:
        return {
            result[0]: result[1:]
            for result in tqdm(pool.imap_unordered(hash_file, filenames), total=len(filenames), desc="Hashing")
        }


def build_scan_results(
    filenames: list[str],
    scan_root: Path,
    stored_hashes: dict[str, str],
    computed_hashes: dict[str, tuple[str, str, str]],
) -> tuple[list[ScanResult], list[DatabaseEntry], set[str]]:
    """Build comparisons, database entries, and the set of scanned paths."""
    results = []
    entries = []
    scanned_paths = set()
    for filename in filenames:
        actual_hash, modified_at, hashed_at = computed_hashes[filename]
        key = relative_path(filename, scan_root)
        expected_hash = stored_hashes.get(key)
        entries.append((key, actual_hash, modified_at, hashed_at))
        results.append((filename, expected_hash, actual_hash))
        scanned_paths.add(key)
    return results, entries, scanned_paths


def find_missing_files(
    stored_hashes: dict[str, str],
    scanned_paths: set[str],
    exclude_filter: ExcludeFilter,
) -> list[str]:
    """Return stored paths absent from the scan and not ignored."""
    return sorted(path for path in stored_hashes if path not in scanned_paths and not exclude_filter.matches(path))


def find_ignored_files(
    stored_hashes: dict[str, str],
    scanned_paths: set[str],
    exclude_filter: ExcludeFilter,
) -> list[str]:
    """Return stored paths that are now excluded by ignore rules."""
    return sorted(path for path in stored_hashes if path not in scanned_paths and exclude_filter.matches(path))


def summarize_scan_results(
    results: list[ScanResult],
    stored_hashes: dict[str, str],
    scanned_paths: set[str],
    exclude_filter: ExcludeFilter,
) -> ScanSummary:
    """Categorize scan comparisons and identify stored paths absent from the scan."""
    return ScanSummary(
        files_added=[result for result in results if result[1] is None],
        files_error=[result for result in results if result[1] is not None and result[1] != result[2]],
        files_missing=find_missing_files(stored_hashes, scanned_paths, exclude_filter),
        files_ignored=find_ignored_files(stored_hashes, scanned_paths, exclude_filter),
        file_count=len(results),
    )


def save_scan_results(
    database_path: Path,
    entries: list[DatabaseEntry],
    stored_hashes: dict[str, str],
    files_to_remove: list[str],
    force_update: bool,
) -> None:
    """Insert new hashes and optionally update or remove baseline records."""
    connection = sqlite3.connect(database_path)
    try:
        with connection:
            if force_update:
                connection.executemany(
                    "DELETE FROM files WHERE path = ?",
                    ((path,) for path in files_to_remove),
                )
                connection.executemany(
                    "UPDATE files SET sha256 = ?, modified_at = ?, hashed_at = ? WHERE path = ?",
                    [
                        (digest, modified_at, hashed_at, path)
                        for path, digest, modified_at, hashed_at in entries
                        if path in stored_hashes and stored_hashes[path] != digest
                    ],
                )
            connection.executemany(
                "INSERT OR IGNORE INTO files (path, sha256, modified_at, hashed_at) VALUES (?, ?, ?, ?)",
                entries,
            )
    finally:
        connection.close()


def report_results(summary: ScanSummary, force_update: bool) -> None:
    """Print scan results and fail unless differences are being force-updated."""
    for filename, _, _ in summary.files_added:
        print(f"A {filename} added")
    for filename, expected_hash, actual_hash in summary.files_error:
        if force_update:
            print(f"U {filename} updated")
        else:
            print(f"E {filename} mismatch, expected {expected_hash[:8]}, computed {actual_hash[:8]}")
    for filename in summary.files_missing:
        if force_update:
            print(f"R {filename} removed from baseline")
        else:
            print(f"D {filename} missing")
    for filename in summary.files_ignored:
        if force_update:
            print(f"R {filename} removed from baseline")
        else:
            print(f"I {filename} ignored but in database")

    print(f"{summary.file_count} files checked")
    error_count = len(summary.files_error) + len(summary.files_missing) + len(summary.files_ignored)
    if error_count and not force_update:
        print(f"{error_count} error(s) detected")
        raise click.exceptions.Exit(1)
    print("baseline updated" if force_update else "no errors detected")


def run_scan(directory: Path, database: Path, force_update: bool) -> None:
    """Check a directory tree against its SQLite SHA-256 baseline."""
    scan_root = directory.resolve()
    database_path = (database if database.is_absolute() else scan_root / database).resolve()
    exclude_filter = ExcludeFilter(scan_root)
    filenames = collect_files(scan_root, exclude_filter)
    stored_hashes = read_stored_hashes(database_path)
    computed_hashes = hash_scan_files(filenames)
    results, entries, scanned_paths = build_scan_results(
        filenames,
        scan_root,
        stored_hashes,
        computed_hashes,
    )

    summary = summarize_scan_results(results, stored_hashes, scanned_paths, exclude_filter)
    files_to_remove = summary.files_missing + summary.files_ignored
    save_scan_results(database_path, entries, stored_hashes, files_to_remove, force_update)

    report_results(summary, force_update)


@click.command()
@click.option(
    "--directory",
    "-d",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default="current working directory",
    help="Directory tree to scan.",
)
@click.option(
    "--database",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    default=DATABASE_FILE,
    show_default=True,
    help="SQLite database file to use; relative paths are based on the scan directory.",
)
@click.option(
    "--force-update",
    is_flag=True,
    help="Update mismatched hashes and remove missing files from the baseline.",
)
def main(directory: Path, database: Path, force_update: bool) -> None:
    """Run the scan and print its total elapsed time."""
    start_time = time.perf_counter()
    try:
        run_scan(directory, database, force_update)
    finally:
        elapsed_seconds = int(time.perf_counter() - start_time)
        minutes, seconds = divmod(elapsed_seconds, 60)
        print(f"Elapsed: {minutes:02d}m{seconds:02d}s")


if __name__ == "__main__":
    main.main()
