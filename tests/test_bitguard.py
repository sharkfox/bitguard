"""Tests for Bitguard's scanning and baseline behavior."""

# pylint: disable=redefined-outer-name

import hashlib
import re
import runpy
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from click.testing import CliRunner

import bitguard
from bitguard import ExcludeFilter, collect_files, main


class InlinePool:
    """Run pool tasks synchronously to keep command tests lightweight."""

    def __enter__(self):
        """Enter the pool context."""
        return self

    def __exit__(self, *exc_info):
        """Exit the pool context."""
        return False

    def imap_unordered(self, function, values):
        """Apply a function to values without multiprocessing."""
        return map(function, values)


@contextmanager
def open_database(database: Path) -> Iterator[sqlite3.Connection]:
    """Open a SQLite transaction and close its connection afterward."""
    connection = sqlite3.connect(database)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


@pytest.fixture
def invoke_tool(monkeypatch):
    """Return a CLI runner using the inline pool."""
    monkeypatch.setattr(bitguard.multiprocessing, "Pool", InlinePool)

    def invoke(directory: Path, database: Path, force_update: bool = False):
        """Invoke the CLI on a scan directory and database."""
        arguments = ["--directory", str(directory), "--database", str(database)]
        if force_update:
            arguments.append("--force-update")
        return CliRunner().invoke(main, arguments)

    return invoke


def create_checksum_fixture(temp_dir: Path, content: bytes, expected_hash: str):
    """Create a scan directory and a database with one expected hash."""
    root = temp_dir / "scan"
    root.mkdir()
    (root / ".bitguardignore").write_text(".bitguardignore\n", encoding="utf-8")
    target = root / "sample.txt"
    target.write_bytes(content)
    database = temp_dir / "baseline.sqlite"
    with open_database(database) as connection:
        connection.execute("CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO files (path, sha256) VALUES (?, ?)",
            (target.name, expected_hash),
        )
    return root, target, database


def test_ignore_file_supports_globs_directories_and_negation(tmp_path):
    """Apply Git-ignore glob, directory, and negation patterns."""
    (tmp_path / ".bitguardignore").write_text(
        ".bitguardignore\n*.tmp\n!important.tmp\ncache/\nparent/*\n!parent/keep.txt\n",
        encoding="utf-8",
    )
    (tmp_path / "remove.tmp").touch()
    (tmp_path / "important.tmp").touch()
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "hidden.txt").touch()
    (tmp_path / "parent").mkdir()
    (tmp_path / "parent" / "hidden.txt").touch()
    (tmp_path / "parent" / "keep.txt").touch()

    collected = {
        Path(filename).relative_to(tmp_path).as_posix() for filename in collect_files(tmp_path, ExcludeFilter(tmp_path))
    }

    assert collected == {"important.tmp", "parent/keep.txt"}


def test_matching_checksum_passes(tmp_path, invoke_tool):
    """Return success when the current hash matches the baseline."""
    content = b"unchanged file contents"
    expected_hash = hashlib.sha256(content).hexdigest()
    root, _, database = create_checksum_fixture(tmp_path, content, expected_hash)

    result = invoke_tool(root, database)

    assert result.exit_code == 0, result.output
    assert "no errors detected" in result.output
    assert "E " not in result.output
    assert re.search(r"Elapsed: \d{2}m\d{2}s", result.output)


def test_mismatched_checksum_fails(tmp_path, invoke_tool):
    """Report a checksum mismatch and return an error exit code."""
    content = b"changed file contents"
    expected_hash = hashlib.sha256(b"previous file contents").hexdigest()
    actual_hash = hashlib.sha256(content).hexdigest()
    root, target, database = create_checksum_fixture(tmp_path, content, expected_hash)

    result = invoke_tool(root, database)

    assert result.exit_code == 1, result.output
    assert f"E {target} mismatch, expected {expected_hash[:8]}, computed {actual_hash[:8]}" in result.output
    assert re.search(r"Elapsed: \d{2}m\d{2}s", result.output)


def test_deleted_tracked_file_is_reported_as_an_error(tmp_path, invoke_tool):
    """Report baseline paths that are absent from the scan."""
    root = tmp_path / "scan"
    root.mkdir()
    (root / ".bitguardignore").write_text(".bitguardignore\n", encoding="utf-8")
    database = tmp_path / "baseline.sqlite"
    with open_database(database) as connection:
        connection.execute("CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO files (path, sha256) VALUES (?, ?)",
            ("removed.txt", "a" * 64),
        )

    result = invoke_tool(root, database)

    assert result.exit_code == 1, result.output
    assert "D removed.txt missing" in result.output


def test_force_updates_mismatches_and_removes_missing_records(tmp_path, invoke_tool):
    """Update changed hashes and remove missing paths in force mode."""
    root = tmp_path / "scan"
    root.mkdir()
    (root / ".bitguardignore").write_text(".bitguardignore\n", encoding="utf-8")
    target = root / "sample.txt"
    target.write_text("updated contents", encoding="utf-8")
    actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    database = tmp_path / "baseline.sqlite"
    with open_database(database) as connection:
        connection.execute("CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO files (path, sha256) VALUES (?, ?)",
            [(target.name, "a" * 64), ("removed.txt", "b" * 64)],
        )

    result = invoke_tool(root, database, force_update=True)

    assert result.exit_code == 0, result.output
    assert f"U {target} updated" in result.output
    assert "R removed.txt removed from baseline" in result.output
    assert "baseline updated" in result.output
    with open_database(database) as connection:
        stored_hashes = dict(connection.execute("SELECT path, sha256 FROM files"))
    assert stored_hashes == {target.name: actual_hash}


def test_newly_ignored_tracked_file_is_reported_and_kept_in_baseline(tmp_path, invoke_tool):
    """Fail for newly ignored baseline paths without deleting their records."""
    root = tmp_path / "scan"
    root.mkdir()
    (root / ".bitguardignore").write_text(
        ".bitguardignore\nremoved.txt\nuntracked.txt\n",
        encoding="utf-8",
    )
    (root / "untracked.txt").write_text("ignored but not tracked", encoding="utf-8")
    database = tmp_path / "baseline.sqlite"
    with open_database(database) as connection:
        connection.execute("CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO files (path, sha256) VALUES (?, ?)",
            ("removed.txt", "a" * 64),
        )

    result = invoke_tool(root, database)

    assert result.exit_code == 1, result.output
    assert "I removed.txt ignored but in database" in result.output
    assert "untracked.txt" not in result.output
    assert "1 error(s) detected" in result.output
    with open_database(database) as connection:
        stored_paths = [row[0] for row in connection.execute("SELECT path FROM files")]
    assert stored_paths == ["removed.txt"]

    result = invoke_tool(root, database, force_update=True)

    assert result.exit_code == 0, result.output
    assert "R removed.txt removed from baseline" in result.output
    with open_database(database) as connection:
        stored_paths = [row[0] for row in connection.execute("SELECT path FROM files")]
    assert stored_paths == []


def test_custom_database_inside_scan_does_not_change_scan_results(tmp_path, invoke_tool):
    """Keep a custom in-tree database out of the scan when ignored."""
    root = tmp_path / "scan"
    root.mkdir()
    (root / ".bitguardignore").write_text(
        ".bitguardignore\ncustom.sqlite\n",
        encoding="utf-8",
    )
    (root / "sample.txt").write_text("sample", encoding="utf-8")
    database = root / "custom.sqlite"

    results = [invoke_tool(root, database) for _ in range(3)]

    for result in results:
        assert result.exit_code == 0, result.output
        assert "no errors detected" in result.output


def test_script_entrypoint_displays_help(monkeypatch, capsys):
    """Exercise the module's direct-execution entrypoint."""
    monkeypatch.setattr(sys, "argv", ["bitguard", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(Path(bitguard.__file__)), run_name="__main__")

    assert exc_info.value.code == 0
    assert "Usage: bitguard" in capsys.readouterr().out
