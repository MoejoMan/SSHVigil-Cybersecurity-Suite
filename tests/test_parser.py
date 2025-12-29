import os
from datetime import datetime
import pytest

from parser import SSHLogParser


def fixture_path(name: str) -> str:
    here = os.path.dirname(__file__)
    return os.path.join(here, "fixtures", name)


def test_parse_valid_log():
    parser = SSHLogParser()
    attempts, stats = parser.parse_file(fixture_path("auth.log"), auto_detect=True)
    assert stats["lines_read"] == 4
    assert stats["format_matches"] > 0
    assert len(attempts) >= 3
    # Ensure an invalid user event is captured
    invalid = [a for a in attempts if a[0] == "192.0.2.10" and a[4] == "invalid_user"]
    assert invalid


def test_empty_log_returns_warning(capsys):
    parser = SSHLogParser()
    attempts, stats = parser.parse_file(fixture_path("empty.log"), auto_detect=True)
    assert attempts == []
    assert stats["lines_read"] == 0
    captured = capsys.readouterr()
    assert "empty" in captured.out.lower()


def test_bad_timestamp_is_counted_in_failed(capsys):
    parser = SSHLogParser()
    attempts, stats = parser.parse_file(fixture_path("invalid_timestamp.log"), auto_detect=True)
    assert stats["failed_timestamps"] >= 1
    captured = capsys.readouterr()
    # No attempts extracted due to bad timestamp
    assert attempts == []
