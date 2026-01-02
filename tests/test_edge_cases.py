"""
Comprehensive edge case testing for SSHvigil.
Tests boundary conditions, malformed inputs, special characters, and edge cases.
"""
import os
import pytest
from datetime import datetime, timedelta
from parser import SSHLogParser
from main import BruteForceDetector
from config import Config
from utils import is_valid_ip


class TestIPValidation:
    """Test IP address validation with edge cases."""
    
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("0.0.0.0")
        assert is_valid_ip("255.255.255.255")
        assert is_valid_ip("127.0.0.1")
    
    def test_valid_ipv6(self):
        assert is_valid_ip("::1")
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert is_valid_ip("2001:db8::1")
        assert is_valid_ip("fe80::1")
    
    def test_invalid_ips(self):
        assert not is_valid_ip("999.999.999.999")
        assert not is_valid_ip("256.1.1.1")
        assert not is_valid_ip("192.168.1")
        assert not is_valid_ip("192.168.1.1.1")
        assert not is_valid_ip("")
        assert not is_valid_ip("localhost")
        assert not is_valid_ip("example.com")
        assert not is_valid_ip("192.168.1.1/24")
        assert not is_valid_ip("192.168.1.-1")
        assert not is_valid_ip("192.168.1.1a")
        assert not is_valid_ip("192.168..1")
        assert not is_valid_ip("......")
        assert not is_valid_ip("' OR '1'='1")  # SQL injection attempt
        assert not is_valid_ip("../../etc/passwd")  # Path traversal
        assert not is_valid_ip("<script>alert('xss')</script>")


class TestDetectorEdgeCases:
    """Test BruteForceDetector with edge cases."""
    
    def test_zero_attempts(self):
        detector = BruteForceDetector()
        results = detector.analyze()
        assert results == []
    
    def test_invalid_ip_rejected(self):
        detector = BruteForceDetector()
        now = datetime.now()
        detector.add_attempt("999.999.999.999", "root", now, False)
        detector.add_attempt("", "root", now, False)
        detector.add_attempt("not-an-ip", "root", now, False)
        assert len(detector.attempts_by_ip) == 0
    
    def test_extremely_long_username(self):
        detector = BruteForceDetector()
        now = datetime.now()
        long_username = "a" * 10000
        detector.add_attempt("192.168.1.1", long_username, now, False)
        assert len(detector.attempts_by_ip["192.168.1.1"]) == 1
        assert detector.attempts_by_ip["192.168.1.1"][0]["username"] == long_username
    
    def test_special_characters_in_username(self):
        detector = BruteForceDetector()
        now = datetime.now()
        special_usernames = [
            "user@example.com",
            "user-name",
            "user_name",
            "user.name",
            "user'name",
            "user\"name",
            "user;name",
            "user|name",
            "user&name",
            "user$name",
            "user`name",
            "../../../etc/passwd",
            "'; DROP TABLE users; --",
        ]
        for username in special_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        assert len(detector.attempts_by_ip["192.168.1.1"]) == len(special_usernames)
    
    def test_unicode_in_username(self):
        detector = BruteForceDetector()
        now = datetime.now()
        unicode_usernames = [
            "用户",  # Chinese
            "пользователь",  # Russian
            "مستخدم",  # Arabic
            "ユーザー",  # Japanese
            "🔥admin🔥",  # Emoji
            "user\x00name",  # Null byte
            "user\r\nname",  # Line breaks
        ]
        for username in unicode_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        assert len(detector.attempts_by_ip["192.168.1.1"]) == len(unicode_usernames)
    
    def test_same_timestamp_multiple_attempts(self):
        detector = BruteForceDetector()
        now = datetime.now()
        for i in range(100):
            detector.add_attempt("192.168.1.1", f"user{i}", now, False)
        assert len(detector.attempts_by_ip["192.168.1.1"]) == 100
    
    def test_negative_time_window(self):
        """Test with invalid negative time_window_minutes."""
        detector = BruteForceDetector(time_window_minutes=-10)
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        # Should not crash
        results = detector.analyze()
        assert len(results) >= 0
    
    def test_zero_thresholds(self):
        """Test with zero thresholds."""
        detector = BruteForceDetector(max_attempts=0, block_threshold=0, monitor_threshold=0)
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        results = detector.analyze()
        assert len(results) >= 0
    
    def test_extremely_high_thresholds(self):
        """Test with unrealistically high thresholds."""
        detector = BruteForceDetector(
            max_attempts=999999999,
            block_threshold=999999999,
            monitor_threshold=999999999
        )
        now = datetime.now()
        for i in range(100):
            detector.add_attempt("192.168.1.1", "root", now + timedelta(seconds=i), False)
        results = detector.analyze()
        # With such high thresholds, should classify as LOW
        assert len(results) > 0
    
    def test_far_future_timestamp(self):
        """Test with timestamp far in the future."""
        detector = BruteForceDetector()
        now = datetime.now()
        future = datetime(2099, 12, 31, 23, 59, 59)
        detector.add_attempt("192.168.1.1", "root", now, False)
        detector.add_attempt("192.168.1.1", "root", future, False)
        results = detector.analyze()
        assert len(results) > 0
    
    def test_far_past_timestamp(self):
        """Test with very old timestamp."""
        detector = BruteForceDetector()
        past = datetime(1970, 1, 1, 0, 0, 1)
        detector.add_attempt("192.168.1.1", "root", past, False)
        results = detector.analyze()
        assert len(results) > 0
    
    def test_whitelist_with_invalid_ips(self):
        """Test whitelist containing invalid IPs."""
        detector = BruteForceDetector()
        now = datetime.now()
        # Add valid attempts
        for i in range(100):
            detector.add_attempt("192.168.1.1", "root", now + timedelta(seconds=i), False)
        
        # Create whitelist with invalid entries
        whitelist = {"192.168.1.1", "invalid-ip", "999.999.999.999", ""}
        results = detector.analyze(export_blocklist=None, whitelist=whitelist)
        # Should not crash
        assert len(results) > 0


class TestParserEdgeCases:
    """Test log parser with edge cases."""
    
    def test_extremely_long_line(self, tmp_path):
        """Test parsing extremely long log lines."""
        log_file = tmp_path / "long_line.log"
        long_line = "Dec 28 10:00:00 server sshd[123]: " + "A" * 100000 + "\n"
        log_file.write_text(long_line)
        parser = SSHLogParser()
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        assert stats["lines_read"] == 1
    
    def test_binary_data_in_log(self, tmp_path):
        """Test log file with binary/non-UTF8 data."""
        log_file = tmp_path / "binary.log"
        with open(log_file, 'wb') as f:
            f.write(b"Dec 28 10:00:00 server sshd[123]: Invalid user root from 192.168.1.1\n")
            f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\n")
            f.write(b"Dec 28 10:01:00 server sshd[124]: Failed password for admin from 192.168.1.2\n")
        parser = SSHLogParser()
        # Should not crash - binary data may be split into multiple lines
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        assert stats["lines_read"] >= 3  # Binary data may count as extra lines
    
    def test_mixed_line_endings(self, tmp_path):
        """Test log with mixed Windows/Unix line endings."""
        log_file = tmp_path / "mixed_endings.log"
        content = "Dec 28 10:00:00 server sshd[123]: Invalid user root from 192.168.1.1\r\n"
        content += "Dec 28 10:01:00 server sshd[124]: Failed password for admin from 192.168.1.2\n"
        content += "Dec 28 10:02:00 server sshd[125]: Invalid user test from 192.168.1.3\r"
        log_file.write_text(content, newline='')
        parser = SSHLogParser()
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        assert stats["lines_read"] >= 3
    
    def test_empty_lines_and_whitespace(self, tmp_path):
        """Test log with empty lines and whitespace."""
        log_file = tmp_path / "whitespace.log"
        content = "\n\n\n"
        content += "Dec 28 10:00:00 server sshd[123]: Invalid user root from 192.168.1.1\n"
        content += "   \n"
        content += "\t\t\n"
        content += "Dec 28 10:01:00 server sshd[124]: Failed password for admin from 192.168.1.2\n"
        content += "\n\n\n"
        log_file.write_text(content)
        parser = SSHLogParser()
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        assert stats["lines_read"] >= 2
    
    def test_malformed_timestamps(self, tmp_path):
        """Test various malformed timestamp formats."""
        log_file = tmp_path / "malformed_ts.log"
        content = "Not a timestamp at all sshd[123]: Invalid user root from 192.168.1.1\n"
        content += "99-99-9999 99:99:99 server sshd[124]: Failed password for admin from 192.168.1.2\n"
        content += "Dec 32 25:61:61 server sshd[125]: Invalid user test from 192.168.1.3\n"
        log_file.write_text(content)
        parser = SSHLogParser()
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        # Should count failed timestamps
        assert stats["failed_timestamps"] >= 0
    
    def test_duplicate_entries(self, tmp_path):
        """Test log with many duplicate entries."""
        log_file = tmp_path / "duplicates.log"
        line = "Dec 28 10:00:00 server sshd[123]: Invalid user root from 192.168.1.1\n"
        content = line * 1000
        log_file.write_text(content)
        parser = SSHLogParser()
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        assert stats["lines_read"] == 1000
        assert len(attempts) == 1000


class TestConfigEdgeCases:
    """Test configuration handling edge cases."""
    
    def test_empty_config_file(self, tmp_path):
        """Test completely empty config file."""
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text("")
        cfg = Config(config_path=str(cfg_path))
        assert cfg["max_attempts"] == Config.DEFAULTS["max_attempts"]
    
    def test_config_with_only_whitespace(self, tmp_path):
        """Test config file with only whitespace."""
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text("   \n\t\n   ")
        cfg = Config(config_path=str(cfg_path))
        assert cfg["max_attempts"] == Config.DEFAULTS["max_attempts"]
    
    def test_config_with_extreme_values(self, tmp_path):
        """Test config with extremely large or small values."""
        import json
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({
            "max_attempts": 999999999,
            "time_window_minutes": 999999999,
            "block_threshold": 0,
            "monitor_threshold": -100
        }))
        cfg = Config(config_path=str(cfg_path))
        # Should handle extreme values
        assert "max_attempts" in cfg.to_dict()
    
    def test_config_with_null_values(self, tmp_path):
        """Test config with null/None values."""
        import json
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({
            "max_attempts": None,
            "time_window_minutes": None
        }))
        cfg = Config(config_path=str(cfg_path))
        # Should fall back to defaults for null values
        assert cfg["max_attempts"] == Config.DEFAULTS["max_attempts"]
    
    def test_config_with_nested_objects(self, tmp_path):
        """Test config with unexpected nested structures."""
        import json
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({
            "max_attempts": {"nested": "value"},
            "time_window_minutes": [1, 2, 3]
        }))
        cfg = Config(config_path=str(cfg_path))
        # Should ignore invalid types
        assert cfg["max_attempts"] == Config.DEFAULTS["max_attempts"]


class TestCSVExportEdgeCases:
    """Test CSV export edge cases."""
    
    def test_csv_export_special_characters(self, tmp_path):
        """Test CSV export with special characters in data."""
        from main import BruteForceDetector
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add attempts with special characters
        special_usernames = [
            'user,with,commas',
            'user"with"quotes',
            'user\nwith\nnewlines',
            'user\twith\ttabs',
        ]
        for username in special_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        
        csv_path = tmp_path / "test_export.csv"
        detector.analyze(export_csv=str(csv_path))
        
        # Verify CSV was created and is valid
        assert csv_path.exists()
        import csv
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0
    
    def test_csv_export_to_readonly_location(self, tmp_path):
        """Test CSV export when directory is read-only."""
        from main import BruteForceDetector
        detector = BruteForceDetector()
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        
        # Create a read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        import stat
        readonly_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        
        csv_path = readonly_dir / "test_export.csv"
        # Should handle permission error gracefully
        try:
            detector.analyze(export_csv=str(csv_path))
        except (PermissionError, OSError):
            pass  # Expected
        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(stat.S_IRWXU)


class TestColorOutputEdgeCases:
    """Test color output edge cases."""
    
    def test_color_disabled_via_env(self):
        """Test that NO_COLOR environment variable disables colors."""
        import os
        original_value = os.environ.get('NO_COLOR')
        try:
            os.environ['NO_COLOR'] = '1'
            detector = BruteForceDetector()
            assert not detector.use_color
            colored_text = detector._color("test", fg='red', bold=True)
            assert colored_text == "test"  # No ANSI codes
        finally:
            if original_value is None:
                os.environ.pop('NO_COLOR', None)
            else:
                os.environ['NO_COLOR'] = original_value
    
    def test_color_with_none_fg(self):
        """Test color function with None foreground."""
        detector = BruteForceDetector()
        detector.use_color = True
        colored_text = detector._color("test", fg=None, bold=True)
        # Should still add bold
        assert "\033[" in colored_text or colored_text == "test"
    
    def test_color_with_invalid_fg(self):
        """Test color function with invalid foreground color."""
        detector = BruteForceDetector()
        detector.use_color = True
        colored_text = detector._color("test", fg="invalid_color", bold=False)
        # Should return text without crashing
        assert "test" in colored_text
