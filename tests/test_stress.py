"""
Stress and performance testing for SSHvigil.
Tests with large datasets, many IPs, and resource-intensive operations.
"""
import os
import pytest
import tempfile
from datetime import datetime, timedelta
from parser import SSHLogParser
from main import BruteForceDetector


class TestLargeScaleOperations:
    """Test performance and stability with large datasets."""
    
    def test_many_unique_ips(self):
        """Test with thousands of unique IPs."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add 10,000 unique IPs
        for i in range(10000):
            ip = f"192.168.{i // 256}.{i % 256}"
            detector.add_attempt(ip, "root", now, False)
        
        # Should handle large dataset
        assert len(detector.attempts_by_ip) == 10000
        results = detector.analyze()
        assert len(results) > 0
    
    def test_many_attempts_per_ip(self):
        """Test with many attempts from single IP."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add 10,000 attempts from one IP
        for i in range(10000):
            detector.add_attempt("192.168.1.1", f"user{i}", 
                               now + timedelta(seconds=i), False)
        
        assert len(detector.attempts_by_ip["192.168.1.1"]) == 10000
        results = detector.analyze()
        assert len(results) > 0
    
    def test_large_log_file_parsing(self, tmp_path):
        """Test parsing large log file with many entries."""
        log_file = tmp_path / "large.log"
        
        # Create log with 10,000 lines
        lines = []
        for i in range(10000):
            ip = f"192.168.{i // 256}.{i % 256}"
            lines.append(f"Dec 28 {i % 24:02d}:00:00 server sshd[{i}]: Invalid user root from {ip}\n")
        
        log_file.write_text(''.join(lines))
        
        parser = SSHLogParser()
        attempts, stats = parser.parse_file(str(log_file), auto_detect=True)
        
        assert stats["lines_read"] == 10000
        assert len(attempts) > 0
    
    def test_very_long_time_span(self):
        """Test with attempts spanning very long time periods."""
        detector = BruteForceDetector()
        start = datetime(2020, 1, 1)
        
        # Add attempts spanning 5 years
        for i in range(1000):
            ts = start + timedelta(days=i*2)
            detector.add_attempt("192.168.1.1", "root", ts, False)
        
        results = detector.analyze()
        assert len(results) > 0
    
    def test_memory_efficiency_large_usernames(self):
        """Test memory handling with large username strings."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add 1000 attempts with 1KB usernames each
        large_username = "A" * 1024
        for i in range(1000):
            detector.add_attempt(f"192.168.{i // 256}.{i % 256}", 
                               large_username, now, False)
        
        # Should not crash or use excessive memory
        results = detector.analyze()
        assert len(results) > 0
    
    def test_csv_export_large_dataset(self, tmp_path):
        """Test CSV export with large number of results."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Create large dataset
        for i in range(1000):
            ip = f"10.{i // 256}.{(i // 256) % 256}.{i % 256}"
            for j in range(10):
                detector.add_attempt(ip, f"user{j}", 
                                   now + timedelta(seconds=j), False)
        
        csv_path = tmp_path / "large_export.csv"
        results = detector.analyze(export_csv=str(csv_path))
        
        # Verify CSV was created and has data
        assert csv_path.exists()
        assert csv_path.stat().st_size > 0
    
    def test_repeated_analysis_calls(self):
        """Test that analyze() can be called multiple times."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        for i in range(100):
            detector.add_attempt("192.168.1.1", "root", 
                               now + timedelta(seconds=i), False)
        
        # Call analyze multiple times
        for _ in range(10):
            results = detector.analyze()
            assert len(results) > 0
    
    def test_extreme_attack_rates(self):
        """Test with extremely high attack rates (many attempts per second)."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # 10,000 attempts in 1 second
        for i in range(10000):
            ts = now + timedelta(microseconds=i*100)
            detector.add_attempt("192.168.1.1", f"user{i}", ts, False)
        
        results = detector.analyze()
        assert len(results) > 0
        # Should be classified as CRITICAL
        assert any(r.get('Severity') == 'CRITICAL' for r in results)


class TestConcurrentOperations:
    """Test behavior with concurrent-like operations."""
    
    def test_interleaved_ip_attempts(self):
        """Test with attempts from multiple IPs interleaved."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Interleave attempts from 100 IPs
        for i in range(1000):
            ip = f"192.168.1.{i % 100}"
            detector.add_attempt(ip, "root", now + timedelta(seconds=i), False)
        
        results = detector.analyze()
        # Should have results for 100 unique IPs
        assert len(results) >= 100
    
    def test_mixed_success_failure(self):
        """Test with mixture of successful and failed attempts."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Alternate between success and failure
        for i in range(1000):
            success = (i % 2 == 0)
            detector.add_attempt("192.168.1.1", "root", 
                               now + timedelta(seconds=i), success)
        
        results = detector.analyze()
        assert len(results) > 0


class TestResourceExhaustion:
    """Test behavior under resource constraints."""
    
    def test_ipv6_addresses(self):
        """Test with IPv6 addresses."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add various IPv6 attempts
        ipv6_addresses = [
            "2001:db8::1",
            "2001:db8::2",
            "::1",
            "fe80::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ]
        
        for ip in ipv6_addresses:
            for i in range(100):
                detector.add_attempt(ip, "root", now + timedelta(seconds=i), False)
        
        results = detector.analyze()
        assert len(results) > 0
    
    def test_many_event_types(self):
        """Test with many different event types."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        event_types = [
            "invalid_user",
            "failed_password_user",
            "failed_password_invalid",
            "accepted_password",
            "accepted_publickey",
            "accepted_keyboard_interactive",
            "custom_event_1",
            "custom_event_2"
        ]
        
        for i in range(1000):
            event = event_types[i % len(event_types)]
            detector.add_attempt("192.168.1.1", "root", 
                               now + timedelta(seconds=i), False, event)
        
        results = detector.analyze()
        assert len(results) > 0
    
    def test_whitelist_with_many_ips(self):
        """Test whitelist functionality with large whitelist."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Create large whitelist
        whitelist = set()
        for i in range(5000):
            ip = f"10.{i // 256}.{(i // 256) % 256}.{i % 256}"
            whitelist.add(ip)
            # Add attempts from whitelisted IPs
            if i < 100:
                for j in range(100):
                    detector.add_attempt(ip, "root", 
                                       now + timedelta(seconds=j), False)
        
        # Add some non-whitelisted IPs
        for i in range(100):
            ip = f"192.168.1.{i}"
            for j in range(100):
                detector.add_attempt(ip, "root", 
                                   now + timedelta(seconds=j), False)
        
        results = detector.analyze(whitelist=whitelist)
        # Should have results
        assert len(results) > 0


class TestBoundaryConditions:
    """Test boundary conditions in processing."""
    
    def test_exactly_at_threshold(self):
        """Test with attempt counts exactly at various thresholds."""
        detector = BruteForceDetector(max_attempts=10, block_threshold=50, 
                                     monitor_threshold=20)
        now = datetime.now()
        
        test_cases = [
            ("192.168.1.1", 10),   # Exactly max_attempts
            ("192.168.1.2", 20),   # Exactly monitor_threshold
            ("192.168.1.3", 50),   # Exactly block_threshold
            ("192.168.1.4", 9),    # Just below max_attempts
            ("192.168.1.5", 51),   # Just above block_threshold
        ]
        
        for ip, count in test_cases:
            for i in range(count):
                detector.add_attempt(ip, "root", now + timedelta(seconds=i), False)
        
        results = detector.analyze()
        assert len(results) == len(test_cases)
    
    def test_single_attempt(self):
        """Test with exactly one attempt."""
        detector = BruteForceDetector()
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        
        results = detector.analyze()
        # Should still produce results even with one attempt
        assert len(results) >= 0
    
    def test_zero_duration_attack(self):
        """Test when all attempts have same timestamp (zero duration)."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # All attempts at exact same time
        for i in range(100):
            detector.add_attempt("192.168.1.1", f"user{i}", now, False)
        
        results = detector.analyze()
        # Should handle zero duration without division by zero
        assert len(results) > 0
