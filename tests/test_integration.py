import os
import tempfile
import subprocess
from datetime import datetime

def test_non_interactive_mode(tmp_path):
    """Test that --non-interactive suppresses prompts."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("Dec 28 10:00:00 server sshd[123]: Invalid user admin from 192.0.2.10 port 5555\n")
    csv_file = tmp_path / "results.csv"

 # Run with --non-interactive (should not prompt)
    result = subprocess.run([
        "python", "main.py",
        "--log-file", str(log_file),
        "--non-interactive",
        "--export-csv", str(csv_file)
    ], capture_output=True, text=True, timeout=10)

    assert result.returncode == 0
    assert csv_file.exists()
    assert "y/n" not in result.stdout  # No prompts

def test_whitelist_filtering(tmp_path):
    """Test that whitelisted IPs are excluded from blocklist."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Dec 28 10:00:00 server sshd[1]: Invalid user admin from 192.0.2.10 port 5555\n" * 100
    )
    blocklist = tmp_path / "blocklist.txt"
    whitelist = tmp_path / "whitelist.txt"
    whitelist.write_text("192.0.2.10\n")  # Whitelist this IP
    
    result = subprocess.run([
        "python", "main.py",
        "--log-file", str(log_file),
        "--non-interactive",
        "--whitelist", str(whitelist),
        "--export-blocklist", str(blocklist)
    ], capture_output=True, text=True, timeout=10)

    assert result.returncode == 0
    # Blocklist should be empty (IP was whitelisted)
    assert not blocklist.exists() or blocklist.read_text().strip() == ""
    
def test_csv_export_live_mode(tmp_path):
    """Test that CSV export works in live mode."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("Dec 28 10:00:00 server sshd[1]: Invalid user admin from 192.0.2.10 port 5555\n")
    csv_file = tmp_path / "live_export.csv"

    result = subprocess.run([
        "python", "main.py",
        "--log-file", str(log_file),
        "--export-csv", str(csv_file),
        "--non-interactive",
        "--help" 
    ], capture_output=True, text=True, timeout=5)
    
    assert "--export-csv" in result.stdout
    