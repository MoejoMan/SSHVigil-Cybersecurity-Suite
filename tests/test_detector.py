from datetime import datetime, timedelta

from main import BruteForceDetector


def test_classify_threat_levels():
    detector = BruteForceDetector(max_attempts=5, time_window_minutes=10, block_threshold=50, monitor_threshold=20)
    short_window = timedelta(minutes=5)
    long_window = timedelta(minutes=60)

    # Rapid, high volume
    assert detector.classify_threat(total_attempts=10, attack_rate=3.0, duration=short_window) == "CRITICAL"
    # Short burst but lower rate
    assert detector.classify_threat(total_attempts=6, attack_rate=1.5, duration=short_window) == "HIGH"
    # Persistent high volume
    assert detector.classify_threat(total_attempts=60, attack_rate=0.5, duration=long_window) == "HIGH"
    # Moderate volume
    assert detector.classify_threat(total_attempts=25, attack_rate=0.5, duration=long_window) == "MEDIUM"
    # Elevated rate
    assert detector.classify_threat(total_attempts=4, attack_rate=1.2, duration=long_window) == "MEDIUM"
    # Meets max_attempts threshold
    assert detector.classify_threat(total_attempts=5, attack_rate=0.2, duration=long_window) == "LOW"


def test_add_attempt_accumulates_and_orders():
    detector = BruteForceDetector()
    now = datetime.now()
    detector.add_attempt("192.0.2.10", "root", now, False, "invalid_user")
    detector.add_attempt("192.0.2.10", "root", now + timedelta(seconds=30), False, "failed_password_user")
    assert len(detector.attempts_by_ip["192.0.2.10"]) == 2
    # Ensure timestamps are stored correctly
    timestamps = [a["timestamp"] for a in detector.attempts_by_ip["192.0.2.10"]]
    assert min(timestamps) == now
