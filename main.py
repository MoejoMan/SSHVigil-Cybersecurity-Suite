import re
import sys
import os
import tkinter as tk
from collections import defaultdict
from datetime import datetime, timedelta
from tkinter import filedialog

class BruteForceDetector:
    """
    Analyzes SSH authentication logs to detect brute-force behaviour.
    """

    def __init__(self, max_attempts=5, time_window_minutes=10):
        self.max_attempts = max_attempts
        self.time_window = timedelta(minutes=time_window_minutes)

        # will store parsed attempts grouped by IP
        # Example:
        # {
        #   "92.118.39.62": [
        #       {"username": "root", "timestamp": datetime, "success": False},
        #       ...
        #   ]
        # }
        self.attempts_by_ip = defaultdict(list)

    def add_attempt(self, ip_address, username, timestamp, success):
        """
        Add a parsed SSH login attempt.
        This method will be called AFTER log parsing.
        """
        self.attempts_by_ip[ip_address].append({
            "username": username,
            "timestamp": timestamp,
            "success": success
        })

    def analyze(self):
        """
        Analyze collected attempts and classify behaviour.
        Returns analysis results instead of enforcing actions.
        """
        THRESHOLD = self.max_attempts
        summary = defaultdict(lambda: defaultdict(int))

        for ip, attempts in self.attempts_by_ip.items():
            for attempt in attempts:
                username = attempt['username']
                summary[ip][username] += 1

        sorted_ips = sorted(summary.items(), key=lambda x: sum(x[1].values()), reverse=True)

        print("\nAttempt Summary:")
        for ip, usernames in sorted_ips:
            total_attempts = sum(usernames.values())

            attempts = self.attempts_by_ip[ip]

            print(f"IP: {ip}, Attempts: {total_attempts}")
            print(f"Username counts: {dict(usernames)}")

            if attempts:
                timestamps = [att['timestamp'] for att in attempts]
                first = min(timestamps)
                last = max(timestamps)
                duration = last - first

                total_seconds = int(duration.total_seconds())
                hours, remainder = divmod(total_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                if hours:
                    duration_str = f"{hours}h {minutes}m {seconds}s"
                else:
                    duration_str = f"{minutes}m {seconds}s"

                print(f"Attack window: {first.strftime('%Y-%m-%d %H:%M:%S')} → {last.strftime('%H:%M:%S')} (duration: {duration_str})")

            if total_attempts >= THRESHOLD:
                print(f"Action: Block IP {ip} due to excessive failed attempts.")
            print("-" * 60)  

def main():
    print("SSH Brute Force Log Analyzer")
    print("=" * 40)
    tk.Tk().withdraw()

    log_path = filedialog.askopenfilename(
        title="Select your auth.log file",
        filetypes=[("Log files", "*.log"), ("All files", "*.*")]
    )

    possible_paths = [
        "/var/log/auth.log",        
        "/var/log/secure",           
        "auth.log",                  
        "C:\\Users\\jhg56\\Downloads\\auth.log",  
    ]

    log_path = None
    for path in possible_paths:
        if os.path.exists(path):
            log_path = path
            print(f"Found log file at: {log_path}")
            input("Do you want to use this file? Press Enter to confirm or Ctrl+C to cancel.")
            break

    if log_path is None:
        print("Error: No common auth.log file found.")
        print("Try placing it in the current folder or specify manually later.")
        sys.exit(1)
    print(f"Using log file: {log_path}")

    detector = BruteForceDetector()
    main_pattern = re.compile(r'^\d{4}-\d{1,2}-\d{1,2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\]):\s+(?P<info>.*)$')
    extract_pattern = re.compile(r'Invalid user (\S+) from ([\d.]+)')

    line_count = 0
    main_matches = 0
    extract_matches = 0
    samples = []
    
    with open(log_path, 'r') as log_file:
        for line in log_file:
            line_count += 1
            main_match = main_pattern.search(line)
            if main_match:
                main_matches += 1
                info = main_match.group('info')
                timestamp_str = line.split(' ', 1)[0]
                timestamp_str = timestamp_str.replace('Z', '+00:00') 
                timestamp = datetime.fromisoformat(timestamp_str)

                if info:
                    extract_match = extract_pattern.search(info)
                else:
                    extract_match = None
                if extract_match:
                    extract_matches += 1
                    username = extract_match.group(1)
                    ip = extract_match.group(2)
                    detector.add_attempt(ip, username, timestamp, False)
                    if len(samples) < 5:
                        samples.append((ip, username, timestamp, info))
    
    print(f"\nProcessing stats:")
    print(f"Lines read: {line_count}, Main pattern matches: {main_matches}, Extract matches: {extract_matches}")
    print(f"\nSample matches (first 5):")
    for ip, username, timestamp, info in samples:
        print(f"  Time: {timestamp}, IP: {ip}, Username: {username}, Info: {info[:80]}")
    print()
    detector.analyze()

if __name__ == "__main__":
    main()