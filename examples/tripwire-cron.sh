#!/bin/bash
# Tripwire hourly cron job
# Install: sudo cp tripwire-cron.sh /etc/cron.hourly/tripwire-analysis && sudo chmod +x /etc/cron.hourly/tripwire-analysis

# Configuration
TRIPWIRE_DIR="/opt/tripwire"
LOG_FILE="/var/log/auth.log"
OUTPUT_DIR="/var/log/tripwire"
BLOCKLIST="/var/lib/tripwire/blocklist.txt"
WHITELIST="/etc/tripwire/whitelist.txt"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$BLOCKLIST")"

# Run Tripwire analysis
/usr/bin/python3 "$TRIPWIRE_DIR/main.py" \
  --log-file "$LOG_FILE" \
  --non-interactive \
  --export-csv "$OUTPUT_DIR/tripwire_$(date +%Y%m%d_%H).csv" \
  --export-blocklist "$BLOCKLIST" \
  --whitelist "$WHITELIST" \
  --blocklist-threshold HIGH \
  >> "$OUTPUT_DIR/tripwire.log" 2>&1

# Optional: Rotate old CSV files (keep last 7 days)
find "$OUTPUT_DIR" -name "tripwire_*.csv" -mtime +7 -delete
