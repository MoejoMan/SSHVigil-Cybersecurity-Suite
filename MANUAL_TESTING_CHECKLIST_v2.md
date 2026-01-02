# SSHvigil Manual Testing Checklist - Live & fail2ban Focus

**Core Value Proposition:** SSHvigil is a real-time SSH brute-force threat detector that integrates seamlessly with fail2ban for automated IP blocking. This checklist focuses on realistic deployment scenarios.

## Setup
- [ ] SSH into your VPS
- [ ] Navigate to project directory
- [ ] Activate venv (if using one)
- [ ] Identify your auth log location: `/var/log/auth.log` or `/var/log/secure`
- [ ] Verify you have fail2ban installed (optional, but recommended for full testing)

---

## PART 1: Live Mode Real-Time Monitoring (25 min)
**Why This First:** This is the killer feature. Live mode is what makes SSHvigil stand out—you see threats as they happen.

### 1.1 Basic Live Mode (No Filter)
```bash
# Terminal 1: Start live mode
python3 main.py --log-file /var/log/auth.log --live

# Terminal 2: Generate SSH attempts (simulate attacks)
for i in {1..5}; do ssh baduser@localhost -p 22; done
```
**Check:**
- [x] Live mode starts without errors?
- [x] New SSH attempts appear in real-time (within 1-2 seconds)?
- [x] IPs are detected and severity calculated?
- [x] Output updates every refresh cycle?
- [x] Ctrl+C stops gracefully?

### 1.2 Live Mode with Severity Filter
```bash
# Show only HIGH and CRITICAL threats in real-time
python3 main.py --log-file /var/log/auth.log --live -f HIGH

# In another terminal, simulate more attacks
for i in {1..10}; do ssh -u attacker@localhost; done
```
**Check:**
- [ ] Filter applies to live results?
- [ ] Only HIGH+CRITICAL threats shown?
- [ ] Results update in real-time?
- [ ] Filtered count matches expectations?

### 1.3 Live Mode with Custom Refresh
```bash
# Fast refresh (2 seconds) - useful for dashboards
python3 main.py --log-file /var/log/auth.log --live --refresh 2

# Slow refresh (10 seconds) - resource-light monitoring
python3 main.py --log-file /var/log/auth.log --live --refresh 10
```
**Check:**
- [x] Refresh rate changes as specified?
- [x] Output updates at correct intervals?
- [x] System CPU/memory impact reasonable?

### 1.4 Live Mode Starting from Log Beginning
```bash
# Start from the beginning of the file (useful for fresh analysis)
python3 main.py --log-file /var/log/auth.log --live --follow-start
```
**Check:**
- [x] Shows historical data first?
- [x] Transitions to live monitoring?
- [x] No duplicate entries?

### 1.5 Live Mode + CSV Export (Continuous Logging)
```bash
# Export to CSV while live-monitoring
python3 main.py \
  --log-file /var/log/auth.log \
  --live \
  --refresh 5 \
  --export-csv /tmp/live_threats.csv
```
**Check:**
- [x] CSV file created?
- [x] CSV updates with new entries?
- [x] Can monitor file in another terminal: `tail -f /tmp/live_threats.csv`?
- [x] Data format correct for fail2ban scripts?

---

## PART 2: fail2ban Integration (30 min)
**Core Focus:** This is the deployment scenario. Automatic threat blocking based on SSHvigil detection.

### 2.1 Generate Blocklist from Live Data
```bash
# Analyze current log and create blocklist
python3 main.py \
  --log-file /var/log/auth.log \
  --non-interactive \
  --export-blocklist threats.txt \
  --blocklist-threshold HIGH

# Review the blocklist
echo "=== Blocklist (HIGH+ threats) ==="
cat threats.txt
echo "Total IPs to block: $(wc -l < threats.txt)"
```
**Check:**
- [x] Blocklist contains valid IPs?
- [x] One IP per line?
- [x] Reasonable number of IPs (not too many, not too few)?
- [x] No localhost or trusted IPs? (Note: ::1 IPv6 localhost was in blocklist)

### 2.2 fail2ban Integration - Manual Block
```bash
# If fail2ban installed, manually add IPs from blocklist
sudo fail2ban-client set sshd banip $(cat threats.txt | head -5)

# Check what's banned
sudo fail2ban-client status sshd

# Unban after testing
sudo fail2ban-client set sshd unbanip $(cat threats.txt | head -5)
```
**Check:**
- [x] IPs ban successfully?
- [x] fail2ban status shows banned IPs?
- [x] Unbanning works?

### 2.3 fail2ban Integration - Automated Script Setup
```bash
# Step 1: Create the automation script (use absolute path - pwd will show current directory)
cat > /tmp/update_fail2ban.sh << EOF
#!/bin/bash
# Generate fresh blocklist
sudo python3 $(pwd)/main.py \
  --log-file /var/log/auth.log \
  --non-interactive \
  --export-blocklist /tmp/sshvigil_blocklist.txt \
  --blocklist-threshold HIGH

# Ban the top 5 IPs from the list
head -5 /tmp/sshvigil_blocklist.txt | while read ip; do
  sudo fail2ban-client set sshd banip "\$ip"
  echo "[\$(date)] Banned \$ip"
done
EOF

# Step 2: Make it executable
chmod +x /tmp/update_fail2ban.sh

# Step 3: Test run the script (run from your Cybersecurity-Suite directory)
/tmp/update_fail2ban.sh

# Step 4: Check what got banned
sudo fail2ban-client status sshd
```
**Check:**
- [x] Script creates blocklist successfully?
- [x] Shows "Banned [IP]" messages?
- [x] fail2ban status shows the new IPs?
- [x] No permission errors?

### 2.4 Automated Cron Job (Production Setup)
```bash
# Add to crontab for automated threat blocking
# This checks for threats every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/update_fail2ban.sh") | crontab -

# Verify crontab entry
crontab -l
```
**Note:** Cron = task scheduler. This makes the script run automatically every 5 minutes.

**Check:**
- [x] Cron job added successfully?
- [x] Syntax correct?
- [x] Can be removed later: `crontab -r`?
- [ ] **Path is correct?** (You have `/path/to/update_fail2ban.sh` but should be `/tmp/update_fail2ban.sh`)

---

## PART 3: Threat Detection & Blocklist Accuracy (20 min)

### 3.1 Blocklist Threshold Testing
```bash
# Generate blocklists at different thresholds
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist critical.txt --blocklist-threshold CRITICAL

python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist high.txt --blocklist-threshold HIGH

python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist medium.txt --blocklist-threshold MEDIUM

python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist low.txt --blocklist-threshold LOW

# Compare sizes
echo "Blocklist sizes by threshold:"
echo "CRITICAL: $(wc -l < critical.txt)"
echo "HIGH: $(wc -l < high.txt)"
echo "MEDIUM: $(wc -l < medium.txt)"
echo "LOW: $(wc -l < low.txt)"
```
**Check:**
- [ ] CRITICAL < HIGH < MEDIUM < LOW?
- [ ] Each threshold includes previous tier?
- [ ] All IPs are valid (start with 1-223)?

### 3.2 Blocklist with Whitelist (Trusted IPs)
```bash
# Create whitelist of trusted IPs
cat > trusted_ips.txt << 'EOF'
203.0.113.1
198.51.100.50
EOF

# Generate blocklist excluding trusted IPs
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --whitelist trusted_ips.txt \
  --export-blocklist filtered_block.txt \
  --blocklist-threshold HIGH

# Verify trusted IPs not in blocklist
echo "=== Checking if trusted IPs are excluded ==="
grep -f trusted_ips.txt filtered_block.txt && echo "ERROR: Trusted IPs in blocklist!" || echo "PASS: Trusted IPs excluded"
```
**Check:**
- [ ] Whitelist loaded successfully?
- [ ] Trusted IPs NOT in output blocklist?
- [ ] Other HIGH+ threats still included?

### 3.3 Incremental Threat Updates
```bash
# Generate blocklist once
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist block_v1.txt --blocklist-threshold HIGH

INITIAL_COUNT=$(wc -l < block_v1.txt)
echo "Initial threats: $INITIAL_COUNT"

# Wait a few minutes (simulating new attacks)
sleep 120

# Generate again
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist block_v2.txt --blocklist-threshold HIGH

NEW_COUNT=$(wc -l < block_v2.txt)
ADDED=$((NEW_COUNT - INITIAL_COUNT))
echo "Current threats: $NEW_COUNT"
echo "New threats added: $ADDED"
```
**Check:**
- [ ] Script detects new threats?
- [ ] Blocklist grows over time?
- [ ] No duplicate IPs?

---

## PART 4: Display & Export Options (15 min)

### 4.1 Severity Filter Display (Bug Fix Verification)
```bash
# This was a known bug - verify it's fixed
python3 main.py --log-file /var/log/auth.log --non-interactive -f HIGH

# Should show only HIGH severity (and above, if any)
# Should NOT show CRITICAL first then truncate
```
**Check:**
- [ ] Results show only HIGH+ threats?
- [ ] Not truncated with "... and X more"?
- [ ] All filtered results visible?

### 4.2 CSV Export for Analysis
```bash
# Export full data to CSV
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-csv full_analysis.csv

# Check CSV structure
head -20 full_analysis.csv
wc -l full_analysis.csv
```
**Check:**
- [ ] CSV has headers?
- [ ] All threats included?
- [ ] Can be opened in spreadsheet app?
- [ ] Format suitable for processing by other tools?

### 4.3 Verbose Mode for Detailed Analysis
```bash
# Show detailed event breakdown
python3 main.py --log-file /var/log/auth.log --non-interactive --verbose

# Also works with filtering
python3 main.py --log-file /var/log/auth.log --non-interactive --verbose -f HIGH
```
**Check:**
- [ ] Verbose mode shows additional details?
- [ ] Includes event-by-event breakdown?
- [ ] Useful for security investigations?

### 4.4 Compact Mode for Dashboards
```bash
# Hide event summaries, show only threat table
python3 main.py --log-file /var/log/auth.log --non-interactive --compact

# Useful for repeated monitoring
for i in {1..3}; do 
  python3 main.py --log-file /var/log/auth.log --non-interactive --compact
  echo "---"
  sleep 1
done
```
**Check:**
- [ ] Output is concise?
- [ ] Still shows all relevant threat data?
- [ ] Good for dashboard/monitoring display?

### 4.5 Color Control (NO_COLOR)
```bash
# Run with colors (normal)
python3 main.py --log-file /var/log/auth.log --non-interactive

# Run without colors (for piping, logging, etc.)
NO_COLOR=1 python3 main.py --log-file /var/log/auth.log --non-interactive

# Redirect to file (colors should not appear in file)
python3 main.py --log-file /var/log/auth.log --non-interactive > output.log
cat output.log | grep -E '\x1b\[' && echo "ERROR: Found ANSI codes" || echo "PASS: No color codes"
```
**Check:**
- [ ] Colors work normally?
- [ ] NO_COLOR=1 disables colors?
- [ ] Output can be piped/logged cleanly?

---

## PART 5: Deployment Scenarios (30 min)

### 5.1 Scenario: Daily Threat Report
```bash
# Generate daily report script
cat > /tmp/daily_threat_report.sh << 'EOF'
#!/bin/bash
REPORT_DIR="/tmp/sshvigil_reports"
mkdir -p "$REPORT_DIR"
DATE=$(date +%Y-%m-%d)

python3 /path/to/main.py \
  --log-file /var/log/auth.log \
  --non-interactive \
  --export-csv "$REPORT_DIR/threats_$DATE.csv" \
  --export-blocklist "$REPORT_DIR/blocklist_$DATE.txt" \
  -f HIGH

echo "Daily report saved to $REPORT_DIR"
ls -lh "$REPORT_DIR/threats_$DATE.csv"
EOF

chmod +x /tmp/daily_threat_report.sh
/tmp/daily_threat_report.sh
```
**Check:**
- [ ] Script runs successfully?
- [ ] Report files created with correct date?
- [ ] CSV and blocklist both generated?

### 5.2 Scenario: Alert on New Critical Threats
```bash
# Check for CRITICAL threats and alert
cat > /tmp/check_critical.sh << 'EOF'
#!/bin/bash
CRITICAL_FILE="/tmp/critical_threats.txt"
PREV_FILE="/tmp/critical_threats_prev.txt"

# Get current critical threats
python3 /path/to/main.py \
  --log-file /var/log/auth.log \
  --non-interactive \
  -f CRITICAL | grep -E "^[0-9]" | awk '{print $1}' > "$CRITICAL_FILE"

# Compare with previous run
if [ -f "$PREV_FILE" ]; then
  NEW=$(comm -23 <(sort "$CRITICAL_FILE") <(sort "$PREV_FILE"))
  if [ ! -z "$NEW" ]; then
    echo "ALERT: New critical threats detected:"
    echo "$NEW"
    # Could send email, webhook, etc here
  fi
fi

cp "$CRITICAL_FILE" "$PREV_FILE"
EOF

chmod +x /tmp/check_critical.sh
/tmp/check_critical.sh
```
**Check:**
- [ ] Script detects critical threats?
- [ ] Alert mechanism works?
- [ ] Comparison logic correct?

### 5.3 Scenario: Safe Testing on Production
```bash
# Analyze with various presets
echo "=== SOC Preset (Fast, Important Only) ==="
python3 main.py --log-file /var/log/auth.log --non-interactive --mode soc

echo -e "\n=== Verbose Preset (Full Analysis) ==="
python3 main.py --log-file /var/log/auth.log --non-interactive --mode verbose

echo -e "\n=== Quiet Preset (Summary Only) ==="
python3 main.py --log-file /var/log/auth.log --non-interactive --quiet
```
**Check:**
- [ ] Presets work correctly?
- [ ] Each shows appropriate detail level?
- [ ] Can be used in production without issues?

### 5.4 Scenario: Continuous Monitoring Script
```bash
# Long-running monitoring with periodic reports
cat > /tmp/continuous_monitor.sh << 'EOF'
#!/bin/bash
echo "Starting continuous SSH threat monitoring..."

while true; do
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Analyzing threats..."
  
  python3 /path/to/main.py \
    --log-file /var/log/auth.log \
    --non-interactive \
    --compact \
    -f HIGH
  
  echo "Next check in 60 seconds..."
  sleep 60
done
EOF

chmod +x /tmp/continuous_monitor.sh

# Run in background
nohup /tmp/continuous_monitor.sh > /tmp/monitor.log 2>&1 &
MONITOR_PID=$!
echo "Monitor started with PID: $MONITOR_PID"

# Let it run for a bit
sleep 10

# Check the output
tail -20 /tmp/monitor.log

# Kill it
kill $MONITOR_PID
```
**Check:**
- [ ] Monitoring script runs continuously?
- [ ] Output is logged correctly?
- [ ] Can be started/stopped cleanly?

---

## PART 6: Error Handling & Edge Cases (15 min)

### 6.1 Invalid Log File
```bash
python3 main.py --log-file /nonexistent/path/auth.log --non-interactive
python3 main.py --log-file /dev/null --non-interactive
```
**Check:**
- [ ] Clear error message?
- [ ] No crash?
- [ ] Exits with error code?

### 6.2 Permission Denied
```bash
# If you have a restricted file
python3 main.py --log-file /root/private.log --non-interactive 2>&1 | head -10
```
**Check:**
- [ ] Error message clear?
- [ ] Helpful (suggests running with sudo if needed)?

### 6.3 Invalid Arguments
```bash
python3 main.py --non-interactive -f INVALID
python3 main.py --log-file /var/log/auth.log --invalid-arg
python3 main.py --help | head -20
```
**Check:**
- [ ] Clear error for invalid filter?
- [ ] Help text useful?
- [ ] Suggests valid options?

### 6.4 Empty Log File
```bash
python3 main.py --log-file /dev/null --non-interactive
```
**Check:**
- [ ] Handles gracefully?
- [ ] Shows 0 threats?
- [ ] No crash?

---

## PART 7: Performance & Load Testing (20 min)

### 7.1 Large Log File Processing
```bash
# Time the analysis
time python3 main.py --log-file /var/log/auth.log --non-interactive > /tmp/analysis.txt

# Check output
tail -20 /tmp/analysis.txt

# Check file size
ls -lh /var/log/auth.log
```
**Check:**
- [ ] Completes in reasonable time (<5 seconds for large logs)?
- [ ] Memory usage acceptable?
- [ ] Results accurate?

### 7.2 Live Mode Under Load
```bash
# Simulate many SSH attempts while monitoring live
python3 main.py --log-file /var/log/auth.log --live --refresh 3 &
LIVE_PID=$!

# Generate many attempts
for i in {1..100}; do
  ssh baduser$i@localhost 2>/dev/null &
done

# Let live mode run
sleep 15

# Kill live mode
kill $LIVE_PID
```
**Check:**
- [ ] Live mode handles burst traffic?
- [ ] Doesn't lag significantly?
- [ ] Accurate threat detection under load?

---

## Final Verification Checklist

- [ ] All live mode features work
- [ ] fail2ban integration is smooth and reliable
- [ ] Severity filtering displays correctly
- [ ] Whitelist/blocklist exclusions work
- [ ] CSV export contains complete data
- [ ] --verbose flag works as expected
- [ ] NO_COLOR environment variable respected
- [ ] Error messages are clear and helpful
- [ ] Performance is acceptable for production
- [ ] Documentation matches actual behavior
- [ ] Ready for real-world deployment

---

## Known Issues & Workarounds

### Issue: Large output truncated in terminal
**Solution:** Use CSV export for full data: `--export-csv results.csv`

### Issue: fail2ban integration complex
**Solution:** Use the automated scripts provided, or see `examples/sshvigil-cron.sh`

### Issue: Whitelist not excluding some IPs
**Solution:** Ensure IPs are valid and one per line in whitelist file

---

## Next Steps After Testing

1. **Integration:** Move scripts to `/usr/local/bin/` for system-wide use
2. **Automation:** Set up cron jobs for regular analysis
3. **Monitoring:** Add to monitoring dashboard (Prometheus, Grafana, etc.)
4. **Alerting:** Integrate with alert system (email, Slack, PagerDuty)
5. **Logging:** Archive reports for audit/compliance

