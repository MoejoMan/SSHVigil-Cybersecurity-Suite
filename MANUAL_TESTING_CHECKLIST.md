# SSHvigil Manual Testing Checklist

Use this checklist to systematically test SSHvigil on your VPS with real auth logs.

## Setup
- [ ] SSH into your VPS
- [ ] Navigate to project directory
- [ ] Activate venv (if using one)
- [ ] Identify your auth log location: `/var/log/auth.log` or `/var/log/secure`

---

## Part 1: Basic Functionality (15 min)

### 1.1 Basic Run
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive
```
**Check:**
- [ ] Does it run without errors?
- [ ] Is the output readable and clear?
- [ ] Are the threat levels (CRITICAL/HIGH/MEDIUM/LOW) showing up?
- [ ] Do the IP addresses look valid?
- [ ] Are the attempt counts reasonable?

### 1.2 Verbose Mode
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --verbose
```
**Check:**
- [ ] Does verbose output show more detail?
- [ ] Is the additional info useful or cluttered?
- [ ] Can you read the detailed breakdown?

### 1.3 CSV Export
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --export-csv results.csv
cat results.csv
```
**Check:**
- [ ] CSV file created successfully?
- [ ] CSV has proper headers?
- [ ] Data is properly formatted?
- [ ] Can you open it in Excel/LibreOffice?

---

## Part 2: Color and Display Options (10 min)

### 2.1 Disable Colors
```bash
NO_COLOR=1 python3 main.py --log-file /var/log/auth.log --non-interactive
```
**Check:**
- [ ] No ANSI color codes in output?
- [ ] Still readable without colors?
- [ ] No broken formatting?

### 2.2 Compact Mode
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --compact
```
**Check:**
- [ ] Output is more concise?
- [ ] Event summaries hidden?
- [ ] Still shows threat table?

### 2.3 Color + Compact Together
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --compact
NO_COLOR=1 python3 main.py --log-file /var/log/auth.log --non-interactive --compact
```
**Check:**
- [ ] Both work together?
- [ ] No conflicts?

---

## Part 3: Filtering (15 min)

### 3.1 Filter by Severity
```bash
# Show only CRITICAL threats
python3 main.py --log-file /var/log/auth.log --non-interactive -f CRITICAL

# Show HIGH and above
python3 main.py --log-file /var/log/auth.log --non-interactive -f HIGH

# Show MEDIUM and above
python3 main.py --log-file /var/log/auth.log --non-interactive -f MEDIUM

# Show all (LOW and above)
python3 main.py --log-file /var/log/auth.log --non-interactive -f LOW
```
**Check:**
- [ ] Each filter shows only appropriate severity levels?
- [ ] CRITICAL filter shows fewer results than HIGH?
- [ ] LOW filter shows all results?
- [ ] No crashes with any filter level?

### 3.2 Invalid Filter
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive -f INVALID
python3 main.py --log-file /var/log/auth.log --non-interactive -f medium  # lowercase
python3 main.py --log-file /var/log/auth.log --non-interactive -f ""
```
**Check:**
- [ ] Error message is clear?
- [ ] Doesn't crash?
- [ ] Suggests valid options?

---

## Part 4: Whitelist Testing (15 min)

### 4.1 Create Test Whitelist
```bash
# Get your server's IP
curl -s ifconfig.me
echo "YOUR_IP_HERE" > whitelist.txt
echo "127.0.0.1" >> whitelist.txt
```

### 4.2 Test Whitelist
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --whitelist whitelist.txt
```
**Check:**
- [ ] Your IP is excluded from results?
- [ ] Other IPs still appear?
- [ ] No errors loading whitelist?

### 4.3 Whitelist + Blocklist
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --whitelist whitelist.txt \
  --export-blocklist blocklist.txt

cat blocklist.txt
```
**Check:**
- [ ] Blocklist created?
- [ ] Whitelisted IPs NOT in blocklist?
- [ ] High-threat IPs ARE in blocklist?

### 4.4 Invalid Whitelist
```bash
# Non-existent file
python3 main.py --log-file /var/log/auth.log --non-interactive --whitelist nonexistent.txt

# Empty file
touch empty_whitelist.txt
python3 main.py --log-file /var/log/auth.log --non-interactive --whitelist empty_whitelist.txt

# Whitelist with invalid IPs
echo "not-an-ip" > bad_whitelist.txt
echo "999.999.999.999" >> bad_whitelist.txt
python3 main.py --log-file /var/log/auth.log --non-interactive --whitelist bad_whitelist.txt
```
**Check:**
- [ ] Clear error for missing file?
- [ ] Empty whitelist works (no filtering)?
- [ ] Invalid IPs ignored gracefully?

---

## Part 5: Blocklist Testing (15 min)

### 5.1 Basic Blocklist
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --export-blocklist block.txt
cat block.txt
wc -l block.txt
```
**Check:**
- [ ] Blocklist file created?
- [ ] Contains valid IPs?
- [ ] One IP per line?
- [ ] No duplicates?

### 5.2 Blocklist Thresholds
```bash
# Block CRITICAL only
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist critical_only.txt --blocklist-threshold CRITICAL

# Block HIGH and above (default)
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist high_plus.txt --blocklist-threshold HIGH

# Block MEDIUM and above
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist medium_plus.txt --blocklist-threshold MEDIUM

# Compare counts
wc -l critical_only.txt high_plus.txt medium_plus.txt
```
**Check:**
- [ ] CRITICAL has fewest IPs?
- [ ] MEDIUM has most IPs?
- [ ] HIGH is in between?
- [ ] All files valid?

### 5.3 Blocklist to Existing Path
```bash
# Create blocklist
python3 main.py --log-file /var/log/auth.log --non-interactive --export-blocklist test_block.txt

# Try to overwrite
python3 main.py --log-file /var/log/auth.log --non-interactive --export-blocklist test_block.txt
```
**Check:**
- [ ] Overwrites or appends correctly?
- [ ] No corruption?
- [ ] Expected behavior?

---

## Part 6: Command Combinations (20 min)

### 6.1 All Options Together
```bash
python3 main.py \
  --log-file /var/log/auth.log \
  --non-interactive \
  --verbose \
  --compact \
  --export-csv full_test.csv \
  --export-blocklist full_test_block.txt \
  --whitelist whitelist.txt \
  -f HIGH \
  --blocklist-threshold MEDIUM
```
**Check:**
- [ ] Runs without errors?
- [ ] CSV created?
- [ ] Blocklist created?
- [ ] Whitelist respected?
- [ ] Filter applied?
- [ ] Compact mode working?

### 6.2 Conflicting Options
```bash
# Verbose + Compact (might conflict?)
python3 main.py --log-file /var/log/auth.log --non-interactive --verbose --compact
```
**Check:**
- [ ] Which takes precedence?
- [ ] Output makes sense?
- [ ] No weird behavior?

### 6.3 Multiple Exports
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-csv test1.csv \
  --export-blocklist test1.txt
  
# Run again with different names
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-csv test2.csv \
  --export-blocklist test2.txt
```
**Check:**
- [ ] Both sets created?
- [ ] No interference?
- [ ] Files are independent?

---

## Part 7: Error Handling (15 min)

### 7.1 Invalid Log File
```bash
# Non-existent file
python3 main.py --log-file /nonexistent/path/auth.log --non-interactive

# Directory instead of file
python3 main.py --log-file /var/log/ --non-interactive

# Empty file
touch empty_log.log
python3 main.py --log-file empty_log.log --non-interactive
```
**Check:**
- [ ] Clear error messages?
- [ ] Doesn't crash?
- [ ] Helpful suggestions?

### 7.2 Permission Issues
```bash
# Try to read a restricted file (if any exist)
python3 main.py --log-file /root/.ssh/id_rsa --non-interactive

# Try to write to restricted location
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-csv /root/test.csv
```
**Check:**
- [ ] Permission error caught?
- [ ] Error message is clear?
- [ ] Doesn't expose sensitive info?

### 7.3 Typos in Commands
```bash
# Missing dashes
python3 main.py -log-file /var/log/auth.log

# Wrong option names
python3 main.py --logfile /var/log/auth.log --non-interactive
python3 main.py --log-file /var/log/auth.log --export-blocklist block.txt --threshold HIGH

# Misspelled options
python3 main.py --log-file /var/log/auth.log --non-interctive
```
**Check:**
- [ ] Shows help message?
- [ ] Error is understandable?
- [ ] Suggests correct option?

---

## Part 8: Output Quality (10 min)

### 8.1 Readability Test
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive
```
**Ask yourself:**
- [ ] Can you quickly find the most dangerous IPs?
- [ ] Is the table layout clear?
- [ ] Are the colors helpful (if enabled)?
- [ ] Is the summary information useful?
- [ ] Any confusing abbreviations?

### 8.2 Large Output
```bash
# If you have a lot of data
python3 main.py --log-file /var/log/auth.log --non-interactive -f LOW
```
**Check:**
- [ ] Does it handle many IPs gracefully?
- [ ] Is pagination needed?
- [ ] Can you still find important info?

### 8.3 Minimal Output
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive -f CRITICAL --compact
```
**Check:**
- [ ] Clean and concise?
- [ ] Still informative?
- [ ] No unnecessary clutter?

---

## Part 9: Real-World Scenarios (20 min)

### 9.1 Daily Security Check
```bash
# What you'd run every morning
python3 main.py --log-file /var/log/auth.log --non-interactive \
  -f HIGH --compact --export-csv daily_$(date +%Y%m%d).csv
```
**Check:**
- [ ] Quick to read?
- [ ] Shows important threats?
- [ ] CSV good for records?

### 9.2 Incident Investigation
```bash
# When you detect a problem
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --verbose -f CRITICAL
```
**Check:**
- [ ] Enough detail to investigate?
- [ ] Can identify attack patterns?
- [ ] Useful for analysis?

### 9.3 Blocklist Generation
```bash
# Generate blocklist for fail2ban
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-blocklist fail2ban_ips.txt \
  --blocklist-threshold HIGH \
  --whitelist whitelist.txt \
  --compact
```
**Check:**
- [ ] Blocklist ready to use?
- [ ] No false positives?
- [ ] Whitelisted IPs excluded?

### 9.4 Reporting to Team
```bash
# Generate report for team
python3 main.py --log-file /var/log/auth.log --non-interactive \
  --export-csv security_report.csv \
  -f MEDIUM > report.txt
cat report.txt
```
**Check:**
- [ ] Report is professional?
- [ ] CSV useful for sharing?
- [ ] Data is clear?

---

## Part 10: Edge Cases & Weird Stuff (15 min)

### 10.1 Very Old Logs
```bash
# If you have archived logs
python3 main.py --log-file /var/log/auth.log.1 --non-interactive
python3 main.py --log-file /var/log/auth.log.2.gz --non-interactive  # compressed
```
**Check:**
- [ ] Handles old log format?
- [ ] Works with compressed logs?
- [ ] Timestamps parsed correctly?

### 10.2 Multiple Runs Quickly
```bash
for i in {1..5}; do
  python3 main.py --log-file /var/log/auth.log --non-interactive --compact
done
```
**Check:**
- [ ] Consistent results?
- [ ] No performance degradation?
- [ ] No weird caching issues?

### 10.3 Interrupted Execution
```bash
# Start and Ctrl+C after a second
python3 main.py --log-file /var/log/auth.log --non-interactive
# Press Ctrl+C quickly
```
**Check:**
- [ ] Exits cleanly?
- [ ] No corrupted files?
- [ ] No hanging processes?

### 10.4 Really Long Command
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --verbose --compact --export-csv test.csv --export-blocklist test.txt --whitelist whitelist.txt -f HIGH --blocklist-threshold MEDIUM 2>&1 | tee output.log
```
**Check:**
- [ ] Still works?
- [ ] No command line length issues?
- [ ] Output properly captured?

---

## Part 11: Config File Testing (10 min)

### 11.1 Default Config
```bash
cat config.json  # Check what's there
python3 main.py --log-file /var/log/auth.log --non-interactive
```
**Check:**
- [ ] Uses config values?
- [ ] Default thresholds make sense?

### 11.2 Modified Config
```bash
# Backup original
cp config.json config.json.bak

# Create custom config
cat > config.json << 'EOF'
{
  "max_attempts": 3,
  "time_window_minutes": 5,
  "block_threshold": 20,
  "monitor_threshold": 10
}
EOF

python3 main.py --log-file /var/log/auth.log --non-interactive
```
**Check:**
- [ ] New thresholds applied?
- [ ] More/fewer threats detected?
- [ ] Behavior changed as expected?

```bash
# Restore original
mv config.json.bak config.json
```

### 11.3 Broken Config
```bash
cp config.json config.json.bak

# Invalid JSON
echo "{broken json}" > config.json
python3 main.py --log-file /var/log/auth.log --non-interactive

# Empty config
echo "" > config.json
python3 main.py --log-file /var/log/auth.log --non-interactive

# Restore
mv config.json.bak config.json
```
**Check:**
- [ ] Falls back to defaults?
- [ ] Clear error message?
- [ ] Doesn't crash?

---

## Part 12: Performance Check (10 min)

### 12.1 Timing
```bash
time python3 main.py --log-file /var/log/auth.log --non-interactive

# Compare with large log
time python3 main.py --log-file /var/log/auth.log* --non-interactive 2>/dev/null || echo "Multiple files not supported"
```
**Check:**
- [ ] Completes in reasonable time?
- [ ] Times shown are accurate?

### 12.2 Memory Usage
```bash
# Monitor during execution
python3 main.py --log-file /var/log/auth.log --non-interactive &
PID=$!
ps aux | grep $PID | grep -v grep
wait $PID
```
**Check:**
- [ ] Memory usage reasonable?
- [ ] No memory leaks?

---

## Final Checks

### User Experience
- [ ] Is the tool intuitive to use?
- [ ] Do error messages help you fix problems?
- [ ] Is the output actionable?
- [ ] Would you use this regularly?
- [ ] Anything confusing or frustrating?

### Documentation Match
- [ ] Does README accurately describe behavior?
- [ ] Are all mentioned features working?
- [ ] Any undocumented features?

### Would You Recommend?
- [ ] Is it production-ready?
- [ ] Any blocking issues?
- [ ] What would you improve?

---

## Bug Report Template

If you find issues, note:

**Issue:** [Brief description]
**Command:** [Exact command run]
**Expected:** [What should happen]
**Actual:** [What actually happened]
**Log Output:** [Relevant error messages]
**Environment:** [OS, Python version]

---

## Quick Test Commands

```bash
# Fast sanity check (2 min)
python3 main.py --log-file /var/log/auth.log --non-interactive --compact
python3 main.py --log-file /var/log/auth.log --non-interactive -f HIGH
python3 main.py --log-file /var/log/auth.log --non-interactive --export-csv quick_test.csv

# Medium test (10 min)
for severity in CRITICAL HIGH MEDIUM LOW; do
  echo "Testing $severity..."
  python3 main.py --log-file /var/log/auth.log --non-interactive -f $severity --compact
done

# Full validation (30 min)
bash << 'TESTSCRIPT'
set -e
echo "1. Basic run..."; python3 main.py --log-file /var/log/auth.log --non-interactive --compact
echo "2. With filters..."; python3 main.py --log-file /var/log/auth.log --non-interactive -f HIGH --compact
echo "3. CSV export..."; python3 main.py --log-file /var/log/auth.log --non-interactive --export-csv test.csv --compact
echo "4. Blocklist..."; python3 main.py --log-file /var/log/auth.log --non-interactive --export-blocklist test_block.txt --compact
echo "5. No color..."; NO_COLOR=1 python3 main.py --log-file /var/log/auth.log --non-interactive --compact
echo "All tests passed!"
TESTSCRIPT
```

---

**Estimated Total Time:** 3-4 hours for complete testing
**Minimum Essential:** 30 minutes (Parts 1, 3, 4, 9)

Good luck! 🚀
