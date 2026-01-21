# Blue_defense_tools

Scripts or tools useful for blue teams activities.

## Tools

### 1) IOC Log Matcher
Scan log files for indicators of compromise (IOCs) provided in a text file.

```bash
python3 tools/ioc_log_matcher.py --ioc-file iocs.txt --log-files /var/log/syslog
```

### 2) File Hash Inventory
Create a CSV inventory of file hashes for integrity baselines or change tracking.

```bash
python3 tools/file_hash_inventory.py /etc --output baseline.csv --exclude "*/ssh/*"
```

### 3) Auth Log Summary
Summarize authentication activity (failed/accepted logins and sudo usage).

```bash
python3 tools/auth_log_summary.py /var/log/auth.log --top 5
```

Use `--json` to emit machine-readable output.
