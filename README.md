# Log Signal Extractor

[![CI](https://github.com/znrac137/log-signal-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/znrac137/log-signal-extractor/actions)

Ever wonder what's actually happening in your SSH logs? This tool digs through auth.log files and finds the real problems—brute force attacks, password spraying, and when someone finally cracks an account.

## ⚡ Quickstart

```bash
# Clone and run
git clone https://github.com/znrac137/log-signal-extractor.git
cd log-signal-extractor
python main.py logs/sample_auth.log --verbose

# Save alerts to JSON
python main.py logs/sample_auth.log --output alerts.json
```

That's it. No dependencies to install.

## Why I Built This

It parses your auth.log and hunts for suspicious patterns. When it finds something sketchy, it spits out detailed JSON alerts so you know exactly what happened and when.

### What It Catches

- **Brute Force**: Someone's trying password after password on the same account. Classic attacker move.
- **Password Spray**: They found a common password and are throwing it at every username they can find.
- **Account Takeover**: After a bunch of failures, they got in. That's... not good.

## Getting Started

### Requirements
- Python 3.8 or later
- Nothing else. Seriously.

### Installation
```bash
git clone https://github.com/znrac137/log-signal-extractor.git
cd log-signal-extractor
```

## Using It

Want to just run it? Easy:
```bash
python main.py logs/sample_auth.log
```

Want to save the alerts to a file?
```bash
python main.py logs/sample_auth.log --output alerts.json
```

Want to see what's happening behind the scenes?
```bash
python main.py logs/sample_auth.log --verbose
```

Here's what all the options do:
```
usage: main.py [-h] [-o OUTPUT] [-v] logfile

Extract security signals from SSH authentication logs

positional arguments:
  logfile              Path to auth.log file to analyze

optional arguments:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output file for JSON alerts (default: stdout)
  -v, --verbose        Enable verbose output
```

### Sample Terminal Output

```
[*] Parsing log file: logs/sample_auth.log
[+] Extracted 30 authentication events
[*] Running security detection algorithms...

============================================================
ALERT: BRUTE_FORCE_ATTACK (HIGH)
  Source IP: 192.168.1.100
  Failed attempts: 8
  Usernames targeted: admin, root, postgres, test
  Time window: 10 minutes
============================================================

ALERT: PASSWORD_SPRAY_ATTACK (HIGH)
  Source IP: 192.168.1.101
  Unique usernames: 6
  Common password detected
============================================================

ALERT: SUCCESS_AFTER_FAILURES (CRITICAL)
  Source IP: 192.168.1.100
  Username: root
  Failed attempts before success: 7
  ⚠️ Potential account compromise
============================================================

Analysis Complete
  Events analyzed: 30
  Alerts detected: 3
    CRITICAL: 1
    HIGH: 2
```

## What You Get Back

When it runs, you'll get JSON output with all the alerts. Each one includes the timestamp, usernames involved, the IP address causing trouble, and the actual log lines that triggered the alert:

```json
{
  "metadata": {
    "scan_timestamp": "2026-02-10T12:00:00.000000",
    "log_file": "logs/sample_auth.log",
    "events_analyzed": 30,
    "alerts_detected": 3
  },
  "alerts": [
    {
      "alert_type": "BRUTE_FORCE_ATTACK",
      "severity": "HIGH",
      "source_ip": "192.168.1.100",
      "affected_usernames": ["admin", "root", "postgres", "test"],
      "event_count": 8,
      "timestamp": "2026-02-10T12:00:00.000000",
      "description": "Detected 8 failed login attempts from 192.168.1.100 in 10min window. Possible brute force attack.",
      "events": [
        {
          "timestamp": "2026-01-01T10:15:22",
          "username": "admin",
          "ip_address": "192.168.1.100",
          "event_type": "Invalid user",
          "raw_line": "Jan  1 10:15:22 server sshd[1234]: Invalid user admin from 192.168.1.100 port 54321"
        },
        ...
      ]
    }
  ]
}
```

## Try It Out

The project includes a realistic sample auth.log file with actual attack patterns already in it:

```bash
python main.py logs/sample_auth.log --verbose
```

**Sample Output:**
```
[*] Parsing log file: logs/sample_auth.log
[+] Extracted 30 authentication events
[*] Running security detection algorithms...

============================================================
Analysis Complete
============================================================
Events analyzed: 30
Alerts detected: 3
  CRITICAL: 1
  HIGH: 2
```

## Project Structure

```
log-signal-extractor/
├── logs/
│   └── sample_auth.log              # Sample auth.log with attack patterns
├── extractor/
│   ├── __init__.py                  # Package initialization
│   ├── models.py                    # Data models (LogEvent, Alert)
│   ├── parser.py                    # Auth.log parser
│   ├── detectors.py                 # Detection algorithms
│   └── utils.py                     # Utility functions
├── main.py                          # CLI entry point
├── requirements.txt                 # Python dependencies (none required)
└── README.md                        # This file
```

## Architecture

### The Pieces

Here's how it all fits together:

1. **models.py** - The data structures:
   - `LogEvent`: A single authentication log entry
   - `Alert`: A detected security alert
   - `EventType`: What types of events we track
   - `AlertSeverity`: How bad is this alert?

2. **parser.py** - Reads auth.log files:
   - `AuthLogParser.parse_file()`: Process the whole file
   - `AuthLogParser.parse_line()`: Handle one line at a time
   - Pulls out: timestamp, username, IP, event type

3. **detectors.py** - The detection algorithms:
   - `detect_bruteforce()`: Spots repeated failed attempts
   - `detect_password_spray()`: Finds multi-user targeting
   - `detect_success_after_fail()`: Catches account compromise
   - You can tweak thresholds to make it more or less sensitive

4. **utils.py** - Helper stuff:
   - Parse timestamps
   - Extract and validate IPs
   - Pull out usernames

### How It Detects Things

#### Brute Force Detection
- **What it is**: Multiple failed login attempts from the same IP
- **When it triggers**: 5 or more failed attempts in a 10-minute window
- **How serious**: HIGH
- **What it means**: Someone's systematically guessing passwords

#### Password Spray Detection
- **What it is**: Someone trying to log in as multiple different users from one IP
- **When it triggers**: 3 or more different usernames attempted in a 10-minute window
- **How serious**: HIGH
- **What it means**: They've probably got a common password and are throwing it everywhere

#### Success After Failures
- **What it is**: A successful login that comes after a bunch of failures
- **When it triggers**: Login succeeds after 5+ failed attempts from the same IP and username combo
- **How serious**: CRITICAL
- **What it means**: They guessed it. Account's probably compromised.

## Tuning the Sensitivity

Want to make it stricter or looser? Modify these thresholds in `main.py`:

```python
detector = SuspiciousActivityDetector(config={
    "failed_login_threshold": 5,        # How many failed attempts before alert
    "password_spray_threshold": 3,      # How many different users before alert
    "time_window_minutes": 10,          # Window to group attempts together
})
```

### Example: Stricter Detection (catch more)
```python
detector = SuspiciousActivityDetector(config={
    "failed_login_threshold": 3,        # Alert after just 3 failures
    "password_spray_threshold": 2,      # Alert on 2+ users targeted
    "time_window_minutes": 5,           # Tighter 5-minute window
})
```

### Example: Looser Detection (fewer false positives)
```python
detector = SuspiciousActivityDetector(config={
    "failed_login_threshold": 10,       # Only alert after 10 failures
    "password_spray_threshold": 5,      # Need 5+ users targeted
    "time_window_minutes": 15,          # Wider 15-minute window
})
```

Then just run it normally:
```bash
python main.py logs/sample_auth.log --output alerts.json
```

## Things to Keep in Mind

- **False Positives**: Sometimes legitimate users trigger alerts if their VPN drops or they forget their password
- **Tuning**: Adjust the thresholds based on what's normal in your environment
- **Log Rotation**: Make sure your auth.log is being kept around long enough to analyze
- **Scale It Up**: If you're running this in production, consider using a log aggregation tool like ELK or Splunk

## Limitations

- **Timestamp Format**: The parser expects standard syslog format. Some systems may have different formats
- **Year Information**: Standard auth.log doesn't include year in timestamps, so alerts use the current year (can cause issues with logs spanning calendar years)
- **Log Rotation**: If logs are rotated/compressed, you'll need to decompress and pass individual files
- **Real-time Analysis**: Current version processes static files. For real-time streaming, needs integration with log ingestion tools
- **Geographic Anomalies**: Doesn't detect impossible travel or unusual access patterns (yet)
- **Account Context**: Doesn't know which accounts are service accounts vs. human users

## Want to Contribute?

### Adding New Detections

To add a new detection algorithm:

1. Create a method in `SuspiciousActivityDetector`:
```python
def detect_custom_pattern(self, events: List[LogEvent]) -> List[Alert]:
    """Your detection logic here"""
    alerts = []
    # ... implementation ...
    return alerts
```

2. Call it from `detect_all()`:
```python
all_alerts.extend(self.detect_custom_pattern(events))
```

### Testing

Just run it on the sample logs:
```bash
python main.py logs/sample_auth.log --output test_alerts.json --verbose
```

## Performance

- Parses typical auth.log file (~1000s of events) in <100ms
- Memory efficient: processes logs line-by-line
- Suitable for real-time log processing pipelines

## Future Enhancements

- [ ] Real-time log streaming support
- [ ] Additional detection patterns (geographic anomalies, timing patterns)
- [ ] Integration with threat intelligence feeds
- [ ] Elasticsearch/Splunk exporters
- [ ] Web dashboard for alert visualization
- [ ] Machine learning models for behavioral analysis

## License

MIT License - See LICENSE file for details

## Author

[znrac137](https://github.com/znrac137)

---

**Version**: 1.0.0  
**Last Updated**: February 2026
