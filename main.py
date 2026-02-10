"""
Log Signal Extractor - Main CLI entry point

A security tool that reads SSH auth logs and finds suspicious login patterns.
Looks for brute force attacks, password spraying, and account takeovers.

Usage:
    python main.py <path_to_auth_log> [--output <output_file>]

Example:
    python main.py logs/sample_auth.log --output alerts.json
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from extractor.parser import AuthLogParser
from extractor.detectors import SuspiciousActivityDetector


def main():
    """Run the tool - parse logs, detect attacks, output results."""
    parser = argparse.ArgumentParser(
        description="Extract security signals from SSH authentication logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py logs/sample_auth.log
  python main.py logs/sample_auth.log --output alerts.json
  python main.py logs/sample_auth.log --verbose
        """,
    )

    parser.add_argument(
        "logfile",
        help="Path to auth.log file to analyze",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for JSON alerts (default: stdout)",
        default=None,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Make sure the file exists
    if not Path(args.logfile).exists():
        print(f"Error: Log file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    try:
        # Start parsing the logs
        if args.verbose:
            print(f"[*] Parsing log file: {args.logfile}")

        log_parser = AuthLogParser()
        events = log_parser.parse_file(args.logfile)

        if args.verbose:
            print(f"[+] Extracted {len(events)} authentication events")

        # Now run the detection algorithms to find attacks
        if args.verbose:
            print("[*] Running security detection algorithms...")

        detector = SuspiciousActivityDetector()
        alerts = detector.detect_all(events)

        # Build the output JSON with all the data
        output_data = {
            "metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "log_file": args.logfile,
                "events_analyzed": len(events),
                "alerts_detected": len(alerts),
            },
            "alerts": [alert.to_dict() for alert in alerts],
        }

        # Convert to JSON string
        output_json = json.dumps(output_data, indent=2)

        # Either save to file or print to console
        if args.output:
            if args.verbose:
                print(f"[*] Writing results to: {args.output}")
            with open(args.output, "w") as f:
                f.write(output_json)
            if args.verbose:
                print(f"[+] Results saved to {args.output}")
        else:
            print(output_json)

        # Print a nice summary at the end
        if args.verbose or args.output:
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"Analysis Complete", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)
            print(f"Events analyzed: {len(events)}", file=sys.stderr)
            print(f"Alerts detected: {len(alerts)}", file=sys.stderr)

            # Count alerts by severity level
            severity_counts = {}
            for alert in alerts:
                severity = alert.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity in severity_counts:
                    print(f"  {severity}: {severity_counts[severity]}", file=sys.stderr)

        sys.exit(0)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
