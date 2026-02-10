"""
Utility functions for Log Signal Extractor.

Small helper functions for common parsing tasks - extracting IPs, usernames,
timestamps, and validating them.
"""

import re
from datetime import datetime
from typing import Optional


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Try to parse a timestamp from the auth.log format.

    Could be "Jan  1 00:00:00" or "Jan  1 2025 00:00:00"

    Args:
        timestamp_str: The timestamp string the parser found in a log line

    Returns:
        A datetime object if it works, None if it doesn't
    """
    try:
        # Try with year first (backup format)
        if len(timestamp_str.split()) >= 4:
            return datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
        # Standard syslog - no year
        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    except ValueError:
        return None


def extract_ip_from_log(log_line: str) -> Optional[str]:
    """
    Pull out an IP address from a log line using a regex pattern.

    Args:
        log_line: The full line from the log file

    Returns:
        The IP address if the extractor found one, None otherwise
    """
    # Look for the IPv4 pattern (4 numbers separated by dots)
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    match = re.search(ip_pattern, log_line)
    return match.group(0) if match else None


def extract_username_from_log(log_line: str) -> Optional[str]:
    """
    Pull out the username from a log line.

    The extractor tries a few different patterns since the format varies:
    - "Invalid user <username>"
    - "Failed password for <username>"
    - "Accepted password for <username>"

    Args:
        log_line: The full line from the log file

    Returns:
        The username if the extractor found one, None otherwise
    """
    # Try a few different patterns, in order of preference
    patterns = [
        r"Invalid user\s+([a-zA-Z0-9._\-]+)",
        r"(?:Accepted|Failed) (?:password|publickey) for (?:invalid user )?([a-zA-Z0-9._\-]+)",
        r"user\s+([a-zA-Z0-9._\-]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, log_line)
        if match:
            return match.group(1)

    return None


def is_valid_ipv4(ip: str) -> bool:
    """
    Check if the IP address is actually valid.

    Makes sure it has 4 parts and each part is between 0 and 255.

    Args:
        ip: The IP address string to check

    Returns:
        True if it's valid, False if it's garbage
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False
