"""
Parser for SSH authentication logs (auth.log format).

Takes raw auth.log files and pulls out the useful bits - timestamps, usernames,
IPs, and what actually happened at each login attempt.
"""

from datetime import datetime
from typing import List, Optional
from extractor.models import LogEvent, EventType
from extractor.utils import (
    parse_timestamp,
    extract_ip_from_log,
    extract_username_from_log,
    is_valid_ipv4,
)


class AuthLogParser:
    """Reads SSH auth logs and pulls out useful information from each line."""

    # Patterns to detect authentication event types
    EVENT_PATTERNS = {
        EventType.INVALID_USER: r"Invalid user",
        EventType.FAILED_PASSWORD: r"Failed password",
        EventType.ACCEPTED_PASSWORD: r"Accepted password",
        EventType.ACCEPTED_PUBLICKEY: r"Accepted publickey",
        EventType.DISCONNECT: r"Disconnect",
    }

    def parse_file(self, file_path: str) -> List[LogEvent]:
        """
        Read the entire auth log file and parse every entry in it.

        Args:
            file_path: Path to the auth.log file you want to parse

        Returns:
            A list of all the parsed events

        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If it can't be read for some reason
        """
        events = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip()
                    if not line:
                        continue

                    event = self.parse_line(line)
                    if event:
                        events.append(event)
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except IOError as e:
            raise IOError(f"Error reading log file: {e}")

        return events

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """
        Parse a single line from the auth log file.

        Auth logs usually look like:
        "Jan  1 00:00:00 hostname sshd[pid]: Failed password for user from 1.2.3.4"

        Args:
            line: One line from the auth.log file

        Returns:
            A LogEvent if it can parse it, None if it skips it
        """
        # Skip lines that don't mention sshd
        if "sshd" not in line:
            return None

        # Pull out the timestamp from the beginning
        timestamp_parts = line.split()[:3]
        timestamp_str = " ".join(timestamp_parts)
        timestamp = parse_timestamp(timestamp_str)

        if not timestamp:
            return None

        # Figure out what kind of event this is
        event_type = self._detect_event_type(line)

        # Extract IP address
        ip_address = extract_ip_from_log(line)

        # Extract username
        username = extract_username_from_log(line)

        # Skip if it couldn't find both IP and username
        if not ip_address or not username:
            return None

        # Make sure the IP it found is actually valid
        if not is_valid_ipv4(ip_address):
            return None

        return LogEvent(
            timestamp=timestamp,
            username=username or "unknown",
            ip_address=ip_address,
            event_type=event_type,
            raw_line=line,
        )

    def _detect_event_type(self, line: str) -> EventType:
        """
        Look through the line to figure out what kind of event it is.

        Args:
            line: One line from the auth.log file

        Returns:
            The EventType that matches what it found (or UNKNOWN)
        """
        for event_type, pattern in self.EVENT_PATTERNS.items():
            if pattern in line:
                return event_type

        return EventType.UNKNOWN
