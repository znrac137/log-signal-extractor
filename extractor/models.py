"""
Data models for Log Signal Extractor.

These are the main data types the extractor works with - parsed log entries and the alerts it generates.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
from enum import Enum


class EventType(Enum):
    """Authentication event types extracted from logs."""
    INVALID_USER = "Invalid user"
    FAILED_PASSWORD = "Failed password"
    ACCEPTED_PASSWORD = "Accepted password"
    ACCEPTED_PUBLICKEY = "Accepted publickey"
    DISCONNECT = "Disconnect"
    UNKNOWN = "Unknown"


class AlertSeverity(Enum):
    """Security alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LogEvent:
    """
    A single parsed entry from the auth log.

    This is what the extractor gets after parsing a line - all the useful info extracted
    and organized so it can work with it.

    Attributes:
        timestamp: When this login attempt happened
        username: Who was trying to log in
        ip_address: Where the attempt came from
        event_type: What kind of event it was (failed, accepted, etc.)
        raw_line: The original line from the log file, just in case
    """
    timestamp: datetime
    username: str
    ip_address: str
    event_type: EventType
    raw_line: str

    def to_dict(self) -> dict:
        """Turn the event into a dict so it can be converted to JSON."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "ip_address": self.ip_address,
            "event_type": self.event_type.value,
            "raw_line": self.raw_line,
        }


@dataclass
class Alert:
    """
    A security alert generated from detected suspicious activity.

    When the detection algorithms spot something suspicious, they create one of these
    with all the details about what they found.

    Attributes:
        alert_type: What kind of attack the extractor detected (brute force, spray, etc.)
        severity: How bad is it (LOW, MEDIUM, HIGH, CRITICAL)
        source_ip: The IP address doing the attacking
        affected_usernames: Which accounts were targeted
        event_count: How many events led to this alert
        timestamp: When the extractor generated this alert
        description: A human-readable summary of what happened
        events: The actual log events that triggered this alert
    """
    alert_type: str
    severity: AlertSeverity
    source_ip: str
    affected_usernames: list[str]
    event_count: int
    timestamp: datetime
    description: str
    events: list[LogEvent]

    def to_dict(self) -> dict:
        """Turn the alert into a dict so it can be output as JSON."""
        return {
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "affected_usernames": self.affected_usernames,
            "event_count": self.event_count,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "events": [event.to_dict() for event in self.events],
        }
