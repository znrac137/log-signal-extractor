"""
Detects suspicious SSH login patterns that indicate attacks.

This module identifies common exploitation techniques:
- Brute force: Someone hammering the same account over and over
- Password spray: Trying common passwords against many different accounts
- Account takeover: Finally getting in after dozens of failed attempts
"""

from datetime import datetime, timedelta
from typing import List
from collections import defaultdict
from extractor.models import LogEvent, Alert, AlertSeverity, EventType


class SuspiciousActivityDetector:
    """Detects suspicious authentication patterns in log events."""

    def __init__(self, config: dict = None):
        """
        Set up the detector with custom thresholds if needed.

        Args:
            config: Optional dict to tweak detection sensitivity
                - failed_login_threshold: How many failed attempts before the tool flags it (default: 5)
                - password_spray_threshold: How many different users is suspicious (default: 3)
                - time_window_minutes: How long to look back (default: 10)
        """
        self.config = config or {}
        self.failed_login_threshold = self.config.get("failed_login_threshold", 5)
        self.password_spray_threshold = self.config.get("password_spray_threshold", 3)
        self.time_window_minutes = self.config.get("time_window_minutes", 10)

    def detect_bruteforce(self, events: List[LogEvent]) -> List[Alert]:
        """
        Spot brute force attacks - when someone keeps hammering the same account.

        Here's the idea:
        - The tool collects all the failed login attempts by IP
        - If an IP has too many failures in a short time, it flags it

        What it means:
        Someone's trying password after password against an account. Classic attack.

        Args:
            events: All the log events to scan through

        Returns:
            Alerts for any brute force attempts the tool finds
        """
        alerts = []
        failed_by_ip = defaultdict(list)

        # Collect all failed attempts and group by IP
        for event in events:
            if event.event_type in [EventType.FAILED_PASSWORD, EventType.INVALID_USER]:
                failed_by_ip[event.ip_address].append(event)

        # Now check each IP to see if it looks like an attack
        for ip_address, attempts in failed_by_ip.items():
            if len(attempts) >= self.failed_login_threshold:
                # Sort by time and look at a time window
                sorted_attempts = sorted(attempts, key=lambda e: e.timestamp)
                time_window_start = sorted_attempts[0].timestamp
                time_window_end = time_window_start + timedelta(
                    minutes=self.time_window_minutes
                )

                windowed_attempts = [
                    e for e in sorted_attempts
                    if time_window_start <= e.timestamp <= time_window_end
                ]

                if len(windowed_attempts) >= self.failed_login_threshold:
                    affected_users = list(set(e.username for e in windowed_attempts))

                    alert = Alert(
                        alert_type="BRUTE_FORCE_ATTACK",
                        severity=AlertSeverity.HIGH,
                        source_ip=ip_address,
                        affected_usernames=affected_users,
                        event_count=len(windowed_attempts),
                        timestamp=datetime.now(),
                        description=f"Detected {len(windowed_attempts)} failed login attempts from {ip_address} in {self.time_window_minutes}min window. Possible brute force attack.",
                        events=windowed_attempts,
                    )
                    alerts.append(alert)

        return alerts

    def detect_password_spray(self, events: List[LogEvent]) -> List[Alert]:
        """
        Catch password spray attacks - trying one password against many accounts.

        Here's what the tool looks for:
        - One IP throws login attempts at a bunch of different usernames
        - Could be someone using a common password against everyone

        What it tells the operator:
        Different from brute force. Instead of hammering one account, they're trying
        the same password (or a few common ones) against everyone in the system.

        Args:
            events: All the log events the tool needs to scan

        Returns:
            Alerts for any spray attacks the tool finds
        """
        alerts = []
        attempts_by_ip = defaultdict(list)

        # Grab all the failed attempts and organize by IP
        for event in events:
            if event.event_type in [EventType.FAILED_PASSWORD, EventType.INVALID_USER]:
                attempts_by_ip[event.ip_address].append(event)

        # Check each IP to see if they're spraying
        for ip_address, attempts in attempts_by_ip.items():
            # Count how many different usernames got hit
            unique_usernames = set(e.username for e in attempts)

            if len(unique_usernames) >= self.password_spray_threshold:
                # Look at a specific time window
                sorted_attempts = sorted(attempts, key=lambda e: e.timestamp)
                time_window_start = sorted_attempts[0].timestamp
                time_window_end = time_window_start + timedelta(
                    minutes=self.time_window_minutes
                )

                windowed_attempts = [
                    e for e in sorted_attempts
                    if time_window_start <= e.timestamp <= time_window_end
                ]

                windowed_unique_users = set(e.username for e in windowed_attempts)

                if len(windowed_unique_users) >= self.password_spray_threshold:
                    alert = Alert(
                        alert_type="PASSWORD_SPRAY_ATTACK",
                        severity=AlertSeverity.HIGH,
                        source_ip=ip_address,
                        affected_usernames=list(windowed_unique_users),
                        event_count=len(windowed_attempts),
                        timestamp=datetime.now(),
                        description=f"Detected {len(windowed_attempts)} login attempts targeting {len(windowed_unique_users)} different users from {ip_address}. Possible password spray attack.",
                        events=windowed_attempts,
                    )
                    alerts.append(alert)

        return alerts

    def detect_success_after_fail(self, events: List[LogEvent]) -> List[Alert]:
        """
        Detect account takeovers - when someone finally gets in after a bunch of failed tries.

        Here's what this catches:
        - An attacker hammers an account with failures, then suddenly gets a successful login
        - That's a bad sign - they either guessed the password or found it elsewhere

        Why this is critical:
        Unlike the other alerts, this means they got in. The account is compromised.

        Args:
            events: All the log events to analyze

        Returns:
            Alerts for any accounts that look compromised
        """
        alerts = []

        # Group all events by IP + username combo
        attempt_chains = defaultdict(list)
        for event in events:
            key = (event.ip_address, event.username)
            attempt_chains[key].append(event)

        # Walk through each IP+username combination
        for (ip_address, username), chain in attempt_chains.items():
            sorted_chain = sorted(chain, key=lambda e: e.timestamp)

            failed_count = 0
            failure_events = []

            # Go through the events in order
            for event in sorted_chain:
                if event.event_type in [EventType.FAILED_PASSWORD, EventType.INVALID_USER]:
                    failed_count += 1
                    failure_events.append(event)
                elif event.event_type in [EventType.ACCEPTED_PASSWORD, EventType.ACCEPTED_PUBLICKEY]:
                    # Success! Check if it came after enough failures
                    if failed_count >= self.failed_login_threshold:
                        # Include all the failed attempts + the success
                        alert_events = failure_events + [event]

                        alert = Alert(
                            alert_type="SUCCESSFUL_LOGIN_AFTER_FAILURES",
                            severity=AlertSeverity.CRITICAL,
                            source_ip=ip_address,
                            affected_usernames=[username],
                            event_count=len(alert_events),
                            timestamp=datetime.now(),
                            description=f"Account {username} successfully accessed from {ip_address} after {failed_count} failed attempts. Possible account compromise.",
                            events=alert_events,
                        )
                        alerts.append(alert)
                        failed_count = 0
                        failure_events = []

        return alerts

    def detect_all(self, events: List[LogEvent]) -> List[Alert]:
        """
        Run all detection methods and aggregate results.

        Args:
            events: All the log events to scan

        Returns:
            A list of all alerts, sorted by severity
        """
        all_alerts = []
        all_alerts.extend(self.detect_bruteforce(events))
        all_alerts.extend(self.detect_password_spray(events))
        all_alerts.extend(self.detect_success_after_fail(events))

        # Sort by severity so the worst stuff shows up first
        all_alerts.sort(
            key=lambda a: (a.severity.value, a.timestamp),
            reverse=True
        )

        return all_alerts
