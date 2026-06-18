"""
utils.py — Shared helpers, constants, and type definitions for SentinelLog.

Keeps the rest of the codebase clean by centralizing things that don't
belong in any one module: severity levels, timestamp handling, IP validation,
and the dataclass that every alert in the system is built on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER: dict[SeverityLevel, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}

SEVERITY_ICONS: dict[str, str] = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


@dataclass
class Alert:
    """
    A single detected security event.

    Every detection rule in detector.py produces one or more Alert objects.
    The reporter and exporter then consume this list without caring how
    the alert was generated.
    """
    alert_type:  str
    severity:    SeverityLevel
    source_ip:   str
    description: str
    timestamp:   str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    def to_dict(self) -> dict:
        """Return a plain dict — used for JSON / CSV export."""
        return {
            "timestamp":   self.timestamp,
            "alert_type":  self.alert_type,
            "severity":    self.severity,
            "source_ip":   self.source_ip,
            "description": self.description,
        }



_IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
)


def is_valid_ipv4(addr: str) -> bool:
    """Return True if *addr* looks like a valid dotted-quad IPv4 address."""
    return bool(_IPV4_RE.match(addr.strip()))



_AUTH_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

_APACHE_TS_RE = re.compile(r"(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})")
_APACHE_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def extract_auth_timestamp(line: str) -> str:
    """Pull a timestamp from an auth log line, or return empty string."""
    m = _AUTH_TS_RE.search(line)
    return m.group(1) if m else ""


def extract_apache_timestamp(raw: str) -> str:
    """
    Convert an Apache timestamp like '15/Jan/2024:08:00:01' into
    ISO format '2024-01-15 08:00:01'.  Returns empty string on failure.
    """
    m = _APACHE_TS_RE.search(raw)
    if not m:
        return ""
    parts = m.group(1).split(":")
    date_part = parts[0]
    time_part = ":".join(parts[1:])
    day, mon_str, year = date_part.split("/")
    month = _APACHE_MONTHS.get(mon_str, "01")
    return f"{year}-{month}-{day.zfill(2)} {time_part}"



def truncate(text: str, max_len: int = 60) -> str:
    """Shorten *text* to *max_len* chars and add '…' if needed."""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"
