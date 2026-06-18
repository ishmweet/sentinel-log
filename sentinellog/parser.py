"""
parser.py — Log file parsers for SentinelLog.

Two parsers live here:
  • AuthLogParser  — handles auth/SSH-style logs
  • ApacheLogParser — handles Apache Combined Log Format

Each parser reads a file line-by-line and returns a list of structured dicts
that the rest of the pipeline can work with without touching raw strings.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict

from sentinellog.utils import (
    extract_apache_timestamp,
    extract_auth_timestamp,
    is_valid_ipv4,
)



class AuthRecord(TypedDict):
    timestamp: str
    ip:        str
    status:    str
    user:      str


class ApacheRecord(TypedDict):
    timestamp:  str
    ip:         str
    method:     str
    url:        str
    protocol:   str
    status_code: int
    bytes_sent:  int
    user_agent:  str


_AUTH_RE = re.compile(
    r"(?P<ip>[\d.]+)"
    r"\s+(?P<status>LOGIN_FAILED|LOGIN_SUCCESS)"
    r"(?:\s+user=(?P<user>\S+))?"
)


class AuthLogParser:
    """Parse authentication log files into a list of AuthRecord dicts."""

    def parse(self, filepath: str | Path) -> list[AuthRecord]:
        """
        Read *filepath* and return every parseable line as an AuthRecord.

        Lines that do not match the expected pattern are silently skipped
        so that partial or malformed logs don't crash the tool.
        """
        records: list[AuthRecord] = []
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                m = _AUTH_RE.search(line)
                if not m:
                    continue

                ip = m.group("ip")
                if not is_valid_ipv4(ip):
                    continue

                records.append(
                    AuthRecord(
                        timestamp=extract_auth_timestamp(line),
                        ip=ip,
                        status=m.group("status"),
                        user=m.group("user") or "unknown",
                    )
                )

        return records


_APACHE_RE = re.compile(
    r'(?P<ip>[\d.]+)'
    r'\s+\S+\s+\S+'
    r'\s+\[(?P<ts>[^\]]+)\]'
    r'\s+"(?P<method>\S+)'
    r'\s+(?P<url>\S+)'
    r'\s+(?P<proto>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<bytes>\d+|-)'
    r'(?:\s+"[^"]*"'
    r'\s+"(?P<ua>[^"]*)")?'
)


class ApacheLogParser:
    """Parse Apache Combined Log Format files into a list of ApacheRecord dicts."""

    def parse(self, filepath: str | Path) -> list[ApacheRecord]:
        """
        Read *filepath* and return every parseable line as an ApacheRecord.
        Malformed lines are skipped.
        """
        records: list[ApacheRecord] = []
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                m = _APACHE_RE.match(line)
                if not m:
                    continue

                ip = m.group("ip")
                if not is_valid_ipv4(ip):
                    continue

                bytes_raw = m.group("bytes")
                bytes_sent = int(bytes_raw) if bytes_raw.isdigit() else 0

                records.append(
                    ApacheRecord(
                        timestamp=extract_apache_timestamp(m.group("ts")),
                        ip=ip,
                        method=m.group("method"),
                        url=m.group("url"),
                        protocol=m.group("proto").strip(),
                        status_code=int(m.group("status")),
                        bytes_sent=bytes_sent,
                        user_agent=m.group("ua") or "",
                    )
                )

        return records



def detect_log_type(filepath: str | Path) -> str:
    """
    Sniff the first non-empty line of a file to decide whether it looks like
    an auth log or an Apache log.

    Returns 'auth' or 'apache'.  Raises ValueError if neither pattern matches.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if "LOGIN_FAILED" in line or "LOGIN_SUCCESS" in line:
                return "auth"
            if _APACHE_RE.match(line):
                return "apache"
            break

    raise ValueError(
        f"Cannot determine log type for '{filepath}'.\n"
        "Expected an auth log (LOGIN_FAILED/LOGIN_SUCCESS) "
        "or Apache Combined Log Format."
    )
