"""
analyzer.py — Orchestration layer for SentinelLog.

AnalysisResult holds every piece of data the reporter needs:
  • raw record counts
  • top-N breakdowns (IPs, URLs, status codes, …)
  • the Alert list produced by the detector

LogAnalyzer.analyze() is the single entry point called by main.py.
It:
  1. detects the log type
  2. parses the file
  3. computes statistics
  4. runs the detector
  5. returns an AnalysisResult
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from sentinellog.detector import ApacheDetector, AuthDetector
from sentinellog.parser import (
    ApacheLogParser,
    AuthLogParser,
    detect_log_type,
)
from sentinellog.utils import Alert


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    """
    All data produced by a single analysis run.

    Attributes shared by both log types
    ------------------------------------
    log_type    : 'auth' or 'apache'
    log_file    : path to the source file
    total_lines : number of parseable records
    alerts      : detected security events
    top_ips     : most active source IPs

    Auth-log specific
    -----------------
    total_failed  : total LOGIN_FAILED events
    total_success : total LOGIN_SUCCESS events
    unique_ips    : number of distinct IPs seen

    Apache-log specific
    -------------------
    top_urls           : most requested URLs
    status_code_counts : Counter of HTTP status codes
    total_404s         : count of 404 responses
    """
    log_type:    str
    log_file:    str
    total_lines: int
    alerts:      list[Alert]
    top_ips:     list[tuple[str, int]]

    # Auth fields
    total_failed:  int = 0
    total_success: int = 0
    unique_ips:    int = 0

    # Apache fields
    top_urls:            list[tuple[str, int]] = field(default_factory=list)
    status_code_counts:  Counter               = field(default_factory=Counter)
    total_404s:          int                   = 0


# ── Analyzer ──────────────────────────────────────────────────────────────────

class LogAnalyzer:
    """
    Detect log type, parse, compute statistics, and run threat detection.

    Usage
    -----
    >>> result = LogAnalyzer().analyze("logs/sample_auth.log")
    """

    TOP_N = 10   # how many items to include in each top-N list

    def analyze(self, filepath: str | Path) -> AnalysisResult:
        """
        Full analysis pipeline for *filepath*.

        Raises
        ------
        FileNotFoundError  — file does not exist
        ValueError         — log type cannot be determined
        """
        filepath = Path(filepath)

        # Step 1 — detect log type
        log_type = detect_log_type(filepath)

        if log_type == "auth":
            return self._analyze_auth(filepath)
        else:
            return self._analyze_apache(filepath)

    # ── Auth analysis ─────────────────────────────────────────────────────────

    def _analyze_auth(self, filepath: Path) -> AnalysisResult:
        records = AuthLogParser().parse(filepath)

        # Stats
        ip_counter:   Counter[str] = Counter()
        fail_counter: Counter[str] = Counter()
        total_failed  = 0
        total_success = 0

        for r in records:
            ip_counter[r["ip"]] += 1
            if r["status"] == "LOGIN_FAILED":
                total_failed += 1
                fail_counter[r["ip"]] += 1
            else:
                total_success += 1

        # Alerts
        alerts = AuthDetector().detect(records)

        return AnalysisResult(
            log_type="auth",
            log_file=str(filepath),
            total_lines=len(records),
            alerts=alerts,
            top_ips=ip_counter.most_common(self.TOP_N),
            total_failed=total_failed,
            total_success=total_success,
            unique_ips=len(ip_counter),
        )

    # ── Apache analysis ───────────────────────────────────────────────────────

    def _analyze_apache(self, filepath: Path) -> AnalysisResult:
        records = ApacheLogParser().parse(filepath)

        ip_counter:     Counter[str] = Counter()
        url_counter:    Counter[str] = Counter()
        status_counter: Counter[int] = Counter()

        for r in records:
            ip_counter[r["ip"]]          += 1
            url_counter[r["url"]]        += 1
            status_counter[r["status_code"]] += 1

        total_404s = status_counter.get(404, 0)

        # Alerts
        alerts = ApacheDetector().detect(records)

        return AnalysisResult(
            log_type="apache",
            log_file=str(filepath),
            total_lines=len(records),
            alerts=alerts,
            top_ips=ip_counter.most_common(self.TOP_N),
            top_urls=url_counter.most_common(self.TOP_N),
            status_code_counts=status_counter,
            total_404s=total_404s,
        )
