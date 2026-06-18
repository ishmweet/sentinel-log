"""
detector.py — Threat detection engine for SentinelLog.

Each Detection class takes the parsed records produced by parser.py
and produces a list of Alert objects.  Rules are deliberately simple and
readable — this is an educational tool, so the logic should be auditable
by a first-year student.

Detection rules
───────────────
Auth logs
  • Brute Force        — ≥ 5 failed logins from a single IP

Apache logs
  • Admin Panel Scan   — requests to /admin*, /administrator*
  • WordPress Recon    — requests to /wp-login.php, /wp-admin*, /xmlrpc.php
  • Sensitive File Probe — requests to /.env*, /config*, /phpmyadmin*, /pma*,
                           /.git*, backup files, db dumps
  • SQL Injection Probe — suspicious query-string patterns (UNION, OR 1=1, etc.)
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import TYPE_CHECKING

from sentinellog.utils import Alert, SeverityLevel

if TYPE_CHECKING:
    from sentinellog.parser import ApacheRecord, AuthRecord



BRUTE_FORCE_THRESHOLD = 5



class AuthDetector:
    """Run detection rules against a list of AuthRecord dicts."""

    def detect(self, records: list[AuthRecord]) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._brute_force(records))
        return alerts


    def _brute_force(self, records: list[AuthRecord]) -> list[Alert]:
        """
        Flag any IP that has >= BRUTE_FORCE_THRESHOLD failed login attempts.

        Severity scales with attempt count:
          ≥ 15 → CRITICAL
          ≥ 10 → HIGH
          ≥  5 → MEDIUM
        """
        fail_counts: Counter[str] = Counter()
        usernames_tried: defaultdict[str, set[str]] = defaultdict(set)

        for r in records:
            if r["status"] == "LOGIN_FAILED":
                fail_counts[r["ip"]] += 1
                usernames_tried[r["ip"]].add(r["user"])

        alerts: list[Alert] = []
        for ip, count in fail_counts.items():
            if count < BRUTE_FORCE_THRESHOLD:
                continue

            if count >= 15:
                severity: SeverityLevel = "CRITICAL"
            elif count >= 10:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            users = ", ".join(sorted(usernames_tried[ip])[:5])
            if len(usernames_tried[ip]) > 5:
                users += f" … (+{len(usernames_tried[ip]) - 5} more)"

            alerts.append(
                Alert(
                    alert_type="Brute Force",
                    severity=severity,
                    source_ip=ip,
                    description=(
                        f"{count} failed login attempts detected. "
                        f"Usernames tried: {users}."
                    ),
                )
            )

        return alerts



_ADMIN_PATHS = re.compile(
    r"^/(admin|administrator|adminpanel|manage|management|backend)",
    re.IGNORECASE,
)

_WP_PATHS = re.compile(
    r"/(wp-login\.php|wp-admin|xmlrpc\.php|wp-content|wp-includes)",
    re.IGNORECASE,
)

_SENSITIVE_PATHS = re.compile(
    r"/(\.env|config\.(php|yml|yaml|json|ini)|phpmyadmin|pma"
    r"|\.git|\.svn|backup|db\.sql|dump\.sql|\.htaccess|server-status"
    r"|crossdomain\.xml|\.DS_Store|web\.config)",
    re.IGNORECASE,
)

_SQLI_PATTERNS = re.compile(
    r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|--\s|'--"
    r"|;\s*drop|information_schema|sleep\s*\(|benchmark\s*\()",
    re.IGNORECASE,
)


class ApacheDetector:
    """Run detection rules against a list of ApacheRecord dicts."""

    def detect(self, records: list[ApacheRecord]) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._admin_scan(records))
        alerts.extend(self._wordpress_recon(records))
        alerts.extend(self._sensitive_probe(records))
        alerts.extend(self._sqli_probe(records))
        return alerts


    def _admin_scan(self, records: list[ApacheRecord]) -> list[Alert]:
        """
        Detect IPs that probe admin paths.  One alert per unique IP.
        Severity depends on hit count: ≥ 3 hits → HIGH, else MEDIUM.
        """
        hits: defaultdict[str, list[str]] = defaultdict(list)
        for r in records:
            if _ADMIN_PATHS.match(r["url"]):
                hits[r["ip"]].append(r["url"])

        alerts: list[Alert] = []
        for ip, urls in hits.items():
            severity: SeverityLevel = "HIGH" if len(urls) >= 3 else "MEDIUM"
            unique_urls = list(dict.fromkeys(urls))[:5]   # dedupe, keep order
            alerts.append(
                Alert(
                    alert_type="Admin Panel Scan",
                    severity=severity,
                    source_ip=ip,
                    description=(
                        f"{len(urls)} request(s) to admin endpoints. "
                        f"Paths: {', '.join(unique_urls)}."
                    ),
                )
            )
        return alerts


    def _wordpress_recon(self, records: list[ApacheRecord]) -> list[Alert]:
        """
        Group WordPress-related requests by IP.
        ≥ 4 requests → HIGH (likely credential stuffing or plugin enum);
        otherwise MEDIUM.
        """
        hits: defaultdict[str, list[str]] = defaultdict(list)
        for r in records:
            if _WP_PATHS.search(r["url"]):
                hits[r["ip"]].append(r["url"])

        alerts: list[Alert] = []
        for ip, urls in hits.items():
            severity: SeverityLevel = "HIGH" if len(urls) >= 4 else "MEDIUM"
            unique_urls = list(dict.fromkeys(urls))[:5]
            alerts.append(
                Alert(
                    alert_type="WordPress Reconnaissance",
                    severity=severity,
                    source_ip=ip,
                    description=(
                        f"{len(urls)} request(s) to WordPress endpoints. "
                        f"Paths: {', '.join(unique_urls)}."
                    ),
                )
            )
        return alerts


    def _sensitive_probe(self, records: list[ApacheRecord]) -> list[Alert]:
        """
        Requests to config files, environment files, database dumps, etc.
        ≥ 5 different sensitive paths → HIGH (indicates automated scanner);
        otherwise MEDIUM.
        """
        hits: defaultdict[str, list[str]] = defaultdict(list)
        for r in records:
            if _SENSITIVE_PATHS.search(r["url"]):
                hits[r["ip"]].append(r["url"])

        alerts: list[Alert] = []
        for ip, urls in hits.items():
            severity: SeverityLevel = "HIGH" if len(set(urls)) >= 5 else "MEDIUM"
            unique_urls = list(dict.fromkeys(urls))[:5]
            alerts.append(
                Alert(
                    alert_type="Sensitive File Probe",
                    severity=severity,
                    source_ip=ip,
                    description=(
                        f"{len(urls)} request(s) to sensitive paths. "
                        f"Files: {', '.join(unique_urls)}."
                    ),
                )
            )
        return alerts


    def _sqli_probe(self, records: list[ApacheRecord]) -> list[Alert]:
        """
        Look for SQL-injection payloads embedded in the request URL.
        Any match is HIGH — SQL injection attempts are always a serious signal.
        """
        hits: defaultdict[str, list[str]] = defaultdict(list)
        for r in records:
            if _SQLI_PATTERNS.search(r["url"]):
                hits[r["ip"]].append(r["url"])

        alerts: list[Alert] = []
        for ip, urls in hits.items():
            sample = urls[0][:80]
            alerts.append(
                Alert(
                    alert_type="SQL Injection Probe",
                    severity="HIGH",
                    source_ip=ip,
                    description=(
                        f"{len(urls)} request(s) with SQLi patterns. "
                        f"Sample: {sample}."
                    ),
                )
            )
        return alerts
