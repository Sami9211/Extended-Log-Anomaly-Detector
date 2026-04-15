# =============================================================================
# detectors/statistical.py — Z-score and rate-based anomaly detection
# =============================================================================
# Uses statistical methods to find anomalies without needing known signatures.
# Useful for detecting novel or slow-burn attacks that don't match patterns.
#
# Detectors:
#   1. Request rate spike — per-IP requests/minute
#   2. Error rate spike   — sudden surge in HTTP 4xx/5xx errors
#   3. Bytes transferred  — abnormally large responses (potential data leak)
#   4. Failed auth rate   — per-user or per-IP auth failures
#   5. Unique path count  — IP hitting too many unique URLs (scanner behaviour)
# =============================================================================

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Tuple
from models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from config import (ZSCORE_THRESHOLD, RATE_SPIKE_RPM_THRESHOLD,
                    ERROR_RATE_THRESHOLD_PCT,
                    SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD,
                    SEVERITY_MEDIUM_THRESHOLD)


def run_statistical_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []

    findings.extend(_detect_request_rate_spike(entries))
    findings.extend(_detect_error_rate_spike(entries))
    findings.extend(_detect_bytes_anomaly(entries))
    findings.extend(_detect_auth_failure_rate(entries))
    findings.extend(_detect_path_enumeration_rate(entries))

    return findings


# ---------------------------------------------------------------------------
# 1. Request rate spike per IP
# ---------------------------------------------------------------------------

def _detect_request_rate_spike(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """Flag IPs whose requests-per-minute exceeds the threshold or is a Z-score outlier."""
    findings: List[AnomalyFinding] = []
    rpm_by_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for e in entries:
        if not e.source_ip or not e.timestamp:
            continue
        bucket = e.timestamp.strftime("%Y-%m-%d %H:%M")
        rpm_by_ip[e.source_ip][bucket] += 1

    # Per-IP max RPM
    ip_max_rpm: Dict[str, int] = {}
    ip_evidence: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.source_ip:
            ip_evidence[e.source_ip].append(e)

    for ip, buckets in rpm_by_ip.items():
        ip_max_rpm[ip] = max(buckets.values())

    if not ip_max_rpm:
        return findings

    all_rpms = list(ip_max_rpm.values())
    mean, std = _mean_std(all_rpms)

    for ip, max_rpm in ip_max_rpm.items():
        z = (max_rpm - mean) / std if std > 0 else 0
        threshold_hit = max_rpm >= RATE_SPIKE_RPM_THRESHOLD
        zscore_hit    = z >= ZSCORE_THRESHOLD

        if not (threshold_hit or zscore_hit):
            continue

        score = min(100, 40 + int(z * 10))
        ev = ip_evidence[ip]

        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="request_rate_spike",
            description=(
                f"IP {ip} sent {max_rpm} requests/minute "
                f"(Z-score: {z:.1f}, threshold: {RATE_SPIKE_RPM_THRESHOLD} RPM). "
                f"Possible brute force or DDoS."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=ip,
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                url="https://attack.mitre.org/techniques/T1110/",
            )],
            count=sum(rpm_by_ip[ip].values()),
            extra={"max_rpm": max_rpm, "z_score": round(z, 2)},
        ))

    return findings


# ---------------------------------------------------------------------------
# 2. HTTP error rate spike
# ---------------------------------------------------------------------------

def _detect_error_rate_spike(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """Detect time windows where error responses (4xx/5xx) exceed threshold."""
    findings: List[AnomalyFinding] = []

    # Bucket by 5-minute windows
    windows: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "errors": 0})
    window_entries: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.http_status is None or not e.timestamp:
            continue
        minute = e.timestamp.replace(second=0, microsecond=0)
        # Round to 5-minute window
        bucket_minute = minute - timedelta(minutes=minute.minute % 5)
        bucket = bucket_minute.strftime("%Y-%m-%d %H:%M")
        windows[bucket]["total"] += 1
        if e.http_status >= 400:
            windows[bucket]["errors"] += 1
        window_entries[bucket].append(e)

    for bucket, counts in windows.items():
        total = counts["total"]
        if total < 10:
            continue  # not enough data
        error_pct = (counts["errors"] / total) * 100
        if error_pct < ERROR_RATE_THRESHOLD_PCT:
            continue

        score = min(100, int(error_pct))
        ev    = window_entries[bucket]

        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="error_rate_spike",
            description=(
                f"{error_pct:.0f}% error rate in window {bucket} "
                f"({counts['errors']}/{total} requests). "
                f"May indicate scanning, attack, or application failure."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic="Reconnaissance",
                url="https://attack.mitre.org/techniques/T1595/",
            )],
            count=total,
            extra={"error_pct": round(error_pct, 1), "window": bucket},
        ))

    return findings


# ---------------------------------------------------------------------------
# 3. Abnormal bytes transferred (Z-score)
# ---------------------------------------------------------------------------

def _detect_bytes_anomaly(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """Flag HTTP responses with abnormally large byte counts (potential data exfiltration)."""
    findings: List[AnomalyFinding] = []
    byte_entries = [(e, e.bytes_sent) for e in entries
                    if e.bytes_sent is not None and e.bytes_sent > 0]

    if len(byte_entries) < 20:
        return findings  # Not enough data for statistics

    all_bytes = [b for _, b in byte_entries]
    mean, std = _mean_std(all_bytes)

    if std == 0:
        return findings

    for entry, b in byte_entries:
        z = (b - mean) / std
        if z < ZSCORE_THRESHOLD:
            continue

        score = min(100, 45 + int(z * 8))
        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="large_response_bytes",
            description=(
                f"Unusually large response: {b:,} bytes "
                f"(Z-score: {z:.1f}, mean: {mean:,.0f}). "
                f"Possible data exfiltration or misconfiguration."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=entry.source_ip,
            timestamp=entry.timestamp,
            evidence=[entry.raw[:200]],
            mitre_tags=[MitreTag(
                technique_id="T1030",
                technique_name="Data Transfer Size Limits",
                tactic="Exfiltration",
                url="https://attack.mitre.org/techniques/T1030/",
            )],
            count=1,
            extra={"bytes": b, "z_score": round(z, 2), "mean_bytes": round(mean, 0)},
        ))

    return findings


# ---------------------------------------------------------------------------
# 4. Auth failure rate per source
# ---------------------------------------------------------------------------

def _detect_auth_failure_rate(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """Detect per-IP or per-user authentication failure rates above normal."""
    findings: List[AnomalyFinding] = []
    FAILURE_KEYWORDS = {"failed", "failure", "invalid", "error", "denied", "locked"}
    AUTH_PROCESSES   = {"sshd", "su", "sudo", "login", "passwd", "pam", "krb5", "kerberos"}

    fail_by_key: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        # Syslog auth failures
        is_auth = (e.process or "").lower() in AUTH_PROCESSES
        is_fail = any(w in (e.message or "").lower() for w in FAILURE_KEYWORDS)
        # Windows Event 4625
        is_win_fail = e.event_id == "4625"

        if (is_auth and is_fail) or is_win_fail:
            key = e.source_ip or e.username or "unknown"
            fail_by_key[key].append(e)

    for key, fail_entries in fail_by_key.items():
        count = len(fail_entries)
        if count < 5:
            continue

        score = min(100, 35 + min(count, 60))
        ev    = fail_entries

        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="auth_failure_spike",
            description=(
                f"{count} authentication failures from {key}. "
                f"Possible brute force or credential stuffing."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=ev[0].source_ip,
            username=ev[0].username,
            timestamp=ev[0].timestamp,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1110.001",
                technique_name="Password Guessing",
                tactic="Credential Access",
                url="https://attack.mitre.org/techniques/T1110/001/",
            )],
            count=count,
            extra={"fail_count": count, "source": key},
        ))

    return findings


# ---------------------------------------------------------------------------
# 5. Path enumeration rate per IP
# ---------------------------------------------------------------------------

def _detect_path_enumeration_rate(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """Flag IPs that hit an unusually high number of unique paths (scanner behaviour)."""
    findings: List[AnomalyFinding] = []
    paths_by_ip: Dict[str, set] = defaultdict(set)
    ev_by_ip:   Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.source_ip and e.http_path:
            paths_by_ip[e.source_ip].add(e.http_path)
            ev_by_ip[e.source_ip].append(e)

    if not paths_by_ip:
        return findings

    unique_counts = [len(p) for p in paths_by_ip.values()]
    mean, std = _mean_std(unique_counts)

    for ip, paths in paths_by_ip.items():
        count = len(paths)
        z = (count - mean) / std if std > 0 else 0
        if z < ZSCORE_THRESHOLD or count < 20:
            continue

        score = min(100, 40 + int(z * 8))
        ev    = ev_by_ip[ip]

        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="path_enumeration",
            description=(
                f"IP {ip} accessed {count} unique paths "
                f"(Z-score: {z:.1f}). "
                f"Consistent with directory/content scanning."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=ip,
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1595.003",
                technique_name="Wordlist Scanning",
                tactic="Reconnaissance",
                url="https://attack.mitre.org/techniques/T1595/003/",
            )],
            count=count,
            extra={"unique_paths": count, "z_score": round(z, 2)},
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mean_std(values: List[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    n    = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return mean, math.sqrt(variance)


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW
