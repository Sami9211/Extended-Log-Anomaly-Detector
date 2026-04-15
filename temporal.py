# =============================================================================
# detectors/temporal.py — Time-based anomaly detection
# =============================================================================
# Detects anomalies that are only visible when you look at *when* events happen:
#
#   1. Off-hours activity  — Authentication or admin events outside business hours
#   2. Request bursts      — N events from one IP within a short time window
#   3. Impossible travel   — Same user from two IPs in geographically/logically
#                            different locations within a short window
#                            (simplified: same user, 2+ different IPs, <5 min)
#   4. Weekend/holiday     — Sensitive operations on a weekend
#   5. Slow-burn brute     — Low-rate auth failures spread over hours/days
#                            (evades rate-limit detectors)
# =============================================================================

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict
from models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from config import (BUSINESS_HOURS_START, BUSINESS_HOURS_END,
                    BURST_EVENT_COUNT, BURST_WINDOW_SECONDS,
                    SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD,
                    SEVERITY_MEDIUM_THRESHOLD)

AUTH_FAILURE_KEYWORDS = {"failed", "failure", "invalid", "denied", "error"}
AUTH_PROCESSES        = {"sshd", "su", "sudo", "login", "passwd", "pam",
                         "krb5", "kerberos", "winlogon"}
SENSITIVE_PROCESSES   = {"useradd", "userdel", "usermod", "passwd", "visudo",
                         "crontab", "at", "systemctl", "service"}


def run_temporal_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []

    # Sort entries by timestamp for time-based analysis
    timed = [e for e in entries if e.timestamp]
    timed.sort(key=lambda e: e.timestamp)

    findings.extend(_detect_off_hours_auth(timed))
    findings.extend(_detect_burst(timed))
    findings.extend(_detect_impossible_travel(timed))
    findings.extend(_detect_weekend_activity(timed))
    findings.extend(_detect_slow_brute(timed))

    return findings


# ---------------------------------------------------------------------------
# 1. Off-hours authentication / sensitive operations
# ---------------------------------------------------------------------------

def _detect_off_hours_auth(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    off_hours_by_key: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if not e.timestamp:
            continue

        hour = e.timestamp.hour
        is_off_hours = (hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END)
        if not is_off_hours:
            continue

        is_auth      = (e.process or "").lower() in AUTH_PROCESSES
        is_sensitive = (e.process or "").lower() in SENSITIVE_PROCESSES
        is_win_logon = e.event_id in ("4624", "4625", "4648", "4672", "4720", "4726")
        is_ssh_ok    = "accepted" in (e.message or "").lower() and is_auth

        if any([is_auth, is_sensitive, is_win_logon]):
            key = e.source_ip or e.username or "unknown"
            off_hours_by_key[key].append(e)

    for key, evts in off_hours_by_key.items():
        if len(evts) < 2:
            continue

        score = min(100, 45 + len(evts) * 2)
        ts_str = evts[0].timestamp.strftime("%H:%M") if evts[0].timestamp else "?"

        findings.append(AnomalyFinding(
            detector="Temporal Detector",
            finding_type="off_hours_auth_activity",
            description=(
                f"{len(evts)} authentication/sensitive events outside business hours "
                f"({BUSINESS_HOURS_START:02d}:00–{BUSINESS_HOURS_END:02d}:00) "
                f"from {key}. First event at {ts_str}."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=evts[0].source_ip,
            username=evts[0].username,
            timestamp=evts[0].timestamp,
            evidence=[e.raw[:200] for e in evts[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                url="https://attack.mitre.org/techniques/T1078/",
            )],
            count=len(evts),
        ))

    return findings


# ---------------------------------------------------------------------------
# 2. Request bursts (N events in Y seconds from same IP)
# ---------------------------------------------------------------------------

def _detect_burst(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    by_ip: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.source_ip and e.timestamp:
            by_ip[e.source_ip].append(e)

    for ip, evts in by_ip.items():
        evts_sorted = sorted(evts, key=lambda x: x.timestamp)
        window      = timedelta(seconds=BURST_WINDOW_SECONDS)

        # Sliding window
        left = 0
        for right in range(len(evts_sorted)):
            while (evts_sorted[right].timestamp -
                   evts_sorted[left].timestamp) > window:
                left += 1
            burst_count = right - left + 1
            if burst_count >= BURST_EVENT_COUNT:
                score = min(100, 50 + burst_count)
                findings.append(AnomalyFinding(
                    detector="Temporal Detector",
                    finding_type="request_burst",
                    description=(
                        f"IP {ip} sent {burst_count} requests in "
                        f"{BURST_WINDOW_SECONDS} seconds. "
                        f"Possible DDoS, brute force, or automated scanner."
                    ),
                    severity_score=score,
                    severity=_score_to_severity(score),
                    source_ip=ip,
                    timestamp=evts_sorted[left].timestamp,
                    evidence=[e.raw[:200] for e in evts_sorted[left:left+5]],
                    mitre_tags=[MitreTag(
                        technique_id="T1498",
                        technique_name="Network Denial of Service",
                        tactic="Impact",
                        url="https://attack.mitre.org/techniques/T1498/",
                    )],
                    count=burst_count,
                    extra={"window_seconds": BURST_WINDOW_SECONDS},
                ))
                break  # one finding per IP is enough

    return findings


# ---------------------------------------------------------------------------
# 3. Impossible travel (same user, 2+ IPs, short window)
# ---------------------------------------------------------------------------

def _detect_impossible_travel(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """
    Flag: user logged in from IP A, then IP B, within 5 minutes.
    (Real impossible travel would use GeoIP — here we flag same-user, different-IP.)
    """
    findings: List[AnomalyFinding] = []
    TRAVEL_WINDOW = timedelta(minutes=5)

    user_sessions: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.username and e.source_ip and e.timestamp:
            user_sessions[e.username].append(e)

    for user, evts in user_sessions.items():
        if len(evts) < 2:
            continue
        evts_sorted = sorted(evts, key=lambda x: x.timestamp)

        for i in range(1, len(evts_sorted)):
            prev = evts_sorted[i - 1]
            curr = evts_sorted[i]

            if curr.timestamp - prev.timestamp > TRAVEL_WINDOW:
                continue
            if prev.source_ip == curr.source_ip:
                continue

            findings.append(AnomalyFinding(
                detector="Temporal Detector",
                finding_type="impossible_travel",
                description=(
                    f"User '{user}' active from {prev.source_ip} then {curr.source_ip} "
                    f"within {int((curr.timestamp - prev.timestamp).total_seconds())} seconds. "
                    f"Possible account sharing, credential theft, or VPN switch."
                ),
                severity_score=70,
                severity=Severity.HIGH,
                username=user,
                source_ip=curr.source_ip,
                timestamp=curr.timestamp,
                evidence=[prev.raw[:200], curr.raw[:200]],
                mitre_tags=[MitreTag(
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic="Initial Access",
                    url="https://attack.mitre.org/techniques/T1078/",
                )],
                count=2,
                extra={"ip_a": prev.source_ip, "ip_b": curr.source_ip,
                       "delta_seconds": int((curr.timestamp - prev.timestamp).total_seconds())},
            ))

    return findings


# ---------------------------------------------------------------------------
# 4. Sensitive weekend activity
# ---------------------------------------------------------------------------

def _detect_weekend_activity(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    weekend_events: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if not e.timestamp:
            continue
        is_weekend   = e.timestamp.weekday() >= 5  # 5=Saturday, 6=Sunday
        is_sensitive = (
            (e.process or "").lower() in SENSITIVE_PROCESSES or
            e.event_id in ("4720", "4726", "4698", "7045", "1102", "4719")
        )
        if is_weekend and is_sensitive:
            key = e.username or e.source_ip or "unknown"
            weekend_events[key].append(e)

    for key, evts in weekend_events.items():
        if len(evts) < 1:
            continue
        score = min(100, 35 + len(evts) * 3)
        findings.append(AnomalyFinding(
            detector="Temporal Detector",
            finding_type="weekend_sensitive_activity",
            description=(
                f"{len(evts)} sensitive operations on a weekend by {key}. "
                f"User account changes, service installs, or audit policy "
                f"changes outside working days warrant investigation."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            username=evts[0].username,
            source_ip=evts[0].source_ip,
            timestamp=evts[0].timestamp,
            evidence=[e.raw[:200] for e in evts[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactic="Persistence",
                url="https://attack.mitre.org/techniques/T1098/",
            )],
            count=len(evts),
        ))

    return findings


# ---------------------------------------------------------------------------
# 5. Slow-burn brute force (spread over hours)
# ---------------------------------------------------------------------------

def _detect_slow_brute(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """
    Detect auth failures that are spread slowly to evade rate limits.
    Threshold: 10+ failures from same source over > 30 minutes.
    """
    findings: List[AnomalyFinding] = []
    fail_by_src: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        is_fail = (
            any(w in (e.message or "").lower() for w in AUTH_FAILURE_KEYWORDS)
            and (e.process or "").lower() in AUTH_PROCESSES
        ) or e.event_id == "4625"

        if is_fail and e.timestamp:
            key = e.source_ip or e.username or "unknown"
            fail_by_src[key].append(e)

    for src, evts in fail_by_src.items():
        if len(evts) < 10:
            continue
        evts_sorted = sorted(evts, key=lambda x: x.timestamp)
        duration    = evts_sorted[-1].timestamp - evts_sorted[0].timestamp
        if duration < timedelta(minutes=30):
            continue  # Fast brute — already caught by rate detector

        score = min(100, 50 + len(evts))
        findings.append(AnomalyFinding(
            detector="Temporal Detector",
            finding_type="slow_brute_force",
            description=(
                f"{len(evts)} auth failures from {src} spread over "
                f"{_fmt_duration(duration)}. "
                f"Low-rate brute force designed to evade rate-limit detection."
            ),
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=evts_sorted[0].source_ip,
            username=evts_sorted[0].username,
            timestamp=evts_sorted[0].timestamp,
            evidence=[e.raw[:200] for e in evts_sorted[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1110.003",
                technique_name="Password Spraying",
                tactic="Credential Access",
                url="https://attack.mitre.org/techniques/T1110/003/",
            )],
            count=len(evts),
            extra={"duration_minutes": int(duration.total_seconds() / 60)},
        ))

    return findings


def _fmt_duration(td: timedelta) -> str:
    total = int(td.total_seconds())
    h, m  = divmod(total // 60, 60)
    return f"{h}h {m}m" if h else f"{m}m"


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW
