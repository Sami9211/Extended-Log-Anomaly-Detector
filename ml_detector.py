# =============================================================================
# detectors/ml_detector.py — Isolation Forest unsupervised ML anomaly detection
# =============================================================================
# Uses scikit-learn's Isolation Forest algorithm — a tree-based ensemble that
# identifies anomalies by isolating data points. Points requiring fewer splits
# to isolate are more anomalous.
#
# No labelled data needed. Purely unsupervised.
#
# Feature vector per IP (aggregated over the whole log file):
#   - total_requests        : volume
#   - unique_paths          : breadth of access
#   - error_rate_pct        : proportion of 4xx/5xx responses
#   - avg_bytes             : average response size
#   - unique_user_agents    : number of distinct UAs (bots often rotate)
#   - requests_per_minute   : average rate
#   - auth_failures         : count of failed auth events
#   - off_hours_ratio       : proportion of requests outside business hours
#   - post_ratio            : proportion of POST requests (upload/injection risk)
# =============================================================================

from collections import defaultdict
from typing import List, Dict, Any
from datetime import timezone
from models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from config import (ML_CONTAMINATION, ML_N_ESTIMATORS,
                    BUSINESS_HOURS_START, BUSINESS_HOURS_END,
                    SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD,
                    SEVERITY_MEDIUM_THRESHOLD, ENABLE_ML_DETECTOR)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


AUTH_FAILURE_KEYWORDS = {"failed", "failure", "invalid", "denied"}
AUTH_PROCESSES        = {"sshd", "su", "sudo", "login", "passwd", "pam"}


def run_ml_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    if not ENABLE_ML_DETECTOR:
        return []

    if not ML_AVAILABLE:
        return [AnomalyFinding(
            detector="ML Detector",
            finding_type="ml_unavailable",
            description="scikit-learn not installed. Run: pip install scikit-learn numpy",
            severity_score=0,
            severity=Severity.INFO,
            count=0,
        )]

    features, ip_list, ip_entries = _build_feature_matrix(entries)

    if len(features) < 5:
        return []  # Not enough distinct sources for meaningful ML

    X = np.array(features, dtype=float)

    # Handle NaN/inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=ML_N_ESTIMATORS,
        contamination=ML_CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    predictions    = model.fit_predict(X_scaled)   # -1 = anomaly, 1 = normal
    anomaly_scores = model.score_samples(X_scaled)  # More negative = more anomalous

    # Normalise scores to 0-100 (invert: lower score = higher anomaly)
    min_score = anomaly_scores.min()
    max_score = anomaly_scores.max()
    score_range = max_score - min_score if max_score != min_score else 1.0

    findings: List[AnomalyFinding] = []

    for idx, (pred, raw_score) in enumerate(zip(predictions, anomaly_scores)):
        if pred != -1:
            continue  # Not flagged as anomaly

        ip      = ip_list[idx]
        feat    = features[idx]
        ev      = ip_entries[ip]

        # Normalised severity score: 0-100 where 100 = most anomalous
        normalised = int(((raw_score - min_score) / score_range) * 100)
        sev_score  = max(25, 100 - normalised)  # invert: lower raw = higher risk

        findings.append(AnomalyFinding(
            detector="ML Detector (Isolation Forest)",
            finding_type="ml_behavioural_anomaly",
            description=_build_description(ip, feat, sev_score),
            severity_score=sev_score,
            severity=_score_to_severity(sev_score),
            source_ip=ip if ip != "unknown" else None,
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic="Reconnaissance",
                url="https://attack.mitre.org/techniques/T1595/",
            )],
            count=int(feat[0]),
            extra=_feature_dict(feat),
        ))

    return findings


def _build_feature_matrix(entries: List[ParsedLogEntry]):
    """
    Aggregate per-IP statistics and build a feature matrix.
    Returns (features_list, ip_list, ip_entries_dict).
    """
    stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total":        0,
        "errors":       0,
        "bytes":        [],
        "paths":        set(),
        "agents":       set(),
        "timestamps":   [],
        "auth_fail":    0,
        "post":         0,
        "off_hours":    0,
    })
    ip_entries: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        key = e.source_ip or "unknown"
        s   = stats[key]
        ip_entries[key].append(e)

        s["total"] += 1

        if e.http_status and e.http_status >= 400:
            s["errors"] += 1
        if e.bytes_sent:
            s["bytes"].append(e.bytes_sent)
        if e.http_path:
            s["paths"].add(e.http_path)
        if e.user_agent:
            s["agents"].add(e.user_agent)
        if e.timestamp:
            s["timestamps"].append(e.timestamp)
            hour = e.timestamp.hour
            if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
                s["off_hours"] += 1
        if e.http_method == "POST":
            s["post"] += 1

        # Auth failures (syslog)
        is_auth_proc = (e.process or "").lower() in AUTH_PROCESSES
        is_fail_msg  = any(w in (e.message or "").lower()
                          for w in AUTH_FAILURE_KEYWORDS)
        if (is_auth_proc and is_fail_msg) or e.event_id == "4625":
            s["auth_fail"] += 1

    features  = []
    ip_list   = []

    for ip, s in stats.items():
        total   = s["total"]
        if total < 3:
            continue  # Skip IPs with too few requests

        # Calculate requests per minute
        ts_list = sorted(s["timestamps"])
        if len(ts_list) >= 2:
            duration_minutes = max(
                (ts_list[-1] - ts_list[0]).total_seconds() / 60.0,
                0.01
            )
            rpm = total / duration_minutes
        else:
            rpm = 0.0

        feat = [
            total,                                                    # 0 total_requests
            len(s["paths"]),                                          # 1 unique_paths
            (s["errors"] / total * 100) if total > 0 else 0,         # 2 error_rate_pct
            (sum(s["bytes"]) / len(s["bytes"])) if s["bytes"] else 0,# 3 avg_bytes
            len(s["agents"]),                                         # 4 unique_user_agents
            rpm,                                                      # 5 requests_per_minute
            s["auth_fail"],                                           # 6 auth_failures
            (s["off_hours"] / total * 100) if total > 0 else 0,      # 7 off_hours_ratio_pct
            (s["post"] / total * 100) if total > 0 else 0,           # 8 post_ratio_pct
        ]

        features.append(feat)
        ip_list.append(ip)

    return features, ip_list, ip_entries


def _build_description(ip: str, feat: list, score: int) -> str:
    parts = [f"ML anomaly detected for source {ip} (anomaly score: {score}/100)."]
    if feat[1] > 50:
        parts.append(f"Accessed {int(feat[1])} unique paths.")
    if feat[2] > 30:
        parts.append(f"High error rate: {feat[2]:.0f}%.")
    if feat[5] > 60:
        parts.append(f"High request rate: {feat[5]:.0f} RPM.")
    if feat[6] > 3:
        parts.append(f"{int(feat[6])} authentication failures.")
    if feat[7] > 50:
        parts.append(f"{feat[7]:.0f}% of activity outside business hours.")
    if feat[4] > 5:
        parts.append(f"{int(feat[4])} distinct user agents (possible rotation).")
    return " ".join(parts)


def _feature_dict(feat: list) -> dict:
    keys = ["total_requests", "unique_paths", "error_rate_pct", "avg_bytes",
            "unique_user_agents", "rpm", "auth_failures",
            "off_hours_pct", "post_ratio_pct"]
    return {k: round(v, 2) for k, v in zip(keys, feat)}


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW
