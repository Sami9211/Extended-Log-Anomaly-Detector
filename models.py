# =============================================================================
# models.py — Shared data models
# =============================================================================

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class LogFormat(str, Enum):
    SYSLOG        = "syslog"
    APACHE        = "apache"
    WINDOWS_EVENT = "windows_event"
    GENERIC       = "generic"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ParsedLogEntry(BaseModel):
    """
    Normalised log entry produced by any parser.
    All parsers output this common structure.
    """
    raw:          str                          # Original log line
    timestamp:    Optional[datetime] = None
    source_ip:    Optional[str] = None
    dest_ip:      Optional[str] = None
    username:     Optional[str] = None
    hostname:     Optional[str] = None
    process:      Optional[str] = None
    pid:          Optional[int] = None
    event_id:     Optional[str] = None        # Windows Event ID or syslog facility
    log_level:    Optional[str] = None        # ERROR, WARNING, INFO, etc.
    message:      Optional[str] = None
    http_method:  Optional[str] = None        # GET, POST, etc.
    http_path:    Optional[str] = None
    http_status:  Optional[int] = None
    bytes_sent:   Optional[int] = None
    user_agent:   Optional[str] = None
    extra:        Dict[str, Any] = {}         # Any parser-specific fields
    log_format:   Optional[str] = None


class MitreTag(BaseModel):
    technique_id:   str    # e.g. "T1110"
    technique_name: str    # e.g. "Brute Force"
    tactic:         str    # e.g. "Credential Access"
    url:            str    # Link to MITRE ATT&CK page


class AnomalyFinding(BaseModel):
    """
    A single anomaly found by any detector.
    """
    detector:       str                        # Which detector found it
    finding_type:   str                        # e.g. "sql_injection_attempt"
    description:    str                        # Human-readable explanation
    severity_score: int = Field(ge=0, le=100)  # Raw score 0-100
    severity:       Severity = Severity.LOW
    source_ip:      Optional[str] = None
    username:       Optional[str] = None
    timestamp:      Optional[datetime] = None
    evidence:       List[str] = []             # Sample log lines as evidence
    mitre_tags:     List[MitreTag] = []
    count:          int = 1                    # How many events contributed
    extra:          Dict[str, Any] = {}


class AnalysisResult(BaseModel):
    """
    Full output of an analysis run.
    """
    log_format:       str
    total_lines:      int
    parsed_lines:     int
    parse_errors:     int
    analysis_duration_seconds: float
    findings:         List[AnomalyFinding]
    summary:          Dict[str, int]           # counts by severity
    top_source_ips:   List[Dict[str, Any]]
    analysed_at:      datetime
    detectors_used:   List[str]


class UploadResponse(BaseModel):
    job_id:    str
    message:   str
    log_format: str
    line_count: int
