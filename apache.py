# =============================================================================
# parsers/apache.py — Parse Apache and Nginx access logs
# =============================================================================
# Handles Combined Log Format (CLF) used by both Apache and Nginx:
#
# 192.168.1.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
#
# Also handles the Common Log Format (no referrer/user-agent fields).
# =============================================================================

import re
from datetime import datetime, timezone, timedelta
from typing import List, Tuple
from models import ParsedLogEntry

# Combined Log Format (Apache default, Nginx default)
COMBINED_RE = re.compile(
    r'^(?P<ip>[\d.a-fA-F:]+)\s+'           # client IP
    r'(?P<ident>\S+)\s+'                    # ident (usually -)
    r'(?P<user>\S+)\s+'                     # auth user (usually -)
    r'\[(?P<time>[^\]]+)\]\s+'              # timestamp
    r'"(?P<request>[^"]*?)"\s+'             # "METHOD /path HTTP/x.x"
    r'(?P<status>\d{3})\s+'                 # status code
    r'(?P<bytes>\S+)'                       # bytes sent
    r'(?:\s+"(?P<referrer>[^"]*)")?'        # referrer (optional)
    r'(?:\s+"(?P<agent>[^"]*)")?'           # user agent (optional)
)

# Apache/Nginx error log format
ERROR_LOG_RE = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+\[(?P<level>\w+)\]\s+(?:\[pid \d+\]\s+)?(?P<message>.+)$'
)

APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache(lines: List[str]) -> Tuple[List[ParsedLogEntry], int]:
    """
    Parse Apache/Nginx access log lines.
    Returns (parsed_entries, error_count).
    """
    entries: List[ParsedLogEntry] = []
    errors  = 0

    for raw in lines:
        raw = raw.rstrip()
        if not raw:
            continue

        entry = _parse_access_line(raw)
        if not entry:
            entry = _parse_error_line(raw)
        if not entry:
            errors += 1
            entries.append(ParsedLogEntry(raw=raw, log_format="apache", message=raw))
            continue

        entries.append(entry)

    return entries, errors


def _parse_access_line(raw: str) -> ParsedLogEntry | None:
    m = COMBINED_RE.match(raw)
    if not m:
        return None

    ts = _parse_ts(m.group("time"))

    # Parse "METHOD /path HTTP/version" or handle malformed requests
    request    = m.group("request") or ""
    method     = path = protocol = None
    req_parts  = request.split(" ", 2)
    if len(req_parts) == 3:
        method, path, protocol = req_parts
    elif len(req_parts) == 2:
        method, path = req_parts
    elif len(req_parts) == 1:
        path = req_parts[0]

    status_str = m.group("status")
    status     = int(status_str) if status_str and status_str.isdigit() else None

    bytes_str  = m.group("bytes")
    bytes_sent = int(bytes_str) if bytes_str and bytes_str.isdigit() else None

    user = m.group("user")
    username = None if user in ("-", None) else user

    return ParsedLogEntry(
        raw=raw,
        log_format="apache",
        timestamp=ts,
        source_ip=m.group("ip"),
        username=username,
        http_method=method,
        http_path=path,
        http_status=status,
        bytes_sent=bytes_sent,
        user_agent=m.group("agent"),
        log_level=_status_to_level(status),
        message=request,
        extra={
            "referrer":  m.group("referrer"),
            "protocol":  protocol,
        }
    )


def _parse_error_line(raw: str) -> ParsedLogEntry | None:
    m = ERROR_LOG_RE.match(raw)
    if not m:
        return None

    # Apache error log timestamps: "Thu Oct 10 13:55:36.123456 2024"
    ts = None
    try:
        ts_clean = m.group("time").rsplit(".", 1)[0]  # drop microseconds
        ts = datetime.strptime(ts_clean, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except Exception:
        pass

    return ParsedLogEntry(
        raw=raw,
        log_format="apache",
        timestamp=ts,
        log_level=m.group("level").upper(),
        message=m.group("message"),
    )


def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.strptime(ts_str.strip(), APACHE_TS_FMT)
    except Exception:
        return None


def _status_to_level(status: int | None) -> str:
    if status is None:
        return "INFO"
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"
