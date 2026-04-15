# =============================================================================
# parsers/generic.py — Generic JSON and key=value log parser
# =============================================================================
# Handles:
#   - Pure JSON logs (one object per line) — common in cloud environments,
#     Elastic/Splunk exports, application logs
#   - key=value / key="value" pairs — common in Cisco ASA, Palo Alto, etc.
#   - Plain text with common patterns extracted via regex
# =============================================================================

import json
import re
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any
from models import ParsedLogEntry

# key=value or key="value" parser
KV_RE = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')

# Common timestamp patterns to try
TS_PATTERNS = [
    (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'),
     ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
      "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"]),
    (re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
     ["%Y-%m-%d %H:%M:%S"]),
    (re.compile(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'),
     ["%d/%b/%Y:%H:%M:%S"]),
]

IP_RE    = re.compile(r'\b(?:src|source|client|ip|addr|address|remote_ip|clientip)[\s=:]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b', re.I)
IP_BARE  = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
USER_RE  = re.compile(r'\b(?:user|username|account|usr)[\s=:"]+([^\s,"\']+)', re.I)
LEVEL_RE = re.compile(r'\b(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRITICAL|FATAL|ALERT|EMERG)\b', re.I)
HTTP_RE  = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)', re.I)
STATUS_RE= re.compile(r'\bstatus[\s=:]+(\d{3})\b', re.I)

# Fields we try to map to our normalised model
FIELD_ALIASES: Dict[str, List[str]] = {
    "source_ip":   ["src", "srcip", "client_ip", "clientip", "remote_addr",
                    "source", "src_ip", "ipaddr", "ip_address"],
    "username":    ["user", "username", "account", "usr", "user_name"],
    "hostname":    ["host", "hostname", "computer", "device"],
    "http_method": ["method", "http_method", "verb"],
    "http_path":   ["path", "uri", "url", "request_uri", "cs-uri-stem"],
    "http_status": ["status", "status_code", "sc-status", "response"],
    "bytes_sent":  ["bytes", "bytes_sent", "sc-bytes", "size"],
    "user_agent":  ["useragent", "user_agent", "ua", "agent", "cs(User-Agent)"],
    "message":     ["msg", "message", "log", "text", "description", "event"],
    "log_level":   ["level", "severity", "loglevel", "log_level", "priority"],
    "timestamp":   ["time", "timestamp", "@timestamp", "datetime", "ts",
                    "eventtime", "date"],
}


def parse_generic(lines: List[str]) -> Tuple[List[ParsedLogEntry], int]:
    entries: List[ParsedLogEntry] = []
    errors  = 0

    for raw in lines:
        raw = raw.rstrip()
        if not raw:
            continue

        # Try JSON first
        if raw.lstrip().startswith("{"):
            try:
                obj = json.loads(raw)
                entries.append(_from_json(obj, raw))
                continue
            except json.JSONDecodeError:
                pass

        # Try key=value
        kv = _extract_kv(raw)
        if len(kv) >= 2:
            entries.append(_from_kv(kv, raw))
            continue

        # Fall back to regex extraction on plain text
        entries.append(_from_plaintext(raw))

    return entries, errors


def _from_json(obj: Dict[str, Any], raw: str) -> ParsedLogEntry:
    mapped: Dict[str, Any] = {}

    # Flatten one level of nesting (for nested JSON)
    flat = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                flat[k2.lower()] = v2
        flat[k.lower()] = v

    # Map aliased fields
    for field, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias in flat and flat[alias] not in (None, "-", ""):
                mapped[field] = flat[alias]
                break

    ts = _parse_ts(mapped.get("timestamp"))

    return ParsedLogEntry(
        raw=raw,
        log_format="generic",
        timestamp=ts,
        source_ip=str(mapped["source_ip"]) if "source_ip" in mapped else None,
        username=str(mapped["username"])  if "username"  in mapped else None,
        hostname=str(mapped["hostname"])  if "hostname"  in mapped else None,
        http_method=str(mapped["http_method"]) if "http_method" in mapped else None,
        http_path=str(mapped["http_path"])   if "http_path"   in mapped else None,
        http_status=_to_int(mapped.get("http_status")),
        bytes_sent=_to_int(mapped.get("bytes_sent")),
        user_agent=str(mapped["user_agent"]) if "user_agent" in mapped else None,
        message=str(mapped.get("message", raw[:200])),
        log_level=str(mapped.get("log_level", "INFO")).upper(),
        extra={k: v for k, v in flat.items() if k not in FIELD_ALIASES},
    )


def _from_kv(kv: Dict[str, str], raw: str) -> ParsedLogEntry:
    lower_kv = {k.lower(): v for k, v in kv.items()}
    mapped: Dict[str, Any] = {}

    for field, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias in lower_kv:
                mapped[field] = lower_kv[alias]
                break

    ts = _parse_ts(mapped.get("timestamp"))

    return ParsedLogEntry(
        raw=raw,
        log_format="generic",
        timestamp=ts,
        source_ip=mapped.get("source_ip"),
        username=mapped.get("username"),
        hostname=mapped.get("hostname"),
        http_method=mapped.get("http_method"),
        http_path=mapped.get("http_path"),
        http_status=_to_int(mapped.get("http_status")),
        bytes_sent=_to_int(mapped.get("bytes_sent")),
        user_agent=mapped.get("user_agent"),
        message=mapped.get("message", raw[:200]),
        log_level=str(mapped.get("log_level", "INFO")).upper(),
        extra=lower_kv,
    )


def _from_plaintext(raw: str) -> ParsedLogEntry:
    """Last resort: extract whatever we can via regex."""
    ts = None
    for pat, fmts in TS_PATTERNS:
        m = pat.search(raw)
        if m:
            ts = _parse_ts(m.group(0))
            if ts:
                break

    ip = None
    ip_m = IP_RE.search(raw)
    if ip_m:
        ip = ip_m.group(1)
    elif (ip_m := IP_BARE.search(raw)):
        ip = ip_m.group(1)

    user = None
    user_m = USER_RE.search(raw)
    if user_m:
        user = user_m.group(1)

    level = "INFO"
    level_m = LEVEL_RE.search(raw)
    if level_m:
        level = level_m.group(1).upper()

    http_m = HTTP_RE.search(raw)
    method = http_m.group(1) if http_m else None
    path   = http_m.group(2) if http_m else None

    status = None
    status_m = STATUS_RE.search(raw)
    if status_m:
        status = int(status_m.group(1))

    return ParsedLogEntry(
        raw=raw,
        log_format="generic",
        timestamp=ts,
        source_ip=ip,
        username=user,
        log_level=level,
        http_method=method,
        http_path=path,
        http_status=status,
        message=raw[:500],
    )


def _extract_kv(text: str) -> Dict[str, str]:
    return {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3))
            for m in KV_RE.finditer(text)}


def _parse_ts(val: Any) -> datetime | None:
    if not val:
        return None
    s = str(val).strip()
    for _, fmts in TS_PATTERNS:
        for fmt in fmts:
            try:
                dt = datetime.strptime(s[:26], fmt)
                return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
            except ValueError:
                continue
    # Try fromisoformat as fallback
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _to_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
