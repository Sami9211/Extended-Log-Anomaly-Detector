# =============================================================================
# parsers/windows_event.py — Parse Windows Event Log exports
# =============================================================================
# Handles two formats:
#   1. JSON export from Get-WinEvent | ConvertTo-Json  (PowerShell)
#   2. EVTX-to-JSON from tools like EvtxECmd or python-evtx
#   3. Single-line JSON objects (one per line, as exported by many SIEMs)
#
# Key security-relevant Event IDs:
#   4624 — Successful logon
#   4625 — Failed logon
#   4648 — Logon with explicit credentials
#   4672 — Special privileges assigned (admin logon)
#   4688 — Process creation
#   4698 — Scheduled task created
#   4719 — Audit policy changed
#   4732 — Member added to security-enabled local group
#   4740 — Account locked out
#   7045 — New service installed
# =============================================================================

import json
import re
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any
from models import ParsedLogEntry

# Human-readable descriptions for key Event IDs
EVENT_ID_MAP: Dict[str, str] = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Logoff",
    "4648": "Logon with Explicit Credentials",
    "4656": "Handle to Object Requested",
    "4663": "Object Access Attempted",
    "4672": "Special Privileges Assigned to New Logon",
    "4688": "Process Created",
    "4698": "Scheduled Task Created",
    "4700": "Scheduled Task Enabled",
    "4719": "System Audit Policy Changed",
    "4720": "User Account Created",
    "4726": "User Account Deleted",
    "4728": "Member Added to Security-Enabled Global Group",
    "4732": "Member Added to Security-Enabled Local Group",
    "4740": "User Account Locked Out",
    "4756": "Member Added to Security-Enabled Universal Group",
    "4776": "Credential Validation",
    "4798": "User's Local Group Membership Enumerated",
    "4799": "Security-Enabled Local Group Membership Enumerated",
    "7045": "New Service Installed",
    "1102": "Audit Log Cleared",
    "4616": "System Time Changed",
    "4657": "Registry Value Modified",
}

LOGON_TYPES: Dict[str, str] = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def parse_windows_event(lines: List[str]) -> Tuple[List[ParsedLogEntry], int]:
    """
    Parse Windows Event Log lines (one JSON object per line, or a JSON array).
    Returns (parsed_entries, error_count).
    """
    entries: List[ParsedLogEntry] = []
    errors  = 0

    # Try treating the whole input as a JSON array first
    joined = "\n".join(lines).strip()
    if joined.startswith("["):
        try:
            records = json.loads(joined)
            for record in records:
                e = _parse_record(record)
                if e:
                    entries.append(e)
                else:
                    errors += 1
            return entries, errors
        except json.JSONDecodeError:
            pass

    # Otherwise process line by line
    for raw in lines:
        raw = raw.rstrip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
            e = _parse_record(record, raw_line=raw)
            if e:
                entries.append(e)
            else:
                errors += 1
        except json.JSONDecodeError:
            errors += 1
            entries.append(ParsedLogEntry(raw=raw, log_format="windows_event",
                                          message=raw))

    return entries, errors


def _parse_record(record: Dict[str, Any], raw_line: str = "") -> ParsedLogEntry | None:
    if not isinstance(record, dict):
        return None

    raw = raw_line or json.dumps(record)

    # Support multiple JSON schema layouts
    event_data = (
        record.get("EventData") or
        record.get("event_data") or
        record.get("UserData") or
        {}
    )

    system    = record.get("System") or {}
    event_id  = str(
        record.get("EventID") or
        record.get("event_id") or
        system.get("EventID") or
        ""
    )

    # Timestamp
    ts = _parse_ts(
        record.get("TimeCreated") or
        record.get("timestamp") or
        record.get("@timestamp") or
        system.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime", "")
    )

    # Extract common fields
    username = (
        event_data.get("SubjectUserName") or
        event_data.get("TargetUserName") or
        record.get("username") or
        system.get("Security", {}).get("UserID")
    )

    source_ip = (
        event_data.get("IpAddress") or
        event_data.get("WorkstationName") or
        record.get("source_ip")
    )
    if source_ip and source_ip in ("-", "::1", "127.0.0.1"):
        source_ip = None

    hostname = (
        system.get("Computer") or
        record.get("Computer") or
        record.get("hostname")
    )

    logon_type_code = str(event_data.get("LogonType", ""))
    logon_type = LOGON_TYPES.get(logon_type_code, logon_type_code)

    process_name = event_data.get("NewProcessName") or event_data.get("ProcessName")

    description = EVENT_ID_MAP.get(event_id, f"Event {event_id}")
    if logon_type:
        description += f" [{logon_type}]"

    level_map = {"0": "INFO", "1": "CRITICAL", "2": "ERROR",
                 "3": "WARNING", "4": "INFO", "5": "DEBUG"}
    level_code = str(system.get("Level", "4"))
    level = level_map.get(level_code, "INFO")

    return ParsedLogEntry(
        raw=raw,
        log_format="windows_event",
        timestamp=ts,
        source_ip=source_ip,
        username=_clean(username),
        hostname=hostname,
        event_id=event_id,
        log_level=level,
        message=description,
        process=process_name,
        extra={
            "logon_type":       logon_type or None,
            "event_id_human":   description,
            "command_line":     event_data.get("CommandLine"),
            "target_user":      event_data.get("TargetUserName"),
            "subject_user":     event_data.get("SubjectUserName"),
            "task_name":        event_data.get("TaskName"),
            "service_name":     event_data.get("ServiceName"),
            "privilege_list":   event_data.get("PrivilegeList"),
        }
    )


def _parse_ts(ts_val: Any) -> datetime | None:
    if not ts_val:
        return None
    ts_str = str(ts_val)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            dt = datetime.strptime(ts_str[:26], fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    return None


def _clean(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    return None if s in ("-", "", "N/A", "SYSTEM", "LOCAL SERVICE") else s
