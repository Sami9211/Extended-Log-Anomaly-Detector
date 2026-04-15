# =============================================================================
# detectors/pattern.py — Regex signature-based anomaly detection
# =============================================================================
# Detects known attack patterns in log data using regex signatures.
# Each signature carries a MITRE ATT&CK technique mapping, severity score,
# and description. Think of this as a lightweight, in-process SIEM rule engine.
#
# Detects: SQLi, XSS, Path Traversal, Command Injection, Brute Force,
#          Scanner/Tool signatures, Log4Shell, ShellShock, PHP injection,
#          Sensitive file access, Unusual user agents, SSH anomalies,
#          Windows privilege escalation events, Lateral movement.
# =============================================================================

import re
from collections import defaultdict
from typing import List, Dict, Any
from models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from config import SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD, SEVERITY_MEDIUM_THRESHOLD

# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------
# Each signature: (name, compiled_regex, description, severity_score, mitre_tags)
# We test regex against: http_path, message, user_agent, raw

SIGNATURES = [
    # --- Web Attacks ---
    {
        "name":        "sql_injection",
        "fields":      ["http_path", "message", "raw"],
        "pattern":     re.compile(
            r"(?i)(?:'|\%27|--|;|/\*|\*/|0x[0-9a-f]+)"
            r"(?:.*?(?:select|union|insert|update|delete|drop|exec|execute|"
            r"cast\(|convert\(|char\(|declare|xp_cmdshell|information_schema|"
            r"sleep\(|benchmark\(|pg_sleep|waitfor\s+delay))",
            re.I
        ),
        "description": "SQL Injection attempt detected in request",
        "score":       75,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                   "tactic": "Initial Access"}],
    },
    {
        "name":        "xss_attempt",
        "fields":      ["http_path", "message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:<script|javascript:|on(?:load|error|click|mouse|key|focus|blur|change)'
            r'\s*=|alert\s*\(|eval\s*\(|document\.cookie|window\.location)',
        ),
        "description": "Cross-Site Scripting (XSS) attempt detected",
        "score":       55,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                   "tactic": "Initial Access"}],
    },
    {
        "name":        "path_traversal",
        "fields":      ["http_path", "message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./|'
            r'%252e%252e|\.\.%5c|%c0%ae|%c1%9c)'
            r'(?:.*?(?:etc/passwd|etc/shadow|win/system32|boot\.ini|proc/self))?'
        ),
        "description": "Path traversal / directory traversal attempt",
        "score":       65,
        "mitre": [{"id": "T1083", "name": "File and Directory Discovery",
                   "tactic": "Discovery"}],
    },
    {
        "name":        "command_injection",
        "fields":      ["http_path", "message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:;|\||\`|\$\(|&&|\|\|)\s*(?:cat|ls|id|whoami|uname|pwd|'
            r'wget|curl|nc|ncat|netcat|bash|sh|python|perl|php|ruby)\b'
        ),
        "description": "Command injection attempt detected",
        "score":       85,
        "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter",
                   "tactic": "Execution"}],
    },
    {
        "name":        "log4shell",
        "fields":      ["http_path", "message", "user_agent", "raw"],
        "pattern":     re.compile(r'(?i)\$\{(?:jndi|j(?:&#x6e;|n)di|j\$\{)|jndi:\w{1,5}://'),
        "description": "Log4Shell (CVE-2021-44228) exploitation attempt",
        "score":       95,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                   "tactic": "Initial Access"},
                  {"id": "T1059.001", "name": "PowerShell",
                   "tactic": "Execution"}],
    },
    {
        "name":        "shellshock",
        "fields":      ["http_path", "user_agent", "message", "raw"],
        "pattern":     re.compile(r'\(\s*\)\s*\{.*?;.*?(?:bash|sh|ksh|zsh|csh|echo|cat)\b'),
        "description": "ShellShock (CVE-2014-6271) exploitation attempt",
        "score":       90,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                   "tactic": "Initial Access"}],
    },
    {
        "name":        "php_injection",
        "fields":      ["http_path", "message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:php://(?:input|filter|data)|eval\(base64_decode|'
            r'system\(|passthru\(|shell_exec\(|popen\(|proc_open\(|assert\(|preg_replace\()'
        ),
        "description": "PHP code injection or file wrapper abuse attempt",
        "score":       80,
        "mitre": [{"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"}],
    },
    {
        "name":        "sensitive_file_access",
        "fields":      ["http_path", "message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/|'
            r'\.git/config|\.env|wp-config\.php|config\.php|'
            r'web\.config|application\.properties|\.htpasswd|'
            r'id_rsa|authorized_keys|\.bash_history|\.ssh/)'
        ),
        "description": "Attempt to access sensitive file or configuration",
        "score":       70,
        "mitre": [{"id": "T1552.001", "name": "Credentials In Files",
                   "tactic": "Credential Access"}],
    },

    # --- Scanner / Recon ---
    {
        "name":        "scanner_useragent",
        "fields":      ["user_agent", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:nikto|nessus|nmap|masscan|zgrab|nuclei|sqlmap|'
            r'gobuster|dirb|dirbuster|wfuzz|ffuf|burpsuite|'
            r'openvas|qualys|rapid7|acunetix|metasploit|msfconsole|'
            r'python-requests/|go-http-client/|libwww-perl/|'
            r'curl/[0-9]|wget/[0-9])',
            re.I
        ),
        "description": "Known scanner or attack tool user-agent detected",
        "score":       60,
        "mitre": [{"id": "T1595", "name": "Active Scanning",
                   "tactic": "Reconnaissance"}],
    },
    {
        "name":        "web_path_enumeration",
        "fields":      ["http_path"],
        "pattern":     re.compile(
            r'(?i)(?:admin(?:\.php|panel|login|/)|wp-admin|wp-login|'
            r'phpmyadmin|\.git/|\.svn/|backup|dump\.sql|'
            r'\.bak|\.swp|\.DS_Store|robots\.txt|sitemap\.xml|'
            r'xmlrpc\.php|/cgi-bin/|/actuator/|/api/swagger|/v1/api-docs)'
        ),
        "description": "Web path enumeration / admin panel discovery attempt",
        "score":       40,
        "mitre": [{"id": "T1595.003", "name": "Wordlist Scanning",
                   "tactic": "Reconnaissance"}],
    },

    # --- Authentication Attacks ---
    {
        "name":        "ssh_root_login_attempt",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(r'(?i)(?:failed|invalid|error).{0,30}root.{0,30}(?:ssh|port)'),
        "description": "SSH login attempt for root account",
        "score":       50,
        "mitre": [{"id": "T1110.001", "name": "Password Guessing",
                   "tactic": "Credential Access"}],
    },
    {
        "name":        "multiple_auth_failure",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(r'(?i)(?:failed password|authentication failure|'
                                  r'login failed|logon failure|invalid credentials'
                                  r'|failed login|auth failed)'),
        "description": "Authentication failure detected",
        "score":       35,
        "mitre": [{"id": "T1110", "name": "Brute Force",
                   "tactic": "Credential Access"}],
    },
    {
        "name":        "account_lockout",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(r'(?i)(?:account.{0,20}locked|locked.{0,20}out|'
                                  r'too many.{0,20}attempt|maximum.{0,20}retries)'),
        "description": "Account lockout event — possible brute force",
        "score":       60,
        "mitre": [{"id": "T1110", "name": "Brute Force",
                   "tactic": "Credential Access"}],
    },

    # --- Privilege / Lateral Movement ---
    {
        "name":        "privilege_escalation",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:special privilege|privilege assigned|'
            r'sudo.{0,30}(?:root|ALL|PASSWD)|'
            r'su:.{0,20}success|'
            r'SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege)'
        ),
        "description": "Privilege escalation activity detected",
        "score":       70,
        "mitre": [{"id": "T1078", "name": "Valid Accounts",
                   "tactic": "Privilege Escalation"},
                  {"id": "T1548", "name": "Abuse Elevation Control Mechanism",
                   "tactic": "Privilege Escalation"}],
    },
    {
        "name":        "new_service_or_task",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:new service installed|scheduled task created|'
            r'service.{0,20}install|schtasks.{0,20}/create|'
            r'at\.exe|crontab -[li])'
        ),
        "description": "New service or scheduled task created — possible persistence",
        "score":       65,
        "mitre": [{"id": "T1543", "name": "Create or Modify System Process",
                   "tactic": "Persistence"},
                  {"id": "T1053", "name": "Scheduled Task/Job",
                   "tactic": "Persistence"}],
    },
    {
        "name":        "log_cleared",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(r'(?i)(?:audit log.{0,20}clear|log.{0,20}cleared|'
                                  r'event log.{0,20}clear|wevtutil.{0,20}cl)'),
        "description": "Security/audit log was cleared — possible cover-up",
        "score":       90,
        "mitre": [{"id": "T1070.001", "name": "Clear Windows Event Logs",
                   "tactic": "Defense Evasion"}],
    },
    {
        "name":        "data_exfiltration_hint",
        "fields":      ["message", "raw"],
        "pattern":     re.compile(
            r'(?i)(?:wget.{0,50}(?:http|ftp)|curl.{0,50}(?:http|ftp)|'
            r'scp.{0,50}(?:\d{1,3}\.){3}\d{1,3}|'
            r'nc.{0,30}(?:\d{1,3}\.){3}\d{1,3}.{0,10}\d{4,5}|'
            r'base64.{0,30}(?:decode|encode).{0,30}(?:>|>>|\|))'
        ),
        "description": "Potential data exfiltration or remote staging command",
        "score":       75,
        "mitre": [{"id": "T1041", "name": "Exfiltration Over C2 Channel",
                   "tactic": "Exfiltration"}],
    },
]


def run_pattern_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    """
    Run all regex signatures against all parsed log entries.
    Groups hits by (source_ip OR username) to aggregate evidence.
    """
    # hits[sig_name][grouping_key] = list of matching entries
    hits: Dict[str, Dict[str, List[ParsedLogEntry]]] = defaultdict(lambda: defaultdict(list))

    for entry in entries:
        for sig in SIGNATURES:
            for field in sig["fields"]:
                val = _get_field(entry, field)
                if val and sig["pattern"].search(val):
                    key = entry.source_ip or entry.username or "unknown"
                    hits[sig["name"]][key].append(entry)
                    break  # don't double-count same entry for same sig

    findings: List[AnomalyFinding] = []

    for sig_name, groups in hits.items():
        sig = next(s for s in SIGNATURES if s["name"] == sig_name)

        for group_key, matched_entries in groups.items():
            count = len(matched_entries)
            # Escalate score slightly for repeated hits
            score = min(100, sig["score"] + (10 if count > 5 else 0)
                                          + (15 if count > 20 else 0))

            evidence = [e.raw[:200] for e in matched_entries[:5]]
            ts = matched_entries[0].timestamp if matched_entries else None

            mitre_tags = [
                MitreTag(
                    technique_id=t["id"],
                    technique_name=t["name"],
                    tactic=t["tactic"],
                    url=f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/"
                )
                for t in sig["mitre"]
            ]

            findings.append(AnomalyFinding(
                detector="Pattern Detector",
                finding_type=sig_name,
                description=f"{sig['description']} ({count} event{'s' if count > 1 else ''})",
                severity_score=score,
                severity=_score_to_severity(score),
                source_ip=matched_entries[0].source_ip,
                username=matched_entries[0].username,
                timestamp=ts,
                evidence=evidence,
                mitre_tags=mitre_tags,
                count=count,
            ))

    return findings


def _get_field(entry: ParsedLogEntry, field: str) -> str | None:
    if field == "user_agent":
        return entry.user_agent
    if field == "http_path":
        return entry.http_path
    if field == "message":
        return entry.message
    if field == "raw":
        return entry.raw
    return None


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW
