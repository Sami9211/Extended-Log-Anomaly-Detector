# Log Anomaly Detector

A multi-engine log anomaly detection system for cybersecurity analysis.
Parses logs from multiple sources, runs four independent detection engines,
correlates findings across detectors, and produces a full HTML report with
MITRE ATT&CK technique tagging.

---

## What It Does

```
Log File (Apache / Syslog / Windows Event / Generic)
         │
         ▼
    ┌─────────┐
    │  Parser │  Normalise all formats into a common structure
    └────┬────┘
         │
    ┌────▼────────────────────────────────────────┐
    │              Detection Engines               │
    │  ┌─────────┐ ┌──────────┐ ┌────┐ ┌───────┐ │
    │  │ Pattern │ │ Statist. │ │ ML │ │ Temp. │ │
    │  └─────────┘ └──────────┘ └────┘ └───────┘ │
    └────────────────────────┬────────────────────┘
                             │
                    ┌────────▼────────┐
                    │    Alerter      │  Deduplicate + Correlate + Score
                    └────────┬────────┘
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
         REST API      JSON Result       HTML Report
```

---

## Detection Engines

### 1. Pattern Detector
Regex-based signature matching against known attack patterns.

| Signature | What It Catches | MITRE |
|---|---|---|
| `sql_injection` | SQL injection payloads in URLs/params | T1190 |
| `xss_attempt` | `<script>`, `onerror=`, `javascript:` | T1190 |
| `path_traversal` | `../`, `%2e%2e%2f`, encoded variants | T1083 |
| `command_injection` | `;bash`, `\|whoami`, backtick injection | T1059 |
| `log4shell` | `${jndi:ldap://...}` exploit strings | T1190 |
| `shellshock` | `() { :; };` pattern | T1190 |
| `php_injection` | `eval(base64_decode`, `system(`, `php://input` | T1059.004 |
| `sensitive_file_access` | `.env`, `id_rsa`, `wp-config.php`, `/etc/passwd` | T1552.001 |
| `scanner_useragent` | Nikto, sqlmap, Nmap, Nuclei, Burp Suite | T1595 |
| `web_path_enumeration` | `/admin`, `/phpmyadmin`, `/.git/config` | T1595.003 |
| `ssh_root_login` | Failed SSH attempts for root | T1110.001 |
| `multiple_auth_failure` | Authentication failure events | T1110 |
| `account_lockout` | Lockout events (possible brute force) | T1110 |
| `privilege_escalation` | `sudo root`, `SeDebugPrivilege`, `su success` | T1078, T1548 |
| `new_service_or_task` | New service/cron job/scheduled task | T1543, T1053 |
| `log_cleared` | Security log cleared (cover-up) | T1070.001 |
| `data_exfiltration_hint` | `wget`, `curl`, `nc` to remote IPs | T1041 |

### 2. Statistical Detector
Finds anomalies without needing known signatures — useful for novel attacks.

- **Request rate spike** — Z-score on requests/minute per IP
- **Error rate spike** — HTTP 4xx/5xx ratio in 5-minute windows
- **Bytes anomaly** — Z-score on response sizes (data exfiltration)
- **Auth failure rate** — Per-source authentication failure counts
- **Path enumeration** — IPs accessing an outlier number of unique paths

### 3. ML Detector (Isolation Forest)
Unsupervised machine learning — no labelled data required.

Builds a 9-feature vector per source IP:
- Total requests, unique paths, error rate, avg bytes
- Unique user agents (UA rotation = bot indicator)
- Requests/minute, auth failures, off-hours ratio, POST ratio

IsolationForest isolates anomalous behaviour patterns that none of the
other detectors may catch. Best for novel, slow-burn, or multi-vector attacks.

### 4. Temporal Detector
Detects attacks that are only visible in the *timing* of events:

- **Off-hours auth activity** — Logins/sensitive ops outside 07:00–20:00
- **Request burst** — N events from one IP within Y seconds
- **Impossible travel** — Same user, 2 different IPs, within 5 minutes
- **Weekend sensitive activity** — Admin events on Saturday/Sunday
- **Slow-burn brute force** — Low-rate auth failures spread over 30+ minutes
  (specifically designed to evade rate-limit detectors)

---

## Supported Log Formats

| Format | Source | Example |
|---|---|---|
| `apache` | Apache httpd, Nginx | Combined/Common Log Format |
| `syslog` | Linux auth.log, syslog, journald | RFC 3164 / RFC 5424 |
| `windows_event` | Windows Event Log (JSON export) | PowerShell Get-WinEvent export |
| `generic` | Any JSON logs, key=value, Cisco ASA, Palo Alto | Auto-detected |

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11 or 3.12 | Check with `python --version` |
| pip | Comes with Python |

No API keys needed. Fully offline.

---

## Setup (Step by Step)

### Step 1 — Set up the virtual environment

```bash
cd log-anomaly-detector

python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs FastAPI, scikit-learn, numpy, and uvicorn. Takes ~2 minutes.

### Step 3 — (Optional) Adjust settings

Open `config.py` to tune any thresholds. The defaults work well:

```python
# Key settings you might want to adjust:
ML_CONTAMINATION        = 0.05   # 5% of data expected to be anomalous
ZSCORE_THRESHOLD        = 3.0    # How many std deviations = anomaly
RATE_SPIKE_RPM_THRESHOLD = 120   # Requests/minute before flagging
BUSINESS_HOURS_START    = 7      # 07:00
BUSINESS_HOURS_END      = 20     # 20:00
```

### Step 4 — Start the server

```bash
uvicorn main:app --reload
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Step 5 — Generate test logs (optional but recommended)

```bash
python sample_logs/generator.py
```

This creates three realistic log files in `sample_logs/` with injected attacks:
- `sample_logs/sample_apache.log` — Apache access log with SQLi, Log4Shell, scanner
- `sample_logs/sample_syslog.log` — SSH brute force, slow brute, off-hours root login
- `sample_logs/sample_windows.jsonl` — Windows events with backdoor user, log cleared

### Step 6 — Analyse a log file

**Via Swagger UI (easiest):**
1. Open http://127.0.0.1:8000/docs
2. Click `POST /analyse` → "Try it out"
3. Upload a log file, select the format, click Execute

**Via curl:**
```bash
# Analyse the sample Apache log
curl -X POST "http://127.0.0.1:8000/analyse?log_format=apache&generate_report=true" \
  -F "file=@sample_logs/sample_apache.log"

# Analyse a syslog file
curl -X POST "http://127.0.0.1:8000/analyse?log_format=syslog&generate_report=true" \
  -F "file=@sample_logs/sample_syslog.log"

# Windows Event Log
curl -X POST "http://127.0.0.1:8000/analyse?log_format=windows_event&generate_report=true" \
  -F "file=@sample_logs/sample_windows.jsonl"
```

### Step 7 — View the HTML report

After analysis, open your browser and go to:

```
http://127.0.0.1:8000/report
```

Or open `anomaly_report.html` directly in any browser.

---

## API Endpoints

| Method | Endpoint | What It Does |
|---|---|---|
| `GET` | `/` | Status and detector config |
| `POST` | `/analyse` | Upload and analyse a log file |
| `POST` | `/analyse/text` | Analyse raw text sent as JSON |
| `GET` | `/report` | View latest HTML report in browser |
| `GET` | `/results` | List all past analysis results |
| `GET` | `/results/{id}` | Get a specific result by ID |
| `GET` | `/generate-samples` | Generate sample log files |
| `GET` | `/docs` | Interactive Swagger UI |

---

## Understanding the HTML Report

The report shows:
- **Overall Risk Score** (0–100) — weighted composite across all findings
- **Findings by Severity** — CRITICAL / HIGH / MEDIUM / LOW breakdown
- **Top Source IPs** — ranked by risk score
- **Finding Cards** — each with:
  - Severity badge and score bar
  - Human-readable description
  - MITRE ATT&CK technique badge (clickable, links to attack.mitre.org)
  - Source IP / username / timestamp
  - Collapsible evidence (actual log lines)
  - Corroboration note if multiple detectors flagged the same source

---

## File Structure

```
log-anomaly-detector/
├── config.py                  ← All settings & thresholds (edit here)
├── models.py                  ← Shared data models
├── main.py                    ← FastAPI server
├── requirements.txt
│
├── parsers/
│   ├── syslog.py              ← Linux syslog, auth.log (RFC 3164/5424)
│   ├── apache.py              ← Apache/Nginx Combined Log Format
│   ├── windows_event.py       ← Windows Event Log JSON export
│   └── generic.py             ← JSON, key=value, plain text (auto-detect)
│
├── detectors/
│   ├── pattern.py             ← 17 regex signatures with MITRE tags
│   ├── statistical.py         ← Z-score and rate-based detection
│   ├── ml_detector.py         ← Isolation Forest (scikit-learn)
│   └── temporal.py            ← Off-hours, burst, travel, slow brute
│
├── alerts/
│   └── alerter.py             ← Deduplication, correlation, scoring
│
├── reporter/
│   └── report.py              ← Dark-themed HTML report generator
│
└── sample_logs/
    └── generator.py           ← Generates test logs with injected attacks
```

---

## Limitations

- **No persistent database** — results are in-memory only. Restart = data gone.
  Add SQLite or PostgreSQL for production use.

- **No real-time streaming** — designed for batch log file analysis.
  For real-time, integrate with Kafka or a log shipper like Filebeat.

- **ML needs volume** — Isolation Forest produces meaningful results with
  50+ distinct source IPs. Sparse logs may return few or no ML findings.

- **No GeoIP** — "Impossible travel" detection uses only IP address comparison,
  not actual geolocation. A real deployment would use MaxMind GeoLite2.

- **Pattern detector creates false positives** — security research URLs,
  penetration test traffic, and WAF/IDS test suites will trigger signatures.
  Tune the regex patterns in `detectors/pattern.py` for your environment.

- **No authentication on the API** — anyone who can reach port 8000 can
  submit logs and read results. Add OAuth2 or API key auth before exposing
  this to a network.

- **Syslog timestamps assume current year** — RFC 3164 syslog doesn't include
  the year, so logs from December analysed in January may show wrong dates.

---

## Pros

- ✅ **No external dependencies or API keys** — fully offline
- ✅ **Four complementary detection methods** — each catches what others miss
- ✅ **MITRE ATT&CK mapping** — findings speak the language of SOC teams
- ✅ **Cross-detector correlation** — score boosted when multiple engines agree
- ✅ **Four log formats** — one tool covers Linux, Windows, and web servers
- ✅ **Sample log generator** — instant test data with known-bad injections
- ✅ **HTML report** — shareable, no extra tools needed to read findings

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: sklearn` | Run `pip install -r requirements.txt` with venv active |
| 0 ML findings | Need 5+ distinct source IPs; small logs won't trigger ML |
| All findings are LOW | Increase `ML_CONTAMINATION` or lower `ZSCORE_THRESHOLD` in config.py |
| Too many false positives | Raise `ZSCORE_THRESHOLD` to 4.0 or disable noisy detector in config.py |
| Port 8000 in use | Change `API_PORT` in config.py |
| Windows Event log not parsing | Ensure the file is one JSON object per line (JSONL format) |
