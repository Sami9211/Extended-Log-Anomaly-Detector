# =============================================================================
# config.py — All settings, thresholds, and toggles
# =============================================================================

# --- API Server ---
API_HOST = "127.0.0.1"
API_PORT  = 8000

# --- Detection toggles ---
# Set to False to disable a specific detector
ENABLE_PATTERN_DETECTOR     = True   # Regex-based signature matching
ENABLE_STATISTICAL_DETECTOR = True   # Z-score / rate spike analysis
ENABLE_ML_DETECTOR          = True   # Isolation Forest (unsupervised ML)
ENABLE_TEMPORAL_DETECTOR    = True   # Off-hours & burst detection

# --- Statistical detector thresholds ---
# Z-score: how many standard deviations from the mean = anomaly
ZSCORE_THRESHOLD = 3.0

# Rate spike: if requests-per-minute exceeds this, flag it
RATE_SPIKE_RPM_THRESHOLD = 120

# Error rate: if HTTP 4xx/5xx exceed this % of requests in a window, flag it
ERROR_RATE_THRESHOLD_PCT = 40.0

# --- ML detector (Isolation Forest) ---
# contamination: estimated proportion of anomalies in data (0.01–0.5)
# Lower = more selective, higher = more sensitive
ML_CONTAMINATION = 0.05
ML_N_ESTIMATORS  = 100   # More = slower but more accurate

# --- Temporal detector ---
# Define "business hours" — activity outside this window is flagged
BUSINESS_HOURS_START = 7    # 07:00
BUSINESS_HOURS_END   = 20   # 20:00

# Burst threshold: X events in Y seconds from the same source = burst
BURST_EVENT_COUNT   = 20
BURST_WINDOW_SECONDS = 10

# --- Alert severity scoring ---
# Each finding contributes a score; final score maps to severity level
SEVERITY_CRITICAL_THRESHOLD = 80
SEVERITY_HIGH_THRESHOLD     = 50
SEVERITY_MEDIUM_THRESHOLD   = 25
# Below MEDIUM → LOW

# --- Report ---
REPORT_OUTPUT_PATH = "anomaly_report.html"
MAX_EVENTS_PER_ALERT_IN_REPORT = 5   # How many raw log lines to show per alert

# --- Supported log formats ---
# Used in the API and CLI to specify which parser to use
SUPPORTED_FORMATS = ["syslog", "apache", "windows_event", "generic"]
