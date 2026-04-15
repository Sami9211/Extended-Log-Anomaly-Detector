# =============================================================================
# main.py — FastAPI application
# =============================================================================
# Run with:  uvicorn main:app --reload
# Docs at:   http://127.0.0.1:8000/docs
# =============================================================================

import time
import uuid
import tempfile
import os
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse

from config import API_HOST, API_PORT, REPORT_OUTPUT_PATH, SUPPORTED_FORMATS
from config import (ENABLE_PATTERN_DETECTOR, ENABLE_STATISTICAL_DETECTOR,
                    ENABLE_ML_DETECTOR, ENABLE_TEMPORAL_DETECTOR)
from models import LogFormat, AnalysisResult, AnomalyFinding

from parsers.syslog        import parse_syslog
from parsers.apache        import parse_apache
from parsers.windows_event import parse_windows_event
from parsers.generic       import parse_generic

from detectors.pattern     import run_pattern_detector
from detectors.statistical import run_statistical_detector
from detectors.ml_detector import run_ml_detector
from detectors.temporal    import run_temporal_detector

from alerts.alerter        import process_findings, summarise, top_source_ips
from reporter.report       import generate_html_report

app = FastAPI(
    title="Log Anomaly Detector",
    description=(
        "Multi-format log anomaly detection using pattern matching, "
        "statistical analysis, ML (Isolation Forest), and temporal analysis. "
        "MITRE ATT&CK tagged findings, HTML reports."
    ),
    version="1.0.0",
)

# In-memory store of completed analysis results
_results: dict[str, AnalysisResult] = {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", tags=["Status"])
def root():
    return {
        "service": "Log Anomaly Detector",
        "status":  "running",
        "docs":    "/docs",
        "supported_formats": SUPPORTED_FORMATS,
        "detectors": {
            "pattern":     ENABLE_PATTERN_DETECTOR,
            "statistical": ENABLE_STATISTICAL_DETECTOR,
            "ml":          ENABLE_ML_DETECTOR,
            "temporal":    ENABLE_TEMPORAL_DETECTOR,
        }
    }


@app.post("/analyse", response_model=AnalysisResult, tags=["Analysis"])
async def analyse_log_file(
    file: UploadFile = File(..., description="Log file to analyse"),
    log_format: LogFormat = Query(LogFormat.APACHE, description="Log format"),
    generate_report: bool = Query(True, description="Generate HTML report"),
):
    """
    Upload a log file and run all enabled anomaly detectors.
    Returns a full AnalysisResult with all findings.
    """
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not decode file: {e}")

    lines = text.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="File is empty.")

    result = _run_analysis(lines, log_format.value, generate_report)
    _results[str(uuid.uuid4())] = result
    return result


@app.post("/analyse/text", response_model=AnalysisResult, tags=["Analysis"])
def analyse_log_text(
    body: dict,
    log_format: LogFormat = Query(LogFormat.APACHE),
    generate_report: bool = Query(False),
):
    """
    Analyse raw log text passed as JSON body: {"log": "line1\\nline2..."}
    Useful for testing or piping from scripts.
    """
    text = body.get("log", "")
    if not text:
        raise HTTPException(status_code=400, detail='Body must contain {"log": "..."}')
    lines = text.splitlines()
    return _run_analysis(lines, log_format.value, generate_report)


@app.get("/report", response_class=HTMLResponse, tags=["Report"])
def get_latest_report():
    """
    Serve the last generated HTML report.
    """
    if not os.path.exists(REPORT_OUTPUT_PATH):
        raise HTTPException(
            status_code=404,
            detail="No report generated yet. POST a file to /analyse first."
        )
    with open(REPORT_OUTPUT_PATH, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/results", tags=["Analysis"])
def list_results():
    """List all stored analysis results (IDs and summary stats)."""
    return [
        {
            "id":          rid,
            "log_format":  r.log_format,
            "total_lines": r.total_lines,
            "findings":    len(r.findings),
            "analysed_at": r.analysed_at,
        }
        for rid, r in _results.items()
    ]


@app.get("/results/{result_id}", response_model=AnalysisResult, tags=["Analysis"])
def get_result(result_id: str):
    if result_id not in _results:
        raise HTTPException(status_code=404, detail="Result not found.")
    return _results[result_id]


@app.get("/generate-samples", tags=["Utilities"])
def generate_samples():
    """
    Generate sample log files in sample_logs/ for testing.
    Returns paths of generated files.
    """
    from sample_logs.generator import (generate_apache_log, generate_syslog,
                                        generate_windows_event)
    paths = {
        "apache":         generate_apache_log(),
        "syslog":         generate_syslog(),
        "windows_event":  generate_windows_event(),
    }
    return {"message": "Sample files generated.", "files": paths}


# ---------------------------------------------------------------------------
# Core analysis pipeline
# ---------------------------------------------------------------------------

def _run_analysis(lines: List[str], log_format: str,
                  generate_report: bool) -> AnalysisResult:
    start = time.time()

    # 1. Parse
    parsers = {
        "syslog":        parse_syslog,
        "apache":        parse_apache,
        "windows_event": parse_windows_event,
        "generic":       parse_generic,
    }
    parser = parsers.get(log_format, parse_generic)
    entries, parse_errors = parser(lines)

    print(f"[Pipeline] Parsed {len(entries)} entries from {len(lines)} lines "
          f"({parse_errors} errors) using {log_format} parser.")

    # 2. Run detectors
    all_findings: List[AnomalyFinding] = []
    detectors_used = []

    if ENABLE_PATTERN_DETECTOR:
        found = run_pattern_detector(entries)
        all_findings.extend(found)
        detectors_used.append("Pattern")
        print(f"[Pattern]     {len(found)} findings")

    if ENABLE_STATISTICAL_DETECTOR:
        found = run_statistical_detector(entries)
        all_findings.extend(found)
        detectors_used.append("Statistical")
        print(f"[Statistical] {len(found)} findings")

    if ENABLE_ML_DETECTOR:
        found = run_ml_detector(entries)
        all_findings.extend(found)
        detectors_used.append("ML")
        print(f"[ML]          {len(found)} findings")

    if ENABLE_TEMPORAL_DETECTOR:
        found = run_temporal_detector(entries)
        all_findings.extend(found)
        detectors_used.append("Temporal")
        print(f"[Temporal]    {len(found)} findings")

    # 3. Aggregate, deduplicate, correlate
    final_findings = process_findings(all_findings)
    summary        = summarise(final_findings)
    top_ips        = top_source_ips(final_findings)

    duration = time.time() - start

    result = AnalysisResult(
        log_format=log_format,
        total_lines=len(lines),
        parsed_lines=len(entries),
        parse_errors=parse_errors,
        analysis_duration_seconds=round(duration, 3),
        findings=final_findings,
        summary=summary,
        top_source_ips=top_ips,
        analysed_at=datetime.now(timezone.utc),
        detectors_used=detectors_used,
    )

    if generate_report:
        generate_html_report(result, REPORT_OUTPUT_PATH)

    print(f"[Pipeline] Done in {duration:.2f}s. "
          f"{len(final_findings)} findings: {summary}")
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=True)
