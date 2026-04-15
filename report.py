# =============================================================================
# reporter/report.py — Generate a full HTML anomaly report
# =============================================================================

from datetime import datetime
from typing import List
from models import AnalysisResult, AnomalyFinding, Severity

SEVERITY_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fca5a5"),
    "HIGH":     ("#78350f", "#fcd34d"),
    "MEDIUM":   ("#1e3a5f", "#93c5fd"),
    "LOW":      ("#14532d", "#86efac"),
    "INFO":     ("#374151", "#d1d5db"),
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"
}


def generate_html_report(result: AnalysisResult, output_path: str) -> str:
    html = _build_html(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[Report] HTML report saved to {output_path}")
    return output_path


def _build_html(result: AnalysisResult) -> str:
    findings_html = "".join(_finding_card(f, i) for i, f in enumerate(result.findings))
    summary       = result.summary

    total_findings = sum(summary.values())
    risk_score     = _overall_risk(result.findings)
    risk_label, risk_color = _risk_label(risk_score)

    top_ips_rows = "".join(
        f"<tr><td>{r['ip']}</td><td>{r['finding_count']}</td>"
        f"<td>{r['max_score']}</td>"
        f"<td style='font-size:0.8em'>{', '.join(r['finding_types'][:3])}</td></tr>"
        for r in result.top_source_ips[:10]
    )

    detectors_badges = "".join(
        f"<span class='badge'>{d}</span>" for d in result.detectors_used
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTIL Log Anomaly Report — {result.analysed_at.strftime('%Y-%m-%d %H:%M')}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --text2: #94a3b8; --accent: #38bdf8;
    --border: #475569; --radius: 8px;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.2rem; color: var(--text2); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  h3 {{ font-size: 1rem; margin-bottom: 0.5rem; }}
  .meta {{ color: var(--text2); font-size: 0.85rem; margin-bottom: 2rem; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.25rem; }}
  .stat-number {{ font-size: 2.5rem; font-weight: 700; line-height: 1; }}
  .stat-label  {{ font-size: 0.8rem; color: var(--text2); margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .risk-score {{ font-size: 4rem; font-weight: 700; color: {risk_color}; text-align: center; }}
  .risk-label {{ text-align: center; font-size: 1.1rem; color: {risk_color}; font-weight: 600; }}
  .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1rem; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 1rem; padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); }}
  .severity-badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; white-space: nowrap; }}
  .finding-body {{ padding: 1rem 1.25rem; }}
  .finding-desc {{ color: var(--text2); font-size: 0.9rem; margin-bottom: 0.75rem; }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.75rem; }}
  .tag {{ background: var(--surface2); border-radius: 4px; padding: 0.15rem 0.5rem; font-size: 0.75rem; color: var(--text2); }}
  .mitre {{ background: #1a1a2e; border: 1px solid #3a3a6e; border-radius: 4px; padding: 0.15rem 0.5rem; font-size: 0.75rem; color: #818cf8; }}
  .evidence-block {{ background: #0a0a0a; border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; margin-top: 0.5rem; overflow-x: auto; }}
  .evidence-block code {{ font-size: 0.72rem; color: #86efac; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; }}
  .meta-row {{ display: flex; gap: 2rem; flex-wrap: wrap; font-size: 0.8rem; color: var(--text2); margin-bottom: 0.5rem; }}
  .meta-row span {{ display: flex; align-items: center; gap: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th, td {{ text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--text2); font-weight: 500; }}
  td {{ color: var(--text); }}
  tr:hover td {{ background: var(--surface2); }}
  .badge {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 0.2rem 0.6rem; font-size: 0.75rem; margin-right: 0.4rem; }}
  .score-bar-wrap {{ background: var(--surface2); border-radius: 4px; height: 6px; margin-top: 0.5rem; }}
  .score-bar {{ border-radius: 4px; height: 6px; }}
  .no-findings {{ text-align: center; color: var(--text2); padding: 3rem; font-size: 1.1rem; }}
  .filter-row {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .filter-btn {{ background: var(--surface2); border: 1px solid var(--border); color: var(--text); border-radius: 4px; padding: 0.3rem 0.8rem; cursor: pointer; font-size: 0.85rem; }}
  .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
</style>
</head>
<body>

<h1>🛡️ Log Anomaly Detection Report</h1>
<div class="meta">
  Generated: {result.analysed_at.strftime('%A, %d %B %Y at %H:%M UTC')} &nbsp;·&nbsp;
  Log format: <strong>{result.log_format}</strong> &nbsp;·&nbsp;
  Analysis duration: <strong>{result.analysis_duration_seconds:.1f}s</strong> &nbsp;·&nbsp;
  Detectors: {detectors_badges}
</div>

<!-- Summary Stats -->
<div class="grid-4">
  <div class="card">
    <div class="stat-number">{result.total_lines:,}</div>
    <div class="stat-label">Total log lines</div>
  </div>
  <div class="card">
    <div class="stat-number">{result.parsed_lines:,}</div>
    <div class="stat-label">Successfully parsed</div>
  </div>
  <div class="card">
    <div class="stat-number">{total_findings}</div>
    <div class="stat-label">Anomalies found</div>
  </div>
  <div class="card">
    <div class="stat-number" style="color:#fca5a5">{summary.get('CRITICAL', 0)}</div>
    <div class="stat-label">Critical findings</div>
  </div>
</div>

<div class="grid-2">
  <!-- Risk Score -->
  <div class="card">
    <h3>Overall Risk Score</h3>
    <div class="risk-score">{risk_score}</div>
    <div class="risk-label">{risk_label}</div>
    <div style="margin-top:1rem; font-size:0.8rem; color:var(--text2)">
      Composite score based on severity distribution and finding count (0–100).
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="card">
    <h3>Findings by Severity</h3>
    {''.join(_severity_row(sev, summary.get(sev, 0), total_findings)
             for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))}
  </div>
</div>

<!-- Top IPs -->
{'<h2>Top Source IPs by Risk</h2><div class="card"><table><thead><tr><th>IP Address</th><th>Findings</th><th>Max Score</th><th>Finding Types</th></tr></thead><tbody>' + top_ips_rows + '</tbody></table></div>' if top_ips_rows else ''}

<!-- Findings -->
<h2>Anomaly Findings ({total_findings})</h2>

<div class="filter-row">
  <button class="filter-btn active" onclick="filterFindings('all')">All ({total_findings})</button>
  {''.join(f'<button class="filter-btn" onclick="filterFindings(\'{s.lower()}\')">{SEVERITY_EMOJI[s]} {s} ({summary.get(s,0)})</button>'
           for s in ('CRITICAL','HIGH','MEDIUM','LOW') if summary.get(s,0) > 0)}
</div>

<div id="findings-container">
{findings_html if findings_html else '<div class="no-findings">✅ No anomalies detected.</div>'}
</div>

<script>
function filterFindings(severity) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    card.style.display = (severity === 'all' || card.dataset.severity === severity) ? '' : 'none';
  }});
}}
function toggleEvidence(id) {{
  const el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? '' : 'none';
}}
</script>
</body>
</html>"""


def _finding_card(f: AnomalyFinding, idx: int) -> str:
    sev = f.severity.value
    fg, bg = SEVERITY_COLORS.get(sev, ("#374151", "#d1d5db"))
    emoji  = SEVERITY_EMOJI.get(sev, "⚪")

    mitre_html = "".join(
        f'<a href="{t.url}" target="_blank" class="mitre" title="{t.tactic}">'
        f'{t.technique_id} {t.technique_name}</a>'
        for t in f.mitre_tags
    )

    evidence_id = f"ev-{idx}"
    evidence_html = ""
    if f.evidence:
        lines = "".join(f"<code>{_esc(line)}\n</code>" for line in f.evidence)
        evidence_html = f"""
        <a href="#" onclick="toggleEvidence('{evidence_id}'); return false;"
           style="font-size:0.8rem; color:var(--accent)">
          Show/hide {len(f.evidence)} evidence line(s)
        </a>
        <div id="{evidence_id}" class="evidence-block" style="display:none">
          {lines}
        </div>"""

    meta_parts = []
    if f.source_ip:
        meta_parts.append(f"<span>📡 {f.source_ip}</span>")
    if f.username:
        meta_parts.append(f"<span>👤 {f.username}</span>")
    if f.timestamp:
        meta_parts.append(f"<span>🕐 {f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</span>")
    meta_parts.append(f"<span>📊 {f.count} event(s)</span>")
    meta_parts.append(f"<span>🔧 {f.detector}</span>")

    bar_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                 "MEDIUM": "#3b82f6", "LOW": "#22c55e"}.get(sev, "#6b7280")

    return f"""
<div class="finding-card" data-severity="{sev.lower()}">
  <div class="finding-header">
    <span class="severity-badge" style="background:{bg};color:{fg}">{emoji} {sev}</span>
    <strong style="flex:1">{f.finding_type.replace('_', ' ').title()}</strong>
    <span style="color:var(--text2);font-size:0.85rem">Score: {f.severity_score}/100</span>
  </div>
  <div class="finding-body">
    <div class="score-bar-wrap"><div class="score-bar" style="width:{f.severity_score}%;background:{bar_color}"></div></div>
    <p class="finding-desc" style="margin-top:0.75rem">{_esc(f.description)}</p>
    <div class="meta-row">{''.join(meta_parts)}</div>
    <div class="tags">{mitre_html}</div>
    {evidence_html}
  </div>
</div>"""


def _severity_row(sev: str, count: int, total: int) -> str:
    pct  = int((count / total * 100)) if total > 0 else 0
    fg, bg = SEVERITY_COLORS.get(sev, ("#374151", "#d1d5db"))
    bar_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                 "MEDIUM": "#3b82f6", "LOW": "#22c55e", "INFO": "#6b7280"}.get(sev, "#6b7280")
    return f"""
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.6rem">
      <span style="width:70px;font-size:0.8rem;color:{fg}">{SEVERITY_EMOJI[sev]} {sev}</span>
      <div style="flex:1;background:var(--surface2);border-radius:4px;height:8px">
        <div style="width:{pct}%;background:{bar_color};border-radius:4px;height:8px"></div>
      </div>
      <span style="font-size:0.85rem;color:var(--text2);width:40px;text-align:right">{count}</span>
    </div>"""


def _overall_risk(findings: List[AnomalyFinding]) -> int:
    if not findings:
        return 0
    weights = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15, "INFO": 0.0}
    total = sum(weights.get(f.severity.value, 0) * f.severity_score for f in findings)
    normalised = min(100, int(total / max(len(findings), 1)))
    return normalised


def _risk_label(score: int) -> tuple:
    if score >= 80: return "CRITICAL RISK", "#ef4444"
    if score >= 60: return "HIGH RISK",     "#f97316"
    if score >= 35: return "MEDIUM RISK",   "#3b82f6"
    if score >= 10: return "LOW RISK",      "#22c55e"
    return "MINIMAL RISK", "#6b7280"


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))
