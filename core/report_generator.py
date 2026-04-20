"""Generate HTML and JSON vulnerability scan reports."""
import json
from datetime import datetime


def generate_html_report(scan: dict) -> str:
    findings = scan.get("findings", [])
    summary = scan.get("summary", {})
    target = scan.get("target", "")
    scan_id = scan.get("id", "")

    sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                 "MEDIUM": "#eab308", "LOW": "#22c55e", "INFO": "#64748b"}

    rows = ""
    for f in sorted(findings, key=lambda x: -x.get("cvss", 0)):
        color = sev_color.get(f.get("severity", "INFO"), "#64748b")
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:700">{f.get('severity','')}</span></td>
          <td>{f.get('cvss',0):.1f}</td>
          <td>{f.get('plugin','')}</td>
          <td>{f.get('check','')}</td>
          <td>{f.get('owasp','')}</td>
          <td>{f.get('cwe','')}</td>
          <td style="font-size:.85em;color:#94a3b8">{f.get('recommendation','')}</td>
        </tr>"""

    grade_color = {"A+": "#22c55e", "A": "#22c55e", "B": "#84cc16",
                   "C": "#eab308", "D": "#f97316", "F": "#ef4444"}
    grade = summary.get("grade", "F")
    g_color = grade_color.get(grade, "#ef4444")

    counts = summary.get("counts", {})
    count_html = " ".join(
        f'<span style="background:{sev_color.get(s,"#64748b")}22;color:{sev_color.get(s,"#64748b")};'
        f'padding:4px 10px;border-radius:4px;font-size:.85em;font-weight:700">'
        f'{counts.get(s,0)} {s}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Report — {target}</title>
<style>
  body {{font-family:'Courier New',monospace;background:#0a0f1e;color:#e2e8f0;padding:32px;}}
  h1 {{color:#64ffda;margin-bottom:8px;}} h2 {{color:#94a3b8;font-size:1em;margin-bottom:24px;}}
  .meta {{color:#64748b;font-size:.85em;margin-bottom:28px;}}
  .grade {{font-size:4em;font-weight:900;color:{g_color};}}
  .score {{font-size:1.5em;color:{g_color};margin-bottom:16px;}}
  .counts {{margin-bottom:28px;display:flex;gap:8px;flex-wrap:wrap;}}
  table {{width:100%;border-collapse:collapse;}}
  thead th {{background:#1a2235;color:#64748b;padding:10px 14px;text-align:left;
             font-size:.78em;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1e2d45;}}
  tbody td {{padding:10px 14px;border-bottom:1px solid #1a2235;font-size:.85em;vertical-align:top;}}
  tbody tr:hover {{background:#111827;}}
</style>
</head>
<body>
<h1>Vulnerability Scan Report</h1>
<h2>Target: {target}</h2>
<div class="meta">Scan ID: {scan_id} &nbsp;|&nbsp; Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
<div class="grade">{grade}</div>
<div class="score">Risk Score: {summary.get('score',0):.1f} / 10</div>
<div class="counts">{count_html}</div>
<table>
  <thead>
    <tr><th>Severity</th><th>CVSS</th><th>Plugin</th><th>Finding</th>
        <th>OWASP</th><th>CWE</th><th>Recommendation</th></tr>
  </thead>
  <tbody>{rows if rows else '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:32px">No vulnerabilities found</td></tr>'}</tbody>
</table>
</body>
</html>"""


def generate_json_report(scan: dict) -> str:
    report = {
        "report_generated": datetime.utcnow().isoformat(),
        "scan_id": scan.get("id"),
        "target": scan.get("target"),
        "status": scan.get("status"),
        "summary": scan.get("summary", {}),
        "findings": scan.get("findings", []),
    }
    return json.dumps(report, indent=2)
