"""
Report Generator — Professional pentest report
OWASP format, executive summary, reproduction steps, CVSS
"""
import json
import html as html_lib
import time
from pathlib import Path


SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
SEVERITY_COLOR = {
    'CRITICAL': '#ff4444',
    'HIGH':     '#ff8800',
    'MEDIUM':   '#ffcc00',
    'LOW':      '#44bb44',
}


def generate_html_report(findings: list, target: str, ai_analysis: str = '') -> str:
    now = time.strftime('%B %d, %Y — %H:%M UTC')
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in counts:
            counts[sev] += 1

    total = len(findings)
    risk = ('CRITICAL' if counts['CRITICAL'] > 0 else
            'HIGH'     if counts['HIGH']     > 0 else
            'MEDIUM'   if counts['MEDIUM']   > 0 else
            'LOW'      if counts['LOW']      > 0 else 'NONE')

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get('severity','LOW'), 3))

    finding_rows = ''
    for i, f in enumerate(sorted_findings, 1):
        sev  = f.get('severity', 'LOW')
        col  = SEVERITY_COLOR[sev]
        cvss = f.get('cvss_score', f.get('cvss', {}).get('score', 'N/A'))
        vec  = f.get('cvss_vector', f.get('cvss', {}).get('vector', ''))
        rem  = html_lib.escape(f.get('remediation', ''))
        desc = html_lib.escape(f.get('description', f.get('detail', ''))).replace('\n','<br>')
        ev   = f.get('evidence', {})
        if hasattr(ev, 'to_dict'):
            ev = ev.to_dict()
        ev_json  = html_lib.escape(json.dumps(ev, indent=2)) if ev else ''
        repro    = html_lib.escape(ev.get('reproduce','') if ev else '').replace('\n','<br>')
        title    = html_lib.escape(f.get('title', f.get('test', '')))
        endpoint = html_lib.escape(f.get('endpoint', ''))
        ts       = f.get('timestamp', f.get('time', ''))

        finding_rows += f"""
        <div class="finding" id="finding-{i}">
          <div class="finding-header" style="border-left:4px solid {col}">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
              <span class="sev-badge" style="background:{col}22;color:{col};border:1px solid {col}44">{sev}</span>
              <strong style="font-size:1rem;color:#1a1a2e">F{i:02d} — {title}</strong>
              <span style="margin-left:auto;color:#888;font-size:.8rem">{ts}</span>
            </div>
            <div style="margin-top:8px;font-family:monospace;color:#0066cc;font-size:.82rem">📡 {endpoint}</div>
          </div>

          <div class="finding-body">
            <table class="meta-table">
              <tr>
                <td><b>Severity</b></td>
                <td><span style="color:{col};font-weight:700">{sev}</span></td>
                <td><b>CVSS Score</b></td>
                <td><b style="color:{col}">{cvss}</b></td>
              </tr>
              <tr>
                <td><b>CVSS Vector</b></td>
                <td colspan="3"><code style="font-size:.75rem">{html_lib.escape(str(vec))}</code></td>
              </tr>
            </table>

            <h4>📋 Description</h4>
            <p class="desc-box">{desc}</p>

            {"<h4>🔁 Reproduction Steps</h4><div class='repro-box'>"+repro+"</div>" if repro else ""}

            {"<h4>📎 Evidence</h4><pre class='evidence-box'>"+ev_json+"</pre>" if ev_json else ""}

            <h4>🔧 Remediation</h4>
            <p class="rem-box">{rem}</p>
          </div>
        </div>"""

    # Table of contents
    toc_rows = ''
    for i, f in enumerate(sorted_findings, 1):
        sev   = f.get('severity', 'LOW')
        col   = SEVERITY_COLOR[sev]
        title = html_lib.escape(f.get('title', f.get('test', '')))
        cvss  = f.get('cvss_score', 'N/A')
        toc_rows += f"""
        <tr>
          <td style="text-align:center"><a href="#finding-{i}">F{i:02d}</a></td>
          <td><span class="sev-badge" style="background:{col}22;color:{col};border:1px solid {col}44">{sev}</span></td>
          <td>{title}</td>
          <td style="text-align:center"><b style="color:{col}">{cvss}</b></td>
        </tr>"""

    no_findings_note = '' if findings else '<div class="no-findings">✅ No vulnerabilities found. Target appears secure.</div>'

    ai_section = ''
    if ai_analysis and not ai_analysis.startswith('AI analysis will'):
        ai_section = f"""
        <div class="section">
          <h2>🤖 AI Security Analysis</h2>
          <div class="ai-box">{html_lib.escape(ai_analysis).replace(chr(10),'<br>')}</div>
        </div>"""

    risk_color = SEVERITY_COLOR.get(risk, '#888')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebSocket Security Assessment — {html_lib.escape(target)}</title>
</head>
<body>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f4f6f9;color:#1a1a2e;font-size:14px;line-height:1.6}}
a{{color:#0066cc;text-decoration:none}}
.page{{max-width:960px;margin:0 auto;padding:30px 20px}}

/* Cover */
.cover{{background:linear-gradient(135deg,#0d1117,#1a1a3e,#0d1117);color:white;padding:60px 50px;border-radius:16px;margin-bottom:30px;position:relative;overflow:hidden}}
.cover::before{{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%2358a6ff' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");}}
.cover-logo{{font-size:2.5rem;margin-bottom:16px}}
.cover h1{{font-size:2rem;font-weight:700;margin-bottom:8px}}
.cover p{{color:#8b949e;font-size:.9rem}}
.cover .target{{font-family:monospace,Consolas,"Courier New";background:#ffffff11;padding:8px 14px;border-radius:8px;margin-top:16px;font-size:.85rem;color:#58a6ff;display:inline-block}}
.risk-pill{{display:inline-flex;align-items:center;gap:6px;background:{risk_color}22;color:{risk_color};border:1px solid {risk_color}44;padding:4px 14px;border-radius:20px;font-weight:700;font-size:.85rem;margin-top:14px}}

/* Stats */
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.stat-card{{background:white;border:1px solid #e0e7ef;border-radius:12px;padding:18px;text-align:center;box-shadow:0 2px 8px #0001}}
.stat-card h2{{font-size:2rem;font-weight:800}}
.stat-card p{{font-size:.68rem;text-transform:uppercase;letter-spacing:.8px;color:#888;margin-top:4px}}
.c-critical h2{{color:#ff4444}} .c-high h2{{color:#ff8800}}
.c-medium  h2{{color:#ffcc00}} .c-low  h2{{color:#44bb44}}
.c-total   h2{{color:#0066cc}}

/* Sections */
.section{{background:white;border:1px solid #e0e7ef;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 2px 8px #0001}}
.section h2{{font-size:1.1rem;font-weight:700;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #f0f0f0;display:flex;align-items:center;gap:8px}}

/* Table */
.toc-table{{width:100%;border-collapse:collapse}}
.toc-table th,.toc-table td{{padding:9px 12px;border-bottom:1px solid #f0f0f0;text-align:left;font-size:.84rem}}
.toc-table th{{background:#f8fafc;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.5px;color:#666}}
.meta-table{{width:100%;border-collapse:collapse;margin-bottom:14px}}
.meta-table td{{padding:6px 10px;border:1px solid #f0f0f0;font-size:.83rem}}

/* Findings */
.finding{{background:white;border:1px solid #e0e7ef;border-radius:10px;margin-bottom:16px;overflow:hidden;box-shadow:0 2px 8px #0001;page-break-inside:avoid}}
.finding-header{{padding:16px 18px;background:#fafbfc;border-bottom:1px solid #f0f0f0}}
.finding-body{{padding:18px}}
.finding-body h4{{font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#666;margin:14px 0 8px}}
.desc-box{{background:#f8fafc;border-left:3px solid #ddd;padding:10px 14px;border-radius:0 6px 6px 0;font-size:.84rem;line-height:1.65}}
.repro-box{{background:#fffbf0;border-left:3px solid #f59e0b;padding:10px 14px;border-radius:0 6px 6px 0;font-size:.82rem;font-family:monospace,Consolas,"Courier New";line-height:1.8}}
.evidence-box{{background:#0d1117;color:#58a6ff;padding:14px;border-radius:8px;font-size:.73rem;white-space:pre-wrap;word-break:break-all;max-height:220px;overflow-y:auto;font-family:monospace,Consolas,"Courier New"}}
.rem-box{{background:#f0fdf4;border-left:3px solid #22c55e;padding:10px 14px;border-radius:0 6px 6px 0;font-size:.84rem;color:#15803d}}
.sev-badge{{padding:2px 9px;border-radius:4px;font-size:.7rem;font-weight:700;letter-spacing:.5px}}

/* AI */
.ai-box{{background:#f0f4ff;border-left:3px solid #6366f1;padding:14px;border-radius:0 8px 8px 0;font-size:.84rem;line-height:1.8;white-space:pre-wrap}}
.no-findings{{background:#f0fdf4;border:1px solid #22c55e44;border-radius:8px;padding:30px;text-align:center;color:#15803d;font-size:1rem}}

/* Footer */
.footer{{text-align:center;color:#aaa;font-size:.75rem;padding:20px;margin-top:10px}}

@media print{{
  body{{background:white; -webkit-print-color-adjust:exact; print-color-adjust:exact;}}
  .section,.finding{{page-break-inside:avoid}}
}}
</style>
<div class="page">

  <!-- Cover -->
  <div class="cover">
    <div class="cover-logo">🔐</div>
    <h1>WebSocket Security Assessment</h1>
    <p>Confidential Penetration Testing Report</p>
    <div class="target">{html_lib.escape(target)}</div><br>
    <div class="risk-pill">Overall Risk: {risk}</div>
    <p style="margin-top:20px;color:#555;font-size:.78rem">Generated: {now}</p>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat-card c-critical"><h2>{counts['CRITICAL']}</h2><p>Critical</p></div>
    <div class="stat-card c-high">    <h2>{counts['HIGH']}</h2>    <p>High</p></div>
    <div class="stat-card c-medium">  <h2>{counts['MEDIUM']}</h2>  <p>Medium</p></div>
    <div class="stat-card c-low">     <h2>{counts['LOW']}</h2>     <p>Low</p></div>
    <div class="stat-card c-total">   <h2>{total}</h2>             <p>Total</p></div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>📌 Executive Summary</h2>
    <p>This report presents the findings of an automated WebSocket security assessment conducted against <strong>{html_lib.escape(target)}</strong>. The assessment identified <strong>{total} vulnerabilities</strong> across the tested endpoints, with an overall risk rating of <strong style="color:{risk_color}">{risk}</strong>.</p>
    {"<br><p><strong>Immediate action required:</strong> "+str(counts['CRITICAL'])+" critical and "+str(counts['HIGH'])+" high severity findings were identified that require urgent remediation.</p>" if counts['CRITICAL']+counts['HIGH'] > 0 else "<br><p>No critical or high severity issues were identified.</p>"}
  </div>

  <!-- Table of Contents -->
  {f"""<div class="section">
    <h2>📋 Vulnerability Summary</h2>
    <table class="toc-table">
      <thead><tr><th>#</th><th>Severity</th><th>Vulnerability</th><th>CVSS</th></tr></thead>
      <tbody>{toc_rows}</tbody>
    </table>
  </div>""" if findings else ''}

  <!-- Findings -->
  <div class="section">
    <h2>🚨 Detailed Findings</h2>
    {no_findings_note}
    {finding_rows}
  </div>

  {ai_section}

  <div class="footer">
    WS Tester Pro · WebSocket Security Assessment · {now} · Confidential
  </div>
</div>
</body>
</html>"""
