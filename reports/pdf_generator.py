"""
PDF Report Generator — High-quality xhtml2pdf-compatible report
Uses ReportLab-compatible fonts, large clear text, professional spacing.
Colorful, vibrant design with rich accent colors.
"""
import json
import html as html_lib
import time


SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
SEVERITY_COLOR = {
    'CRITICAL': '#E11D48',
    'HIGH':     '#EA580C',
    'MEDIUM':   '#D97706',
    'LOW':      '#16A34A',
}
SEVERITY_BG = {
    'CRITICAL': '#FFF1F2',
    'HIGH':     '#FFF7ED',
    'MEDIUM':   '#FFFBEB',
    'LOW':      '#F0FDF4',
}


def generate_pdf_html(findings: list, target: str, ai_analysis: str = '') -> str:
    """Generate high-quality PDF HTML using xhtml2pdf-compatible markup."""
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
    risk_color = SEVERITY_COLOR.get(risk, '#888888')

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get('severity','LOW'), 3))

    # ── Build finding blocks ──────────────────────────────────────
    finding_blocks = ''
    for i, f in enumerate(sorted_findings, 1):
        sev  = f.get('severity', 'LOW')
        col  = SEVERITY_COLOR[sev]
        bg   = SEVERITY_BG[sev]
        cvss = f.get('cvss_score', f.get('cvss', {}).get('score', 'N/A'))
        vec  = f.get('cvss_vector', f.get('cvss', {}).get('vector', ''))
        rem  = html_lib.escape(f.get('remediation', '') or 'No specific remediation provided.')
        desc = html_lib.escape(f.get('description', f.get('detail', '')) or 'No description available.')
        desc = desc.replace('\n', '<br/>')
        ev   = f.get('evidence', {})
        if hasattr(ev, 'to_dict'):
            ev = ev.to_dict()
        ev_json = html_lib.escape(json.dumps(ev, indent=2, default=str)) if ev else ''
        repro   = html_lib.escape(ev.get('reproduce','') if ev else '').replace('\n','<br/>')
        title   = html_lib.escape(f.get('title', f.get('test', '')))
        endpoint = html_lib.escape(f.get('endpoint', ''))

        repro_html = ''
        if repro:
            repro_html = f'''
            <p style="font-size:11px; font-weight:bold; color:#B45309; margin-top:15px; margin-bottom:5px;">
                &#9881; REPRODUCTION STEPS
            </p>
            <p style="background-color:#FEF3C7; border-left:5px solid #F59E0B; padding:10px 15px;
                      font-size:12px; line-height:20px;">{repro}</p>'''

        evidence_html = ''
        if ev_json:
            evidence_html = f'''
            <p style="font-size:11px; font-weight:bold; color:#4338CA; margin-top:15px; margin-bottom:5px;">
                &#128269; EVIDENCE
            </p>
            <p style="background-color:#EEF2FF; border-left:5px solid #6366F1; padding:10px 15px;
                      font-size:10px; line-height:16px; font-family:Courier;">{ev_json}</p>'''

        finding_blocks += f'''
        <div style="margin-bottom:20px; page-break-inside:avoid;">
            <!-- Finding Header -->
            <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                    <td style="background-color:{col}; padding:4px 20px;">
                        <p style="font-size:11px; font-weight:bold; color:white;
                                  letter-spacing:2px;">FINDING F{i:02d}</p>
                    </td>
                </tr>
                <tr>
                    <td style="background-color:{bg}; border-left:6px solid {col};
                               border-right:1px solid #E2E8F0;
                               padding:15px 20px;">
                        <p style="font-size:11px; font-weight:bold; color:white;
                                  background-color:{col}; padding:4px 14px; display:inline;
                                  letter-spacing:1px;">{sev}</p>
                        <br/><br/>
                        <p style="font-size:16px; font-weight:bold; color:#0F172A; margin:0;">
                            F{i:02d} &mdash; {title}
                        </p>
                        <p style="font-size:12px; color:#2563EB; margin-top:5px;
                                  font-family:Courier;">{endpoint}</p>
                    </td>
                </tr>
            </table>

            <!-- Finding Body -->
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="border-left:1px solid #E2E8F0; border-right:1px solid #E2E8F0;
                          border-bottom:1px solid #E2E8F0;">
                <tr>
                    <td width="25%" style="padding:12px 20px; border-bottom:1px solid #E2E8F0;
                                           background-color:#FAFBFF;">
                        <p style="font-size:10px; color:#6366F1; margin-bottom:3px; font-weight:bold;">SEVERITY</p>
                        <p style="font-size:14px; font-weight:bold; color:{col};">{sev}</p>
                    </td>
                    <td width="25%" style="padding:12px 20px; border-bottom:1px solid #E2E8F0;
                                           background-color:#FAFBFF;">
                        <p style="font-size:10px; color:#6366F1; margin-bottom:3px; font-weight:bold;">CVSS SCORE</p>
                        <p style="font-size:14px; font-weight:bold; color:{col};">{cvss}</p>
                    </td>
                    <td width="50%" style="padding:12px 20px; border-bottom:1px solid #E2E8F0;
                                           background-color:#FAFBFF;">
                        <p style="font-size:10px; color:#6366F1; margin-bottom:3px; font-weight:bold;">CVSS VECTOR</p>
                        <p style="font-size:11px; font-family:Courier; color:#334155;">{html_lib.escape(str(vec))}</p>
                    </td>
                </tr>
                <tr>
                    <td colspan="3" style="padding:15px 20px;">
                        <p style="font-size:11px; font-weight:bold; color:#0284C7; margin-bottom:5px;">
                            &#128196; DESCRIPTION
                        </p>
                        <p style="background-color:#F0F9FF; border-left:5px solid #0EA5E9;
                                  padding:10px 15px; font-size:13px; line-height:22px;
                                  color:#0C4A6E;">{desc}</p>

                        {repro_html}
                        {evidence_html}

                        <p style="font-size:11px; font-weight:bold; color:#059669;
                                  margin-top:15px; margin-bottom:5px;">
                            &#9989; REMEDIATION
                        </p>
                        <p style="background-color:#ECFDF5; border-left:5px solid #10B981;
                                  padding:10px 15px; font-size:13px; line-height:22px;
                                  color:#065F46;">{rem}</p>
                    </td>
                </tr>
            </table>
        </div>'''

    # ── TOC rows ──────────────────────────────────────────────────
    toc_rows = ''
    for i, f in enumerate(sorted_findings, 1):
        sev   = f.get('severity', 'LOW')
        col   = SEVERITY_COLOR[sev]
        bg    = SEVERITY_BG[sev]
        title = html_lib.escape(f.get('title', f.get('test', '')))
        cvss  = f.get('cvss_score', 'N/A')
        row_bg = '#FFFFFF' if i % 2 == 0 else '#F8FAFC'
        toc_rows += f'''
            <tr>
                <td style="padding:10px 15px; border-bottom:1px solid #E2E8F0;
                           text-align:center; font-size:12px; background-color:{row_bg};
                           color:#4338CA; font-weight:bold;">
                    F{i:02d}
                </td>
                <td style="padding:10px 15px; border-bottom:1px solid #E2E8F0;
                           background-color:{row_bg};">
                    <span style="background-color:{col}; color:white; padding:3px 10px;
                                 font-size:10px; font-weight:bold; letter-spacing:1px;">{sev}</span>
                </td>
                <td style="padding:10px 15px; border-bottom:1px solid #E2E8F0;
                           font-size:13px; background-color:{row_bg}; color:#1E293B;">{title}</td>
                <td style="padding:10px 15px; border-bottom:1px solid #E2E8F0;
                           text-align:center; background-color:{row_bg};">
                    <span style="font-size:14px; font-weight:bold; color:{col};">{cvss}</span>
                </td>
            </tr>'''

    toc_section = ''
    if findings:
        toc_section = f'''
        <div style="margin-bottom:25px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #C7D2FE;">
                <tr>
                    <td colspan="4" style="background-color:#4338CA; padding:15px 20px;
                                           border-bottom:2px solid #3730A3;">
                        <p style="font-size:16px; font-weight:bold; color:#FFFFFF; margin:0;">
                            &#128202; Vulnerability Summary
                        </p>
                    </td>
                </tr>
                <tr style="background-color:#EEF2FF;">
                    <th style="padding:10px 15px; font-size:11px; color:#4338CA;
                               text-align:center; border-bottom:2px solid #C7D2FE; width:60px;">#</th>
                    <th style="padding:10px 15px; font-size:11px; color:#4338CA;
                               text-align:left; border-bottom:2px solid #C7D2FE; width:90px;">SEVERITY</th>
                    <th style="padding:10px 15px; font-size:11px; color:#4338CA;
                               text-align:left; border-bottom:2px solid #C7D2FE;">VULNERABILITY</th>
                    <th style="padding:10px 15px; font-size:11px; color:#4338CA;
                               text-align:center; border-bottom:2px solid #C7D2FE; width:70px;">CVSS</th>
                </tr>
                {toc_rows}
            </table>
        </div>'''

    ai_section = ''
    if ai_analysis and not ai_analysis.startswith('AI analysis will'):
        ai_section = f'''
        <div style="margin-bottom:25px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #99F6E4;">
                <tr>
                    <td style="background-color:#0D9488; padding:15px 20px;
                               border-bottom:2px solid #0F766E;">
                        <p style="font-size:16px; font-weight:bold; color:#FFFFFF; margin:0;">
                            &#129302; AI Security Analysis
                        </p>
                    </td>
                </tr>
                <tr>
                    <td style="padding:20px; font-size:13px; line-height:22px;
                               border-left:5px solid #14B8A6; background-color:#F0FDFA;
                               color:#134E4A;">
                        {html_lib.escape(ai_analysis).replace(chr(10),'<br/>')}
                    </td>
                </tr>
            </table>
        </div>'''

    urgent_msg = ''
    if counts['CRITICAL'] + counts['HIGH'] > 0:
        urgent_msg = f'''<p style="margin-top:12px; padding:10px 15px; background-color:#FFF1F2;
            border-left:5px solid #E11D48; color:#9F1239; font-size:13px; font-weight:bold;">
            &#9888; IMMEDIATE ACTION REQUIRED: {counts["CRITICAL"]} critical and {counts["HIGH"]} high
            severity findings require urgent remediation.</p>'''
    else:
        urgent_msg = '''<p style="margin-top:12px; padding:10px 15px; background-color:#F0FDF4;
            border-left:5px solid #16A34A; color:#166534; font-size:13px;">
            &#10004; No critical or high severity issues were identified.</p>'''

    return f'''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>WebSocket Security Assessment - {html_lib.escape(target)}</title>
<style>
    @page {{
        size: A4;
        margin: 2.5cm 2cm 2.5cm 2cm;
        @frame footer {{
            -pdf-frame-content: pageFooter;
            bottom: 0cm;
            margin-left: 2cm;
            margin-right: 2cm;
            height: 1.2cm;
        }}
    }}
    body {{
        font-family: Helvetica;
        font-size: 13px;
        color: #1E293B;
        line-height: 1.6;
    }}
    p {{
        margin: 0;
        padding: 0;
    }}
    h1 {{
        font-size: 26px;
        color: #FFFFFF;
        font-weight: bold;
    }}
    h2 {{
        font-size: 18px;
        color: #0F172A;
        font-weight: bold;
        margin-bottom: 10px;
    }}
</style>
</head>
<body>

    <!-- ============================================ -->
    <!-- COVER PAGE                                   -->
    <!-- ============================================ -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:30px;">
        <tr>
            <td style="background-color:#0F172A; color:#FFFFFF; padding:50px 35px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="border-bottom:3px solid #6366F1; padding-bottom:25px;">
                            <p style="font-size:40px; margin-bottom:15px;">&#128274;</p>
                            <h1>WebSocket Security Assessment</h1>
                            <p style="font-size:14px; color:#94A3B8; margin-top:5px;">
                                Confidential Penetration Testing Report
                            </p>
                        </td>
                    </tr>
                </table>
                <br/>
                <table cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="background-color:#1E293B; padding:12px 20px;
                                   font-family:Courier; font-size:14px; color:#38BDF8;
                                   border:1px solid #334155; border-left:4px solid #6366F1;">
                            {html_lib.escape(target)}
                        </td>
                    </tr>
                </table>
                <br/>
                <table cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="background-color:{risk_color}; color:#FFFFFF;
                                   padding:8px 22px; font-size:13px; font-weight:bold;
                                   letter-spacing:2px;">
                            &#9888; OVERALL RISK: {risk}
                        </td>
                    </tr>
                </table>
                <br/>
                <table cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="background-color:#1E293B; padding:8px 16px;
                                   border:1px solid #334155; font-size:12px; color:#94A3B8;">
                            &#128197; Generated: {now}
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>

    <!-- ============================================ -->
    <!-- SEVERITY STATISTICS                          -->
    <!-- ============================================ -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:25px;">
        <tr>
            <td width="20%" style="text-align:center; padding:5px 10px;
                                   border:1px solid #FECDD3; background-color:#E11D48;">
                <p style="font-size:10px; color:#FFFFFF; letter-spacing:2px; font-weight:bold;">CRITICAL</p>
            </td>
            <td width="20%" style="text-align:center; padding:5px 10px;
                                   border:1px solid #FED7AA; background-color:#EA580C;">
                <p style="font-size:10px; color:#FFFFFF; letter-spacing:2px; font-weight:bold;">HIGH</p>
            </td>
            <td width="20%" style="text-align:center; padding:5px 10px;
                                   border:1px solid #FDE68A; background-color:#D97706;">
                <p style="font-size:10px; color:#FFFFFF; letter-spacing:2px; font-weight:bold;">MEDIUM</p>
            </td>
            <td width="20%" style="text-align:center; padding:5px 10px;
                                   border:1px solid #BBF7D0; background-color:#16A34A;">
                <p style="font-size:10px; color:#FFFFFF; letter-spacing:2px; font-weight:bold;">LOW</p>
            </td>
            <td width="20%" style="text-align:center; padding:5px 10px;
                                   border:1px solid #BFDBFE; background-color:#2563EB;">
                <p style="font-size:10px; color:#FFFFFF; letter-spacing:2px; font-weight:bold;">TOTAL</p>
            </td>
        </tr>
        <tr>
            <td width="20%" style="text-align:center; padding:18px 10px;
                                   border:1px solid #FECDD3; background-color:#FFF1F2;">
                <p style="font-size:32px; font-weight:bold; color:#E11D48;">{counts['CRITICAL']}</p>
            </td>
            <td width="20%" style="text-align:center; padding:18px 10px;
                                   border:1px solid #FED7AA; background-color:#FFF7ED;">
                <p style="font-size:32px; font-weight:bold; color:#EA580C;">{counts['HIGH']}</p>
            </td>
            <td width="20%" style="text-align:center; padding:18px 10px;
                                   border:1px solid #FDE68A; background-color:#FFFBEB;">
                <p style="font-size:32px; font-weight:bold; color:#D97706;">{counts['MEDIUM']}</p>
            </td>
            <td width="20%" style="text-align:center; padding:18px 10px;
                                   border:1px solid #BBF7D0; background-color:#F0FDF4;">
                <p style="font-size:32px; font-weight:bold; color:#16A34A;">{counts['LOW']}</p>
            </td>
            <td width="20%" style="text-align:center; padding:18px 10px;
                                   border:1px solid #BFDBFE; background-color:#EFF6FF;">
                <p style="font-size:32px; font-weight:bold; color:#2563EB;">{total}</p>
            </td>
        </tr>
    </table>

    <!-- ============================================ -->
    <!-- EXECUTIVE SUMMARY                            -->
    <!-- ============================================ -->
    <div style="margin-bottom:25px;">
        <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #C7D2FE;">
            <tr>
                <td style="background-color:#312E81; padding:15px 20px;
                           border-bottom:2px solid #4338CA;">
                    <p style="font-size:16px; font-weight:bold; color:#FFFFFF; margin:0;">
                        &#128220; Executive Summary
                    </p>
                </td>
            </tr>
            <tr>
                <td style="padding:20px; font-size:14px; line-height:24px;
                           background-color:#FAFAFF; color:#1E293B;">
                    This report presents the findings of an automated WebSocket security
                    assessment conducted against
                    <span style="font-weight:bold; color:#2563EB;">{html_lib.escape(target)}</span>.
                    The assessment identified
                    <span style="font-weight:bold; color:#7C3AED;">{total} vulnerabilities</span>
                    across the tested endpoints, with an overall risk rating of
                    <span style="font-weight:bold; color:{risk_color};">{risk}</span>.
                    {urgent_msg}
                </td>
            </tr>
        </table>
    </div>

    <!-- ============================================ -->
    <!-- VULNERABILITY SUMMARY TABLE                  -->
    <!-- ============================================ -->
    {toc_section}

    <!-- ============================================ -->
    <!-- DETAILED FINDINGS                            -->
    <!-- ============================================ -->
    <div style="margin-bottom:15px;">
        <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
                <td style="background-color:#7C3AED; padding:15px 20px;
                           border:1px solid #8B5CF6; border-bottom:2px solid #6D28D9;">
                    <p style="font-size:16px; font-weight:bold; color:#FFFFFF; margin:0;">
                        &#128270; Detailed Findings
                    </p>
                </td>
            </tr>
        </table>
    </div>

    {finding_blocks if findings else '<p style="text-align:center; padding:30px; color:#166534; font-size:14px; background-color:#F0FDF4; border:1px solid #16A34A; border-left:5px solid #16A34A;">&#10004; No vulnerabilities found. Target appears secure.</p>'}

    {ai_section}

    <!-- ============================================ -->
    <!-- PAGE FOOTER                                  -->
    <!-- ============================================ -->
    <div id="pageFooter">
        <table width="100%">
            <tr>
                <td colspan="3" style="border-top:2px solid #6366F1; padding:0; margin:0; height:2px;"></td>
            </tr>
            <tr>
                <td style="text-align:left; font-size:9px; color:#6366F1; font-weight:bold;">
                    WS Tester Pro &bull; Confidential
                </td>
                <td style="text-align:center; font-size:9px; color:#94A3B8;">
                    {now}
                </td>
                <td style="text-align:right; font-size:9px; color:#94A3B8;">
                    Page <pdf:pagenumber/>
                </td>
            </tr>
        </table>
    </div>

</body>
</html>'''
