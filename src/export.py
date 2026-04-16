#!/usr/bin/env python3
"""
METATRON - export.py
Export scan results to PDF and HTML reports.
Reports are saved to /app/reports/ (mapped to ./output/ on the host via Docker volume).
"""

import os
import re
import html
import datetime
import mysql.connector
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable


SEVERITY_COLORS = {
    "critical": "#ff0000",
    "high":     "#ff6600",
    "medium":   "#ffaa00",
    "low":      "#00aa00",
    "unknown":  "#888888",
}

RISK_COLORS = {
    "CRITICAL": "#ff0000",
    "HIGH":     "#ff6600",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#00aa00",
    "UNKNOWN":  "#888888",
}

REPORT_DIR = "/app/reports"


def _safe_target(target: str) -> str:
    """Strip URL scheme and replace path-unsafe characters so target is safe in a filename."""
    s = re.sub(r'^https?://', '', target)
    s = re.sub(r'[/:*?"<>|\\]', '_', s)
    s = re.sub(r'_+', '_', s)
    return s.strip('_') or 'unknown'


def get_connection():
    """Returns a MariaDB connection configured via environment variables."""
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "metatron"),
        password=os.environ.get("DB_PASSWORD", "123"),
        database=os.environ.get("DB_NAME", "metatron"),
    )


def fetch_session(sl_no):
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    exploits = c.fetchall()

    c.execute("SELECT * FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()

    conn.close()
    return {
        "history":  history,
        "vulns":    vulns,
        "fixes":    fixes,
        "exploits": exploits,
        "summary":  summary,
    }


def fetch_all_history():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def export_pdf(data, output_dir=None):
    if output_dir is None:
        output_dir = REPORT_DIR
    os.makedirs(output_dir, exist_ok=True)

    h = data["history"]
    sl_no  = h[0]
    target = h[1]
    ts     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname  = os.path.join(output_dir, f"metatron_report_{sl_no}_{_safe_target(target)}_{ts}.pdf")

    doc    = SimpleDocTemplate(fname, pagesize=letter,
                               rightMargin=0.75*inch, leftMargin=0.75*inch,
                               topMargin=0.75*inch,   bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                 fontSize=20, textColor=colors.HexColor("#cc0000"),
                                 spaceAfter=6)
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                 fontSize=14, textColor=colors.HexColor("#333333"),
                                 spaceBefore=12, spaceAfter=6)
    body_style  = ParagraphStyle("Body", parent=styles["Normal"],
                                 fontSize=10, leading=14)

    story.append(Paragraph("METATRON Penetration Test Report", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#cc0000")))
    story.append(Spacer(1, 0.15*inch))

    meta = [
        ["Target",     target],
        ["Scan Date",  str(h[2])],
        ["Status",     h[3]],
        ["Session",    f"SL# {sl_no}"],
    ]
    if data["summary"]:
        s = data["summary"]
        risk = s[4] or "UNKNOWN"
        meta.append(["Risk Level", risk])
        meta.append(["Generated",  str(s[5])])

    meta_table = Table(meta, colWidths=[1.5*inch, 5*inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#eeeeee")),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.2*inch))

    if data["vulns"]:
        story.append(Paragraph("Vulnerabilities", h2_style))
        for v in data["vulns"]:
            sev       = (v[3] or "unknown").lower()
            sev_color = colors.HexColor(SEVERITY_COLORS.get(sev, "#888888"))
            v_table   = Table([
                ["Name",        v[2] or ""],
                ["Severity",    v[3] or ""],
                ["Port",        v[4] or ""],
                ["Service",     v[5] or ""],
                ["Description", v[6] or ""],
            ], colWidths=[1.5*inch, 5*inch])
            v_table.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#eeeeee")),
                ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, -1), 9),
                ("TEXTCOLOR",   (1, 1), (1, 1), sev_color),
                ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("PADDING",     (0, 0), (-1, -1), 5),
                ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(v_table)
            story.append(Spacer(1, 0.1*inch))

    if data["fixes"]:
        story.append(Paragraph("Fixes and Mitigations", h2_style))
        for f in data["fixes"]:
            story.append(Paragraph(f"Fix ID {f[0]} (vuln {f[2]}): {f[3]}", body_style))
            story.append(Spacer(1, 0.05*inch))

    if data["exploits"]:
        story.append(Paragraph("Exploits Attempted", h2_style))
        for e in data["exploits"]:
            e_table = Table([
                ["Name",    e[2] or ""],
                ["Tool",    e[3] or ""],
                ["Payload", e[4] or ""],
                ["Result",  e[5] or ""],
                ["Notes",   e[6] or ""],
            ], colWidths=[1.5*inch, 5*inch])
            e_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
                ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("PADDING",    (0, 0), (-1, -1), 5),
                ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(e_table)
            story.append(Spacer(1, 0.1*inch))

    if data["summary"]:
        story.append(Paragraph("AI Analysis Summary", h2_style))
        ai_text = (data["summary"][3] or "").replace("\n", "<br/>")
        story.append(Paragraph(ai_text, body_style))

    doc.build(story)
    print(f"[+] PDF report saved: {fname}")
    return fname


def export_html(data, output_dir=None):
    if output_dir is None:
        output_dir = REPORT_DIR
    os.makedirs(output_dir, exist_ok=True)

    h      = data["history"]
    sl_no  = h[0]
    target = h[1]
    ts     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname  = os.path.join(output_dir, f"metatron_report_{sl_no}_{_safe_target(target)}_{ts}.html")

    risk      = "UNKNOWN"
    generated = ""
    ai_text   = ""
    if data["summary"]:
        s         = data["summary"]
        risk      = s[4] or "UNKNOWN"
        generated = str(s[5])
        ai_text   = (s[3] or "").replace("\n", "<br>")

    risk_color = RISK_COLORS.get(risk, "#888888")

    vuln_rows = ""
    for v in data["vulns"]:
        sev       = (v[3] or "unknown").lower()
        sev_color = SEVERITY_COLORS.get(sev, "#888888")
        vuln_rows += f"""
        <tr>
            <td>{v[2] or ""}</td>
            <td style="color:{sev_color};font-weight:bold">{v[3] or ""}</td>
            <td>{v[4] or ""}</td>
            <td>{v[5] or ""}</td>
            <td>{v[6] or ""}</td>
        </tr>"""

    fix_rows = ""
    for f in data["fixes"]:
        fix_rows += f"<li>Fix {f[0]} (vuln {f[2]}): {f[3]}</li>"

    exploit_rows = ""
    for e in data["exploits"]:
        exploit_rows += f"""
        <tr>
            <td>{e[2] or ""}</td>
            <td>{e[3] or ""}</td>
            <td><code>{e[4] or ""}</code></td>
            <td>{e[5] or ""}</td>
            <td>{e[6] or ""}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Metatron Report - {target}</title>
<style>
  body {{ background:#0d0d0d; color:#e0e0e0; font-family:monospace; padding:2em; }}
  h1   {{ color:#cc0000; border-bottom:2px solid #cc0000; padding-bottom:0.3em; }}
  h2   {{ color:#ff6600; margin-top:2em; }}
  table {{ border-collapse:collapse; width:100%; margin-bottom:1em; }}
  th   {{ background:#1a1a1a; color:#aaa; text-align:left; padding:8px; }}
  td   {{ border:1px solid #333; padding:8px; vertical-align:top; }}
  tr:nth-child(even) {{ background:#111; }}
  code {{ background:#1a1a1a; padding:2px 6px; border-radius:3px; color:#7ec8e3; }}
  .meta-label {{ color:#888; font-weight:bold; width:140px; }}
  .risk {{ font-size:1.4em; font-weight:bold; color:{risk_color}; }}
  .ai-box {{ background:#111; border:1px solid #333; padding:1em; border-radius:4px; line-height:1.6; }}
</style>
</head>
<body>
<h1>METATRON Penetration Test Report</h1>
<table>
  <tr><td class="meta-label">Target</td><td>{target}</td></tr>
  <tr><td class="meta-label">Scan Date</td><td>{h[2]}</td></tr>
  <tr><td class="meta-label">Status</td><td>{h[3]}</td></tr>
  <tr><td class="meta-label">Session</td><td>SL# {sl_no}</td></tr>
  <tr><td class="meta-label">Risk Level</td><td><span class="risk">{risk}</span></td></tr>
  <tr><td class="meta-label">Generated</td><td>{generated}</td></tr>
</table>

<h2>Vulnerabilities</h2>
<table>
  <tr><th>Name</th><th>Severity</th><th>Port</th><th>Service</th><th>Description</th></tr>
  {vuln_rows if vuln_rows else "<tr><td colspan='5'>None recorded.</td></tr>"}
</table>

<h2>Fixes and Mitigations</h2>
<ul>{fix_rows if fix_rows else "<li>None recorded.</li>"}</ul>

<h2>Exploits Attempted</h2>
<table>
  <tr><th>Name</th><th>Tool</th><th>Payload</th><th>Result</th><th>Notes</th></tr>
  {exploit_rows if exploit_rows else "<tr><td colspan='5'>None recorded.</td></tr>"}
</table>

<h2>AI Analysis Summary</h2>
<div class="ai-box">{ai_text if ai_text else "None recorded."}</div>

</body>
</html>"""

    with open(fname, "w") as fh:
        fh.write(html)
    print(f"[+] HTML report saved: {fname}")
    return fname


def export_menu(data):
    print("\n[ EXPORT OPTIONS ]")
    print("  [1] Export as PDF")
    print("  [2] Export as HTML")
    print("  [3] Export both")
    print("  [4] Back")
    choice = input("\nChoice: ").strip()

    if choice == "1":
        export_pdf(data)
    elif choice == "2":
        export_html(data)
    elif choice == "3":
        export_pdf(data)
        export_html(data)
    else:
        return


# =============================================================================
# RED TEAM REPORT EXPORT
# =============================================================================

def export_red_team_pdf(target: str, sl_no: int, report: dict, output_dir: str = None) -> str:
    """
    Export the red team report as a standalone PDF.
    report: dict returned by generate_red_team_report()
    """
    if output_dir is None:
        output_dir = REPORT_DIR
    os.makedirs(output_dir, exist_ok=True)

    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(output_dir, f"redteam_report_{sl_no}_{_safe_target(target)}_{ts}.pdf")

    doc    = SimpleDocTemplate(fname, pagesize=letter,
                               rightMargin=0.75*inch, leftMargin=0.75*inch,
                               topMargin=0.75*inch,   bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story  = []

    title_style   = ParagraphStyle("Title", parent=styles["Title"],
                                   fontSize=20, textColor=colors.HexColor("#cc0000"),
                                   spaceAfter=6)
    section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                   fontSize=13, textColor=colors.HexColor("#cc6600"),
                                   spaceBefore=14, spaceAfter=6)
    body_style    = ParagraphStyle("Body", parent=styles["Normal"],
                                   fontSize=9, leading=13,
                                   fontName="Courier")

    story.append(Paragraph("RED TEAM ENGAGEMENT BRIEF", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#cc0000")))
    story.append(Spacer(1, 0.1*inch))

    meta = [
        ["Target",       target],
        ["Session",      f"SL# {sl_no}"],
        ["Generated",    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Classification", "CONFIDENTIAL — Authorized Penetration Test Only"],
    ]
    meta_table = Table(meta, colWidths=[1.8*inch, 4.7*inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#eeeeee")),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("PADDING",     (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.2*inch))

    for section_label, key in [
        ("Section 1: Vulnerability Assessment",  "research_data"),
        ("Section 2: Attack Chains",             "attack_chains"),
        ("Section 3: Red Team Directions",       "red_team_directions"),
    ]:
        content = (report.get(key) or "").strip()
        if not content:
            continue
        story.append(Paragraph(section_label, section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cc6600")))
        story.append(Spacer(1, 0.05*inch))
        for line in content.splitlines():
            if line.strip():
                story.append(Paragraph(html.escape(line), body_style))
            else:
                story.append(Spacer(1, 0.06*inch))
        story.append(Spacer(1, 0.1*inch))

    doc.build(story)
    print(f"[+] Red team PDF saved: {fname}")
    return fname


def export_red_team_html(target: str, sl_no: int, report: dict, output_dir: str = None) -> str:
    """
    Export the red team report as a standalone dark-theme HTML file.
    report: dict returned by generate_red_team_report()
    """
    if output_dir is None:
        output_dir = REPORT_DIR
    os.makedirs(output_dir, exist_ok=True)

    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(output_dir, f"redteam_report_{sl_no}_{_safe_target(target)}_{ts}.html")

    def _section_html(content: str) -> str:
        if not content:
            return "<p>No data.</p>"
        lines = []
        for line in content.splitlines():
            if not line.strip():
                lines.append("<br>")
            elif line.startswith(("CHAIN ", "PHASE:", "SECTION:", "RESEARCH:",
                                   "ENTRY:", "STEP:", "GOAL:", "ACTION:",
                                   "DOCUMENT:", "MITRE:", "CVE:", "CVSS:",
                                   "EXPLOITS:", "IN_THE_WILD:", "PATCH_STATUS:",
                                   "NOTES:", "LIKELIHOOD:", "DIFFICULTY:",
                                   "EXPECTED_OUTPUT:")):
                key, _, val = line.partition(":")
                lines.append(
                    f'<span class="label">{key.strip()}:</span> '
                    f'{val.strip()}<br>'
                )
            else:
                lines.append(line + "<br>")
        return "\n".join(lines)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Red Team Brief - {target}</title>
<style>
  body       {{ background:#0d0d0d; color:#e0e0e0; font-family:monospace; padding:2em; }}
  h1         {{ color:#cc0000; border-bottom:2px solid #cc0000; padding-bottom:0.3em; }}
  h2         {{ color:#ff6600; margin-top:2em; border-left:3px solid #ff6600; padding-left:0.5em; }}
  table      {{ border-collapse:collapse; width:100%; margin-bottom:1.5em; }}
  th         {{ background:#1a1a1a; color:#aaa; text-align:left; padding:8px; }}
  td         {{ border:1px solid #333; padding:8px; vertical-align:top; }}
  .meta-label{{ color:#888; font-weight:bold; width:200px; }}
  .section   {{ background:#111; border:1px solid #333; padding:1em 1.5em;
                border-radius:4px; line-height:1.8; margin-bottom:2em; }}
  .label     {{ color:#ff6600; font-weight:bold; }}
  .classify  {{ background:#3a0000; color:#ff4444; padding:0.5em 1em;
                border-radius:3px; display:inline-block; margin-bottom:1em; }}
</style>
</head>
<body>
<h1>RED TEAM ENGAGEMENT BRIEF</h1>
<div class="classify">CONFIDENTIAL -- Authorized Penetration Test Only</div>
<table>
  <tr><td class="meta-label">Target</td><td>{target}</td></tr>
  <tr><td class="meta-label">Session</td><td>SL# {sl_no}</td></tr>
  <tr><td class="meta-label">Generated</td><td>{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
</table>

<h2>Section 1: Vulnerability Assessment</h2>
<div class="section">{_section_html(report.get("research_data", ""))}</div>

<h2>Section 2: Attack Chains</h2>
<div class="section">{_section_html(report.get("attack_chains", ""))}</div>

<h2>Section 3: Red Team Directions</h2>
<div class="section">{_section_html(report.get("red_team_directions", ""))}</div>

</body>
</html>"""

    with open(fname, "w") as fh:
        fh.write(html)
    print(f"[+] Red team HTML saved: {fname}")
    return fname


def export_red_team_menu(target: str, sl_no: int, report: dict):
    """Interactive menu to export the red team report."""
    print("\n[ RED TEAM REPORT EXPORT ]")
    print("  [1] Export as PDF")
    print("  [2] Export as HTML")
    print("  [3] Export both")
    print("  [4] Skip")
    choice = input("\nChoice: ").strip()

    if choice == "1":
        export_red_team_pdf(target, sl_no, report)
    elif choice == "2":
        export_red_team_html(target, sl_no, report)
    elif choice == "3":
        export_red_team_pdf(target, sl_no, report)
        export_red_team_html(target, sl_no, report)
    else:
        return


if __name__ == "__main__":
    rows = fetch_all_history()
    if not rows:
        print("[!] No scan sessions in database.")
        exit(0)

    print("\n[ SCAN HISTORY ]")
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")

    sl_no_str = input("\nEnter SL# to export: ").strip()
    if not sl_no_str.isdigit():
        print("[!] Invalid SL#.")
        exit(1)

    data = fetch_session(int(sl_no_str))
    if not data["history"]:
        print(f"[!] SL# {sl_no_str} not found.")
        exit(1)

    export_menu(data)
