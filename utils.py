# utils.py
import os, json, re, html
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
# ---------------- Patterns for user ID extraction ----------------
ID_PARAM_NAMES = {"id", "user_id", "uid", "userid", "member_id", "profile_id", "account_id"}
NUMERIC_RE = re.compile(r"\b(\d{3,12})\b")
ID_IN_PATH_RE = re.compile(r"/(user|profile|account|member)[s|/:-]*([0-9A-Za-z_-]+)", re.I)
USERID_PATTERN = re.compile(r'(?:user[_\- ]?id|uid|userid)["\':=\s]*["\']?([0-9A-Za-z_-]{3,40})', re.I)

# ---------------- Report saving ----------------
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def save_report(vulnerabilities, recommendations, out_file='report.json', reports_dir=None, open_after=False):
    """
    Save a standardized JSON report. Compatible with existing callers.
    """
    reports_dir = reports_dir or "reports"
    os.makedirs(reports_dir, exist_ok=True)

    if isinstance(vulnerabilities, dict) and "vulnerabilities" in vulnerabilities:
        report = vulnerabilities.copy()
        if "recommendations" not in report:
            report["recommendations"] = recommendations or []
        if "total_vulnerabilities" not in report:
            report["total_vulnerabilities"] = len(report.get("vulnerabilities", []))
    else:
        if isinstance(vulnerabilities, list):
            report = {
                "tool": "security_tester",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "recommendations": recommendations or []
            }
        else:
            try:
                vuln_list = list(vulnerabilities)
            except Exception:
                vuln_list = []
            report = {
                "tool": "security_tester",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_vulnerabilities": len(vuln_list),
                "vulnerabilities": vuln_list,
                "recommendations": recommendations or []
            }

    base = os.path.splitext(os.path.basename(out_file))[0]
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    filename = f"{base}_{timestamp}.json"
    out_path = os.path.join(reports_dir, filename)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[Report] Saved to {out_path}")
        if open_after:
            try:
                import webbrowser
                webbrowser.open(f"file://{os.path.abspath(out_path)}")
            except Exception:
                pass
        return out_path
    except Exception as e:
        print(f"[!] Failed to save report {out_file}: {e}")
        return None

# ---------------- Report loader ----------------
def _load_json_reports(reports_dir):
    entries = []
    if not os.path.isdir(reports_dir):
        return []

    for fname in os.listdir(reports_dir):
        if not fname.lower().endswith('.json'):
            continue
        path = os.path.join(reports_dir, fname)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, list):
                data = {
                    "tool": os.path.splitext(fname)[0],
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "total_vulnerabilities": len(data),
                    "vulnerabilities": data,
                    "recommendations": []
                }

            if isinstance(data, dict) and "vulnerabilities" not in data:
                maybe_list = None
                for k, v in data.items():
                    if isinstance(v, list) and any(
                        isinstance(x, dict) and ("url" in x or "test" in x or "payload" in x) for x in v[:3]
                    ):
                        maybe_list = v
                        break
                if maybe_list is not None:
                    data = {
                        "tool": data.get("tool", os.path.splitext(fname)[0]),
                        "generated_at": data.get("generated_at", datetime.utcnow().isoformat() + "Z"),
                        "total_vulnerabilities": len(maybe_list),
                        "vulnerabilities": maybe_list,
                        "recommendations": data.get("recommendations", [])
                    }

            entries.append((path, data))
        except Exception as e:
            print(f"[!] Failed to read {path}: {e}")

    def _sort_key(item):
        report = item[1]
        if isinstance(report, dict):
            gen = report.get("generated_at")
            if isinstance(gen, str):
                try:
                    return datetime.fromisoformat(gen.replace('Z', ''))
                except Exception:
                    pass
        return item[0]

    return sorted(entries, key=_sort_key, reverse=True)

# ---------------- User ID extraction ----------------
def extract_user_ids(metadata):
    ids = set()

    def add_if_id(val):
        if not val: return
        s = str(val)
        for m in NUMERIC_RE.findall(s): ids.add(m)
        for m in USERID_PATTERN.findall(s): ids.add(m)
        m2 = ID_IN_PATH_RE.search(s)
        if m2: ids.add(m2.group(2))

    pages = metadata if isinstance(metadata, list) else metadata.get("pages", [])
    for page in pages:
        url = page.get("url", "")
        qparams = page.get("query_params", {}) or {}
        if isinstance(qparams, dict):
            for k, v in qparams.items():
                if isinstance(v, (list, tuple)):
                    for item in v: add_if_id(item)
                else:
                    add_if_id(v)
        add_if_id(url)
        for form in page.get("forms", []) or []:
            add_if_id(form.get("action"))
            for inp in form.get("inputs", []) or []:
                add_if_id(inp.get("name"))
                add_if_id(inp.get("value"))
                add_if_id(inp.get("placeholder"))
        add_if_id(page.get("title"))
        for h in page.get("headings", []) or []: add_if_id(h)
        add_if_id(page.get("meta_description"))
        add_if_id(page.get("html_text") or page.get("text"))

    return sorted(ids)

# ---------------- Helpers ----------------
def _escape(s): return html.escape(str(s)) if s is not None else ""

# ---------------- Severity classification ----------------
def classify_severity(vuln: dict) -> str:
    vtype = str(vuln.get("test") or vuln.get("test_type") or vuln.get("type") or "").lower()
    reason = str(vuln.get("detection_method") or vuln.get("issue") or "").lower()
    payload = str(vuln.get("payload") or vuln.get("tested_payload") or "").lower()
    evidence = str(vuln.get("evidence") or vuln.get("response_snippet") or "").lower()

    if any(k in vtype for k in ["sqli", "sql injection", "auth bypass"]): return "High"
    if "drop table" in payload or "union select" in payload: return "High"
    if "authentication bypass" in reason or "session hijack" in reason: return "High"
    if any(k in vtype for k in ["xss", "csrf", "xxe"]): return "Medium"
    if "script" in evidence: return "Medium"
    if "exposed" in reason or "info disclosure" in reason: return "Medium"
    return "Low"

# ---------------- HTML card per report ----------------
def _report_card_html(path, report):
    tool = _escape(report.get('tool', 'unknown'))
    generated_at = _escape(report.get('generated_at', ''))
    total = report.get('total_vulnerabilities', 0)
    vulns = report.get('vulnerabilities', [])
    recommendations = report.get('recommendations', [])

    rows = []
    for i, v in enumerate(vulns):
        severity = classify_severity(v)
        rows.append({
            "idx": i+1,
            "url": _escape(v.get('url', '')),
            "type": _escape(v.get('test') or v.get('test_type') or v.get('type') or ''),
            "status": _escape(v.get('http_status', '') or ''),
            "payload": _escape(v.get('payload') or v.get('tested_payload') or ''),
            "reason": _escape(v.get('detection_method') or v.get('issue') or ''),
            "evidence_full": _escape(v.get('evidence') or v.get('response_snippet') or v.get('evidence_snippet') or ''),
            "severity": severity
        })

    card_html = f"""
    <section class="report-card">
      <h3>{tool} — {os.path.basename(path)}</h3>
      <div class="meta">Generated: {generated_at} — Findings: <strong>{total}</strong> — <a href="file://{os.path.abspath(path)}" target="_blank">raw JSON</a></div>
      <div class="vuln-summary">
        <table class="vuln-table">
          <thead><tr><th>#</th><th>URL</th><th>Type</th><th>Status</th><th>Payload/Target</th><th>Reason</th><th>Severity</th><th>Evidence</th></tr></thead>
          <tbody>
    """
    for r in rows:
        short = r["evidence_full"][:300] + ("…" if len(r["evidence_full"]) > 300 else "")
        sev_class = r['severity'].lower()
        card_html += f"""
          <tr class="sev-{sev_class}">
            <td>{r['idx']}</td>
            <td class="mono">{r['url']}</td>
            <td>{r['type']}</td>
            <td>{r['status']}</td>
            <td class="mono small">{r['payload']}</td>
            <td>{r['reason']}</td>
            <td><span class="sev-tag {sev_class}">{r['severity']}</span></td>
            <td>
              <div class="evidence-short">{short}</div>
              <details class="evidence-full"><summary>Show full evidence</summary><pre>{r['evidence_full']}</pre></details>
            </td>
          </tr>
        """
    card_html += """
          </tbody>
        </table>
      </div>
    """
    if recommendations:
        card_html += "<div class='recs'><strong>Recommendations:</strong><ul>"
        for rec in recommendations:
            card_html += f"<li>{_escape(rec)}</li>"
        card_html += "</ul></div>"
    card_html += "</section>"
    return card_html

# ---------------- Final report generator ----------------


def generate_full_scan_report(reports_dir='reports', out_file=None):
    os.makedirs(reports_dir, exist_ok=True)
    reports = _load_json_reports(reports_dir)
    summary, sev_summary, cards = {}, {"High": 0, "Medium": 0, "Low": 0}, []

    for path, data in reports:
        tool = data.get('tool', 'unknown')
        total = data.get('total_vulnerabilities', 0)
        summary[tool] = summary.get(tool, 0) + int(total)
        for v in data.get("vulnerabilities", []):
            sev_summary[classify_severity(v)] += 1
        cards.append(_report_card_html(path, data))

    grand_total = sum(summary.values())
    summary_rows = "".join(f"<tr><td>{_escape(tool)}</td><td>{count}</td></tr>" for tool, count in summary.items())
    sev_rows = "".join(f"<tr><td>{s}</td><td>{c}</td></tr>" for s, c in sev_summary.items())

    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    if not out_file:
        out_file = f"full_scan_{ts}.html"

    out_path_html = os.path.join(reports_dir, out_file)
    out_path_pdf = os.path.join(reports_dir, out_file.replace(".html", ".pdf"))

    # ---------------- HTML Report ----------------
    html_content = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Full Scan Report</title>
  <style>
    body {{
      font-family: "Inter", "Segoe UI", Roboto, Arial, sans-serif;
      margin: 0;
      padding: 0;
      background: #f4f6f9;
      color: #333;
      line-height: 1.6;
    }}
    header {{
      position: sticky;
      top: 0;
      background: #2563eb;
      color: #fff;
      padding: 18px 20px;
      text-align: center;
      box-shadow: 0 2px 6px rgba(0,0,0,0.15);
      z-index: 100;
      display:flex;
      justify-content:space-between;
      align-items:center;
    }}
    header h1 {{ margin: 0; font-size: 24px; font-weight: 600; }}
    section {{
      background: #fff;
      padding: 20px;
      margin: 20px auto;
      max-width: 1200px;
      border-radius: 10px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.08);
    }}
    section h2 {{ margin-top: 0; color: #2563eb; border-bottom: 2px solid #eee; padding-bottom: 6px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 14px;
    }}
    table th, table td {{
      border: 1px solid #e5e7eb;
      padding: 8px 10px;
      text-align: left;
    }}
    table th {{
      background: #f9fafb;
      font-weight: 600;
    }}
    .sev-tag.high {{ background: #fee2e2; color: #b91c1c; }}
    .sev-tag.medium {{ background: #fef3c7; color: #b45309; }}
    .sev-tag.low {{ background: #e0f2fe; color: #0369a1; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Full Scan Report</h1>
      <div>Generated: {datetime.utcnow().isoformat()}Z — Reports scanned: {len(reports)} — Total findings: {grand_total}</div>
    </div>
  </header>

  <section class="summary">
    <h2>Summary by Tool</h2>
    <table><thead><tr><th>Tool</th><th>Vulnerabilities</th></tr></thead><tbody>{summary_rows}</tbody></table>
    <h2>Summary by Severity</h2>
    <table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{sev_rows}</tbody></table>
  </section>

  <section id="reports">
    <h2>Reports</h2>
    {"".join(cards)}
  </section>
</body>
</html>
"""
    try:
        with open(out_path_html, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[Report] Full scan HTML saved to {out_path_html}")
    except Exception as e:
        print(f"[!] Failed to write HTML report: {e}")

    # ---------------- PDF Report ----------------
    try:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(out_path_pdf)
        elements = []

        # Cover
        elements.append(Paragraph("<b>WebScanPro — Full Scan Report</b>", styles['Title']))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles['Normal']))
        elements.append(Paragraph(f"Total Findings: {grand_total}", styles['Normal']))
        elements.append(Spacer(1, 30))

        # Severity Summary
        elements.append(Paragraph("<b>Summary by Severity</b>", styles['Heading2']))
        sev_table = [["Severity", "Count"]] + [[s, str(c)] for s, c in sev_summary.items()]
        table = Table(sev_table)
        table.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, colors.black),
            ("BACKGROUND", (0,0), (-1,0), colors.grey),
            ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke)
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # Vulnerabilities per tool
        elements.append(Paragraph("<b>Detailed Findings</b>", styles['Heading2']))
        for path, data in reports:
            vulns = data.get("vulnerabilities", [])
            if not vulns: continue
            elements.append(Paragraph(f"{data.get('tool','unknown')} — {len(vulns)} findings", styles['Heading3']))
            table_data = [["#", "URL", "Type", "Severity", "Payload", "Evidence"]]
            for i, v in enumerate(vulns, 1):
                table_data.append([
                    str(i),
                    v.get("url", ""),
                    v.get("test") or v.get("test_type") or v.get("type",""),
                    classify_severity(v),
                    str(v.get("payload") or v.get("tested_payload",""))[:30],
                    str(v.get("evidence") or v.get("response_snippet") or v.get("evidence_snippet",""))[:50]
                ])
            t = Table(table_data, repeatRows=1)
            t.setStyle(TableStyle([
                ("GRID", (0,0), (-1,-1), 0.25, colors.black),
                ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
                ("FONTSIZE", (0,0), (-1,-1), 7),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 15))

        doc.build(elements)
        print(f"[Report] Full scan PDF saved to {out_path_pdf}")
    except Exception as e:
        print(f"[!] Failed to write PDF report: {e}")

    return out_path_html, out_path_pdf
