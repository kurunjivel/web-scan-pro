# utils.py
import os, json
from datetime import datetime
import re
from urllib.parse import urlparse, parse_qs

ID_PARAM_NAMES = {"id", "user_id", "uid", "userid", "member_id", "profile_id", "account_id"}

NUMERIC_RE = re.compile(r"\b(\d{3,12})\b")  # tune as needed
ID_IN_PATH_RE = re.compile(r"/(user|profile|account|member)[s|/:-]*([0-9A-Za-z_-]+)", re.I)
USERID_PATTERN = re.compile(r'(?:user[_\- ]?id|uid|userid)["\':=\s]*["\']?([0-9A-Za-z_-]{3,40})', re.I)

def save_report(vulnerabilities, recommendations, out_file='report.json', reports_dir=None, open_after=False):
    """
    Save a standardized JSON report. Returns the saved path.
    """
    reports_dir = reports_dir or "reports"
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    # if out_file contains a dir part, ignore it and write to reports_dir
    filename = f"{os.path.splitext(out_file)[0]}_{timestamp}.json"
    out_path = os.path.join(reports_dir, filename)
    report = {
        "tool": "security_tester",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[Report] Saved to {out_path}")
    # optionally open file on some OSes (not used in headless)
    if open_after:
        try:
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(out_path)}")
        except:
            pass
    return out_path

def extract_user_ids(metadata):
    """
    Given crawler results (list of page dicts), return deduplicated list of candidate IDs (strings).
    The function is tolerant of your crawler's structure: url, query_params, forms, title, headings.
    """
    ids = set()

    def add_if_id(val):
        if not val:
            return
        s = str(val)
        # numeric tokens
        for m in NUMERIC_RE.findall(s):
            ids.add(m)
        # user id in patterns
        for m in USERID_PATTERN.findall(s):
            ids.add(m)
        # path-based
        m2 = ID_IN_PATH_RE.search(s)
        if m2:
            ids.add(m2.group(2))

    pages = metadata if isinstance(metadata, list) else metadata.get("pages", [])
    for page in pages:
        url = page.get("url", "")
        # query params may already be parsed as dict-of-lists
        qparams = page.get("query_params", {}) or {}
        # if query_params are strings or dicts, normalize
        if isinstance(qparams, dict):
            for k, v in qparams.items():
                if k.lower() in ID_PARAM_NAMES:
                    if isinstance(v, (list,tuple)):
                        for item in v: add_if_id(item)
                    else:
                        add_if_id(v)
                else:
                    # still scan values
                    if isinstance(v, (list,tuple)):
                        for item in v: add_if_id(item)
                    else:
                        add_if_id(v)

        # URL path segments
        add_if_id(url)

        # forms
        for form in page.get("forms", []) or []:
            # action
            add_if_id(form.get("action"))
            for inp in form.get("inputs", []) or []:
                add_if_id(inp.get("name"))
                add_if_id(inp.get("value"))
                add_if_id(inp.get("placeholder"))

        # text/title/headings
        add_if_id(page.get("title"))
        for h in page.get("headings", []) or []:
            add_if_id(h)
        add_if_id(page.get("meta_description"))
        # raw html/text if present
        add_if_id(page.get("html_text") or page.get("text"))

    return sorted(ids)
