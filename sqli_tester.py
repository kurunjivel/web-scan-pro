# sqlitester.py
import json
import requests
from urllib.parse import urlparse, urlunparse, urlencode
import re
import logging
import time
import difflib

class SQLiTester:
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='2",
        "' OR 1=1--",
        "' OR 1=2--",
        "' OR SLEEP(5)--",
        "\" OR \"1\"=\"1",
        "\" OR \"1\"=\"2",
        "' OR 'x'='x",
        "' OR 'x'='y",
    ]

    SQL_ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"syntax error", re.I),
        re.compile(r"sqlstate", re.I),
    ]

    # input types we will inject into (do not replace hidden tokens by default)
    INJECTABLE_TYPES = {'text', 'search', 'email', 'url', 'tel', 'password', 'textarea'}

    def __init__(self, session=None, delay=1, timeout=10, similarity_threshold=0.90):
        self.delay = delay
        self.timeout = timeout
        self.session = session or requests.Session()
        self.vulnerabilities = []
        self.similarity_threshold = similarity_threshold  # higher = more similar (less likely vuln)
        logging.basicConfig(filename='sqlitester.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_tests(self, metadata):
        """
        metadata: list of page dicts produced by crawler (each containing url, forms, query_params)
        """
        for page in metadata:
            url = page.get('url')
            forms = page.get('forms', [])
            query_params = page.get('query_params', {})

            # Test forms
            for form in forms:
                self.test_form(url, form)

            # Test URL parameters
            if query_params:
                self.test_url_params(url, query_params)

    # ---------- Form testing ----------
    def test_form(self, page_url, form):
        action = form.get('action') or page_url
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])

        # Build a baseline payload using original values (or empty strings)
        baseline_data = {}
        injectable_names = []
        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue
            typ = (inp.get('type') or 'text').lower()
            baseline_data[name] = inp.get('value', '')
            if typ in self.INJECTABLE_TYPES:
                injectable_names.append((name, typ))

        # If there are no injectable fields, skip
        if not injectable_names:
            logging.info(f"No injectable form inputs found for {action}, skipping.")
            return

        # Get baseline response for comparison
        baseline_resp = self._send_request(action, method, baseline_data)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""

        for payload in self.SQLI_PAYLOADS:
            # create data dict copying baseline and replacing only injectable fields
            data = baseline_data.copy()
            for name, _ in injectable_names:
                data[name] = payload

            try:
                logging.info(f"Testing form at {action} with payload: {payload}")
                start_time = time.time()
                resp = self._send_request(action, method, data)
                elapsed = time.time() - start_time
                if resp is None:
                    continue

                self.analyze_response(page_url, 'form', action, data, resp, elapsed, payload, baseline_text)
                time.sleep(self.delay)
            except requests.RequestException as e:
                logging.error(f"Request error testing form at {action}: {e}")

    # ---------- URL param testing ----------
    def test_url_params(self, url, query_params):
        parsed_url = urlparse(url)
        base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

        # build baseline params (use first value or empty)
        baseline_params = {k: (v[0] if isinstance(v, (list, tuple)) and v else '') for k, v in query_params.items()}

        # baseline response
        baseline_resp = self._send_request(base_url, 'GET', baseline_params, params_mode=True)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""

        for param in query_params.keys():
            for payload in self.SQLI_PAYLOADS:
                new_params = baseline_params.copy()
                new_params[param] = payload

                try:
                    test_url = f"{base_url}?{urlencode(new_params)}"
                    logging.info(f"Testing URL {test_url} with payload in param {param}")
                    start_time = time.time()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    elapsed = time.time() - start_time
                    self.analyze_response(url, 'url_param', param, {param: payload}, resp, elapsed, payload, baseline_text)
                    time.sleep(self.delay)
                except requests.RequestException as e:
                    logging.error(f"Request error testing URL param at {test_url}: {e}")

    # ---------- Response analysis ----------
    def analyze_response(self, original_url, test_type, target, payload, response, elapsed, raw_payload, baseline_text):
        content = response.text or ""
        content_lower = content.lower()
        vuln_detected = False

        # 1) Error-based detection (search patterns)
        for pattern in self.SQL_ERROR_PATTERNS:
            if pattern.search(content):
                self.record_vulnerability(original_url, test_type, target, payload, response, pattern.pattern, content)
                vuln_detected = True
                break

        if vuln_detected:
            return

        # 2) Time-based detection (look for SLEEP/WAITFOR style payloads)
        sleep_seconds = self._extract_sleep_time(raw_payload)
        if sleep_seconds:
            if elapsed >= max(4, sleep_seconds - 1):  # tolerate slight timing variation
                self.record_vulnerability(original_url, test_type, target, payload, response, f"time_based_{sleep_seconds}s", content)
                return

        # 3) Boolean/behavioral detection by comparing with baseline
        if baseline_text is not None:
            # compute similarity ratio
            try:
                ratio = difflib.SequenceMatcher(None, baseline_text, content).ratio()
            except Exception:
                ratio = 1.0

            logging.info(f"Behavioral similarity for {target}: {ratio:.3f}")

            # If response differs significantly (ratio below threshold) flag as potential vulnerability
            if ratio < self.similarity_threshold:
                # additional quick checks to avoid false positives
                if response.status_code < 500:
                    self.record_vulnerability(original_url, test_type, target, payload, response, "behavioral_difference", self.get_snippet(content, raw_payload))
                    return

        # No detection
        logging.info(f"No SQLi detected for {target} with payload {raw_payload}")

    # ---------- Helpers ----------
    def record_vulnerability(self, url, test_type, target, payload, response, reason, content_snippet):
        vuln = {
            'url': url,
            'test_type': test_type,
            'target': target,
            'payload': payload,
            'http_status': response.status_code if response is not None else None,
            'detection_method': reason,
            'response_snippet': content_snippet[:500] if content_snippet else ''
        }
        self.vulnerabilities.append(vuln)
        logging.warning(f"Vulnerability found: {vuln}")

    def get_snippet(self, content, pattern, snippet_length=300):
        if not content:
            return ""
        lower = content.lower()
        pat = pattern.lower() if isinstance(pattern, str) else None
        idx = lower.find(pat) if pat else -1
        if idx == -1:
            return content[:snippet_length]
        start = max(idx - snippet_length // 2, 0)
        end = min(idx + len(pat) + snippet_length // 2, len(content))
        return content[start:end]

    def _send_request(self, action, method, data, params_mode=False):
        """
        Helper to send GET/POST. If params_mode True, data is used as query params.
        Returns Response or None (if error).
        """
        try:
            if method.upper() == 'POST' and not params_mode:
                return self.session.post(action, data=data, timeout=self.timeout)
            else:
                return self.session.get(action, params=data if params_mode else data, timeout=self.timeout)
        except requests.RequestException as e:
            logging.error(f"Error sending request to {action}: {e}")
            return None

    def _extract_sleep_time(self, payload):
        """
        Try to parse SLEEP(n) or WAITFOR DELAY '0:0:n' in payload and return n as int.
        """
        m = re.search(r"SLEEP\((\d+)\)", payload, re.I)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                return None
        m2 = re.search(r"WAITFOR\s+DELAY\s+'0:0:(\d+)'", payload, re.I)
        if m2:
            try:
                return int(m2.group(1))
            except Exception:
                return None
        return None

    def generate_report(self, out_file='sqli_report.json'):
        total_vulns = len(self.vulnerabilities)
        report = {
            'total_vulnerabilities': total_vulns,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [
                "Use parameterized queries or prepared statements.",
                "Implement proper input validation and sanitization.",
                "Use stored procedures where applicable.",
                "Implement proper error handling to avoid exposing database errors.",
                "Limit database user permissions to minimize impact."
            ]
        }
        with open(out_file, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"SQL Injection testing completed. Report saved to {out_file}")
