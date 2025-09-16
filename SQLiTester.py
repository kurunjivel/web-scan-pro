import json
import requests
from urllib.parse import urlparse, urlunparse, urlencode
import re
import logging
import time

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

    def __init__(self, session=None, delay=1, timeout=10):
        self.delay = delay
        self.timeout = timeout
        self.session = session or requests.Session()
        self.vulnerabilities = []
        logging.basicConfig(filename='sqlitester.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_tests(self, metadata):
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

    def test_form(self, url, form):
        action = form.get('action') or url
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])

        for payload in self.SQLI_PAYLOADS:
            data = {}
            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue
                data[name] = payload

            try:
                logging.info(f"Testing form at {action} with payload: {payload}")
                start_time = time.time()
                if method == 'POST':
                    response = self.session.post(action, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(action, params=data, timeout=self.timeout)
                elapsed = time.time() - start_time

                self.analyze_response(url, 'form', action, data, response, elapsed, payload)

                time.sleep(self.delay)
            except requests.RequestException as e:
                logging.error(f"Request error testing form at {action}: {e}")

    def test_url_params(self, url, query_params):
        parsed_url = urlparse(url)
        base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

        for param in query_params.keys():
            for payload in self.SQLI_PAYLOADS:
                new_params = query_params.copy()
                new_params[param] = [payload]

                encoded_params = urlencode(new_params, doseq=True)
                test_url = f"{base_url}?{encoded_params}"

                try:
                    logging.info(f"Testing URL {test_url} with payload in param {param}")
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    elapsed = time.time() - start_time

                    self.analyze_response(url, 'url_param', param, {param: payload}, response, elapsed, payload)
                    time.sleep(self.delay)
                except requests.RequestException as e:
                    logging.error(f"Request error testing URL param at {test_url}: {e}")

    def analyze_response(self, original_url, test_type, target, payload, response, elapsed, raw_payload):
        content = response.text.lower()
        vuln_detected = False

        # 1️⃣ Error-based detection
        for pattern in self.SQL_ERROR_PATTERNS:
            if pattern.search(content):
                self.record_vulnerability(original_url, test_type, target, payload, response, pattern.pattern, content)
                vuln_detected = True
                break

        # 2️⃣ Boolean-based detection
        if not vuln_detected and ("' or '1'='1" in raw_payload or "\" or \"1\"=\"1" in raw_payload):
            # simple check: does response change compared to safe payload
            # In practice, you may need baseline comparison
            if "error" not in content:  # naive check
                self.record_vulnerability(original_url, test_type, target, payload, response, "boolean_based_test", content)
                vuln_detected = True

        # 3️⃣ Time-based detection
        if not vuln_detected and "sleep" in raw_payload.lower():
            if elapsed >= 5:  # assuming SLEEP(5)
                self.record_vulnerability(original_url, test_type, target, payload, response, "time_based_test", content)
                vuln_detected = True

    def record_vulnerability(self, url, test_type, target, payload, response, reason, content):
        vuln = {
            'url': url,
            'test_type': test_type,
            'target': target,
            'payload': payload,
            'http_status': response.status_code,
            'detection_method': reason,
            'response_snippet': self.get_snippet(content, reason)
        }
        self.vulnerabilities.append(vuln)
        logging.warning(f"Vulnerability found: {vuln}")

    def get_snippet(self, content, pattern, snippet_length=200):
        if isinstance(pattern, str):
            start = content.find(pattern)
            if start == -1:
                return content[:snippet_length]
            end = start + len(pattern)
        else:
            match = pattern.search(content)
            if not match:
                return content[:snippet_length]
            start = max(match.start() - snippet_length // 2, 0)
            end = min(match.end() + snippet_length // 2, len(content))
        return content[start:end]

    def generate_report(self):
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
        report_file = 'sqli_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"SQL Injection testing completed. Report saved to {report_file}")
