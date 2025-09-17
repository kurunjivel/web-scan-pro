import json
import logging
import time
from urllib.parse import urlparse, urlunparse, urlencode
import requests
import difflib

class XssTester:
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'></iframe>",
    ]

    INJECTABLE_TYPES = {'text', 'search', 'email', 'url', 'tel', 'password', 'textarea'}

    def __init__(self, session=None, delay=1, timeout=10, similarity_threshold=0.85):
        self.session = session or requests.Session()
        self.delay = delay
        self.timeout = timeout
        self.similarity_threshold = similarity_threshold
        self.vulnerabilities = []
        logging.basicConfig(filename='xss_tester.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_tests(self, metadata):
        for page in metadata:
            url = page.get('url')
            forms = page.get('forms', [])
            query_params = page.get('query_params', {})
            baseline_resp = self._send_baseline_request(url, forms, query_params)
            baseline_text = baseline_resp.text.lower() if baseline_resp else ""


            # Test forms
            for form in forms:
                self.test_form(url, form, baseline_text)


            # Test URL parameters
            if query_params:
                self.test_url_params(url, query_params, baseline_text)

    def _send_baseline_request(self, url, forms, query_params):
        try:
            data = {}
            if forms:
                inputs = forms[0].get('inputs', [])
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        data[name] = inp.get('value', '')
                action = forms[0].get('action') or url
                method = forms[0].get('method', 'GET').upper()
                if method == 'POST':
                    return self.session.post(action, data=data, timeout=self.timeout)
                else:
                    return self.session.get(action, params=data, timeout=self.timeout)
            else:
                params = {k: (v[0] if isinstance(v, (list, tuple)) else v) for k, v in query_params.items()}
                return self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            logging.error(f"Error fetching baseline for {url}: {e}")
            return None

    def test_form(self, url, form, baseline_text):
        action = form.get('action') or url
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        injectable = []
        data = {}
        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue
            typ = (inp.get('type') or 'text').lower()
            value = inp.get('value', '')
            data[name] = value
            if typ in self.INJECTABLE_TYPES:
                injectable.append(name)

        if not injectable:
            logging.info(f"No injectable fields in form at {action}")
            return

        for payload in self.XSS_PAYLOADS:
            test_data = data.copy()
            for name in injectable:
                test_data[name] = payload
            try:
                logging.info(f"Testing form at {action} with payload: {payload}")
                start = time.time()
                if method == 'POST':
                    response = self.session.post(action, data=test_data, timeout=self.timeout)
                else:
                    response = self.session.get(action, params=test_data, timeout=self.timeout)
                elapsed = time.time() - start
                content = response.text.lower()
                self.analyze_response(url, 'form', action, test_data, response, payload, baseline_text)
                time.sleep(self.delay)
            except requests.RequestException as e:
                logging.error(f"Error testing form at {action}: {e}")

    def test_url_params(self, url, query_params, baseline_text):
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        params = {k: (v[0] if isinstance(v, (list, tuple)) else v) for k, v in query_params.items()}

        for param in params.keys():
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                encoded = urlencode(test_params)
                test_url = f"{base_url}?{encoded}"
                try:
                    logging.info(f"Testing URL {test_url} with payload in {param}")
                    start = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    elapsed = time.time() - start
                    content = response.text.lower()
                    self.analyze_response(url, 'url_param', param, test_params, response, payload, baseline_text)
                    time.sleep(self.delay)
                except requests.RequestException as e:
                    logging.error(f"Error testing URL param at {test_url}: {e}")
    def analyze_response(self, original_url, test_type, target, data, response, payload, baseline_text):
        content = response.text.lower()
        evidence = self.get_snippet(content, payload.lower())

        # Direct
        if payload.lower() in content:
            self.record_vulnerability(original_url, test_type, target, data, response, "direct_presence", evidence)
            return

        # Behavioral
        try:
            similarity = difflib.SequenceMatcher(None, baseline_text, content).ratio()
        except Exception:
            similarity = 1.0
        logging.info(f"Similarity for {target}: {similarity:.2f}")
        if similarity < self.similarity_threshold:
            self.record_vulnerability(original_url, test_type, target, data, response, "behavioral_difference", evidence)

    def record_vulnerability(self, url, test_type, target, data, response, method, evidence):
        vuln = {
            'url': url,
            'test_type': test_type,
            'target': target,
            'payload': data,
            'http_status': response.status_code,
            'detection_method': method,
            'evidence': evidence
        }
        self.vulnerabilities.append(vuln)
        logging.warning(f"XSS vulnerability found: {vuln}")

    def get_snippet(self, content, pattern, length=200):
        index = content.find(pattern)
        if index == -1:
            return content[:length]
        start = max(index - length // 2, 0)
        end = min(index + length // 2, len(content))
        return content[start:end]

    def generate_report(self, out_file='xss_report.json'):
        report = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [
                "Validate and sanitize all user inputs.",
                "Encode outputs to prevent HTML/JS injection.",
                "Use frameworks that automatically escape dangerous characters.",
                "Implement Content Security Policy (CSP).",
                "Avoid reflecting user input directly without sanitization."
            ]
        }
        with open(out_file, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"XSS testing completed. Report saved to {out_file}")
