# access_control_tester.py
import requests
import json
import logging
import time
import os
from urllib.parse import urlencode, urlparse, urlunparse

from WebScanPro.utils import save_report

logging.basicConfig(filename='access_control.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class AccessControlTester:
    def __init__(self, session=None, delay=1, timeout=10):
        self.session = session or requests.Session()
        self.delay = delay
        self.timeout = timeout
        self.vulnerabilities = []



    def test_horizontal(self, endpoint, param_name, id_list, auth_cookies=None):

        logging.info(f"Starting horizontal testing on {endpoint} param {param_name} with {len(id_list)} ids")
        if not id_list:
            logging.info("No user IDs provided for horizontal testing; skipping.")
            return

        for obj_id in id_list:
            try:
                params = {param_name: str(obj_id)}
                resp = self.session.get(endpoint, params=params, cookies=auth_cookies, timeout=self.timeout)
                status = resp.status_code
                logging.info(f"Horizontal test {endpoint}?{param_name}={obj_id} -> {status}")
                # treat HTTP 200 with non-empty content as potential exposure
                if status == 200 and resp.text.strip():
                    self.vulnerabilities.append({
                        'type': 'horizontal_escalation',
                        'url': resp.url,
                        'param_tested': param_name,
                        'tested_value': obj_id,
                        'http_status': status,
                        'evidence_snippet': resp.text[:800]
                    })
                time.sleep(self.delay)
            except requests.RequestException as e:
                logging.error(f"Request failed during horizontal test for {obj_id}: {e}")


    def test_vertical(self, endpoint, auth_cookies=None):

        logging.info(f"Starting vertical testing on {endpoint}")
        try:
            resp = self.session.get(endpoint, cookies=auth_cookies, timeout=self.timeout, allow_redirects=True)
            status = resp.status_code
            logging.info(f"Vertical test {endpoint} -> {status}")
            # If we reach 200 or are redirected to an admin resource, flag it
            if status == 200 and resp.text.strip():
                self.vulnerabilities.append({
                    'type': 'vertical_escalation',
                    'url': resp.url,
                    'http_status': status,
                    'evidence_snippet': resp.text[:800]
                })
            time.sleep(self.delay)
        except requests.RequestException as e:
            logging.error(f"Request failed during vertical test for {endpoint}: {e}")


    def test_idor(self, metadata, auth_cookies=None):

        logging.info("Starting IDOR testing")
        for page in metadata:
            page_url = page.get('url')
            query_params = page.get('query_params', {}) or {}
            forms = page.get('forms', []) or []

            # URL param testing: try incrementing numeric params or replacing with common ids
            parsed = urlparse(page_url)
            base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

            for param, values in query_params.items():
                # values is typically a list
                values_to_try = []
                for v in values:
                    if isinstance(v, str) and v.isdigit():
                        # try increment and a few common guesses
                        values_to_try.extend([str(int(v) + 1), '1', '2', '100'])
                    else:
                        values_to_try.append('test_idor_value')

                for val in set(values_to_try):
                    try:
                        params = {k: (v[0] if isinstance(v, list) else v) for k, v in query_params.items()}
                        params[param] = val
                        test_url = f"{base_url}?{urlencode(params)}"
                        resp = self.session.get(test_url, cookies=auth_cookies, timeout=self.timeout)
                        status = resp.status_code
                        logging.info(f"IDOR URL param test {test_url} -> {status}")
                        if status == 200 and resp.text.strip():
                            self.vulnerabilities.append({
                                'type': 'idor_url_param',
                                'url': resp.url,
                                'param_tested': param,
                                'tested_value': val,
                                'http_status': status,
                                'evidence_snippet': resp.text[:800]
                            })
                        time.sleep(self.delay)
                    except requests.RequestException as e:
                        logging.error(f"IDOR URL param request failed for {test_url}: {e}")

            # Form testing: submit a simple value for each injectable form input
            for form in forms:
                action = form.get('action') or page_url
                method = (form.get('method') or 'GET').upper()
                inputs = form.get('inputs', []) or []

                # Compose simple payload: target numeric-looking inputs and others
                data = {}
                injectable_found = False
                for inp in inputs:
                    name = inp.get('name')
                    if not name:
                        continue
                    val = inp.get('value', '') or ''
                    typ = (inp.get('type') or 'text').lower()
                    # if value looks numeric, try common ids; else use marker
                    if isinstance(val, str) and val.isdigit():
                        data[name] = str(int(val) + 1)
                    else:
                        data[name] = 'test_idor_value'
                    injectable_found = True

                if not injectable_found:
                    continue

                try:
                    if method == 'POST':
                        resp = self.session.post(action, data=data, cookies=auth_cookies, timeout=self.timeout)
                    else:
                        resp = self.session.get(action, params=data, cookies=auth_cookies, timeout=self.timeout)
                    logging.info(f"IDOR form test {action} -> {resp.status_code}")
                    if resp.status_code == 200 and resp.text.strip():
                        self.vulnerabilities.append({
                            'type': 'idor_form',
                            'url': resp.url,
                            'form_action': action,
                            'tested_payload': data,
                            'http_status': resp.status_code,
                            'evidence_snippet': resp.text[:800]
                        })
                    time.sleep(self.delay)
                except requests.RequestException as e:
                    logging.error(f"IDOR form request failed for {action}: {e}")

    def generate_report(self, out_file='access_control_report.json', reports_dir=None, open_after=False):
        recommendations = [
            "Always validate object ownership server-side.",
            "Implement RBAC or ABAC and enforce on the server.",
            "Avoid using predictable sequential IDs; prefer UUIDs.",
            "Log and monitor access attempts for auditing."
        ]
        return save_report(self.vulnerabilities, recommendations, out_file, reports_dir, open_after)

