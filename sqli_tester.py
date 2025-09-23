# sqli_tester.py
import requests, re, json, time, logging, difflib
from urllib.parse import urlparse, urlunparse, urlencode

class SQLiTester:
    SQLI_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='2", "' OR 1=1--", "' OR 1=2--",
        "' OR SLEEP(5)--", "\" OR \"1\"=\"1", "\" OR \"1\"=\"2"
    ]
    SQL_ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"syntax error", re.I),
        re.compile(r"sqlstate", re.I)
    ]
    INJECTABLE_TYPES = {'text','search','email','url','tel','password','textarea'}

    def __init__(self, session=None, delay=1, timeout=10, similarity_threshold=0.90):
        self.session = session or requests.Session()
        self.delay = delay
        self.timeout = timeout
        self.similarity_threshold = similarity_threshold
        self.vulnerabilities = []
        logging.basicConfig(filename='sqlitester.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_tests(self, metadata):
        for page in metadata:
            url = page.get('url')
            forms = page.get('forms', [])
            query_params = page.get('query_params', {})

            for form in forms:
                self.test_form(url, form)
            if query_params:
                self.test_url_params(url, query_params)

    def test_form(self, page_url, form):
        action = form.get('action') or page_url
        method = form.get('method','GET').upper()
        inputs = form.get('inputs', [])
        baseline_data = {}
        injectable = []

        for inp in inputs:
            name = inp.get('name')
            if not name: continue
            baseline_data[name] = inp.get('value','')
            if inp.get('type','text').lower() in self.INJECTABLE_TYPES:
                injectable.append(name)

        if not injectable: return
        baseline_resp = self._send_request(action, method, baseline_data)
        baseline_text = baseline_resp.text if baseline_resp else ''

        for payload in self.SQLI_PAYLOADS:
            data = baseline_data.copy()
            for name in injectable:
                data[name] = payload
            try:
                start = time.time()
                resp = self._send_request(action, method, data)
                elapsed = time.time() - start
                self.analyze_response(page_url,'form',action,data,resp,payload,baseline_text,elapsed)
                time.sleep(self.delay)
            except Exception as e:
                logging.error(f"Form testing error at {action}: {e}")

    def test_url_params(self, url, query_params):
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,'','',''))
        baseline_params = {k:v[0] if isinstance(v,(list,tuple)) else v for k,v in query_params.items()}
        baseline_resp = self.session.get(base_url, params=baseline_params, timeout=self.timeout)
        baseline_text = baseline_resp.text if baseline_resp else ''

        for param in query_params.keys():
            for payload in self.SQLI_PAYLOADS:
                params = baseline_params.copy()
                params[param] = payload
                try:
                    resp = self.session.get(base_url, params=params, timeout=self.timeout)
                    self.analyze_response(url,'url_param',param,params,resp,payload,baseline_text)
                    time.sleep(self.delay)
                except Exception as e:
                    logging.error(f"URL param testing error at {url}: {e}")

    def analyze_response(self, url,test_type,target,data,response,payload,baseline_text,elapsed=None):
        if not response: return
        content = response.text.lower()

        # Error-based detection
        for pattern in self.SQL_ERROR_PATTERNS:
            if pattern.search(content):
                self.record_vulnerability(url,test_type,target,data,response,'error_pattern')
                return

        # Boolean/behavioral detection
        ratio = difflib.SequenceMatcher(None, baseline_text.lower(), content).ratio()
        if ratio < self.similarity_threshold:
            self.record_vulnerability(url,test_type,target,data,response,'behavioral_difference')

    def _send_request(self, action, method, data):
        try:
            if method.upper()=='POST':
                return self.session.post(action,data=data,timeout=self.timeout)
            else:
                return self.session.get(action,params=data,timeout=self.timeout)
        except:
            return None

    def record_vulnerability(self,url,test_type,target,data,response,reason):
        vuln = {
            'url': url, 'test_type': test_type, 'target': target,
            'payload': data, 'http_status': response.status_code if response else None,
            'detection_method': reason,
            'response_snippet': (response.text[:500] if response else '')
        }
        self.vulnerabilities.append(vuln)

    def generate_report(self, out_file='sqli_report.json'):
        report = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [
                "Use parameterized queries or prepared statements.",
                "Sanitize all inputs properly.",
                "Use stored procedures where applicable.",
                "Proper error handling to avoid exposing DB info."
            ]
        }
        with open(out_file,'w') as f:
            json.dump(report,f,indent=4)
