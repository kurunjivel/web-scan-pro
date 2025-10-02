import requests, json, logging
from utils import save_report

class AuthTester:
    def __init__(self, session, login_url, protected_url, username='admin', password='password'):
        self.session = session
        self.login_url = login_url
        self.protected_url = protected_url
        self.username = username
        self.password = password
        self.vulnerabilities = []
        logging.basicConfig(filename='auth_tester.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.recommendations =[
            "Enforce authentication on all protected endpoints.",
            "Prevent invalid login bypasses.",
            "Use secure session cookies.",
            "Check for proper session handling and timeouts."
        ]

    def run_tests(self):
        # Test protected URL without login
        session2 = requests.Session()
        resp = session2.get(self.protected_url, allow_redirects=True)
        if "login" not in resp.url.lower():
            self.vulnerabilities.append({
                'test': 'unauthenticated_access',
                'url': self.protected_url,
                'issue': 'Protected resource accessible without login'
            })

        # Test invalid login
        resp = session2.post(self.login_url, data={'username':'wrong','password':'wrong'}, allow_redirects=True)
        # if the app redirects away from login page after failed login, it's suspicious
        if resp.url.lower() != self.login_url.lower():
            self.vulnerabilities.append({
                'test':'invalid_login_bypass',
                'url': self.login_url,
                'issue':'Invalid login allowed access or redirect bypass'
            })

        # Check session fixation / cookie issues
        cookies = session2.cookies.get_dict()
        if cookies:
            self.vulnerabilities.append({
                'test':'session_cookie_check',
                'url': self.login_url,
                'issue':'Session cookie set without login'
            })

    def generate_report(self, out_file='auth_report.json', reports_dir=None, open_after=False):
        return save_report(self.vulnerabilities, self.recommendations, out_file, reports_dir, open_after)
