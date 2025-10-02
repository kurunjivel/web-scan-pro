import os
import requests
import json
from datetime import datetime
from crawler import WebCrawler
from sqli_tester import SQLiTester
from xss_tester import XssTester
from auth_tester import AuthTester
from access_control_tester import AccessControlTester
from utils import extract_user_ids, generate_full_scan_report

# Reports directory
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def login(session, login_url, username, password):
    from bs4 import BeautifulSoup
    try:
        resp = session.get(login_url, timeout=10)
        soup = BeautifulSoup(resp.content, 'html.parser')
        token = ''
        tinput = soup.find('input', {'name': 'user_token'})
        if tinput:
            token = tinput.get('value', '')
        data = {'username': username, 'password': password, 'Login': 'Login', 'user_token': token}
        login_resp = session.post(login_url, data=data, timeout=10)
        return login_resp.status_code == 200 and "Login failed" not in login_resp.text
    except Exception as e:
        print(f"[!] Login error: {e}")
        return False

def save_crawler_output(crawler, out_path):
    try:
        with open(out_path, 'w') as f:
            json.dump(crawler.results, f, indent=4)
        print(f"[Crawler] Saved metadata to {out_path}")
    except Exception as e:
        print(f"[Crawler] Failed to save metadata: {e}")

def main():
    login_url = "http://localhost:8080/login.php"
    protected_url = "http://localhost:8080/dashboard.php"
    username = "admin"
    password = "password"

    session = requests.Session()

    if not login(session, login_url, username, password):
        print("Login failed! Exiting...")
        return

    # timestamp for this run
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ------------------ Crawler ------------------
    crawler = WebCrawler(login_url, session=session)
    try:
        crawler.crawl()
        crawler_output_file = os.path.join(REPORT_DIR, f"crawler_output_{ts}.json")
        save_crawler_output(crawler, crawler_output_file)
        metadata = crawler.results
        print("[Crawler] Completed")
    except Exception as e:
        print(f"[Crawler] Error: {e}")
        metadata = []

    # ------------------ SQLi ------------------
    try:
        sqli = SQLiTester(session=session)
        sqli.run_tests(metadata)
        sqli.generate_report(out_file=f"sqli_report_{ts}.json", reports_dir=REPORT_DIR, open_after=False)
        print("[SQLi] Completed")
    except Exception as e:
        print(f"[SQLi] Error: {e}")

    # ------------------ XSS ------------------
    try:
        xss = XssTester(session=session)
        xss.run_tests(metadata)
        xss.generate_report(out_file=f"xss_report_{ts}.json", reports_dir=REPORT_DIR, open_after=False)
        print("[XSS] Completed")
    except Exception as e:
        print(f"[XSS] Error: {e}")

    # ------------------ Auth ------------------
    try:
        auth = AuthTester(session=session, login_url=login_url, protected_url=protected_url)
        auth.run_tests()
        auth.generate_report(out_file=f"auth_report_{ts}.json", reports_dir=REPORT_DIR, open_after=False)
        print("[Auth] Completed")
    except Exception as e:
        print(f"[Auth] Error: {e}")

    # ------------------ Access Control ------------------
    try:
        user_cookies = session.cookies.get_dict()
        ac = AccessControlTester(session=session)

        user_ids = extract_user_ids(metadata) if metadata else []
        print(f"[AC] Discovered user IDs: {user_ids}")

        if user_ids:
            ac.test_horizontal("http://localhost:8080/user/profile.php", "id", user_ids, auth_cookies=user_cookies)
        else:
            print("[AC] No user IDs discovered; skipping horizontal tests.")

        admin_endpoints = [
            "http://localhost:8080/admin/panel.php",
            "http://localhost:8080/admin/delete_user.php?id=1"
        ]
        for ep in admin_endpoints:
            ac.test_vertical(ep, auth_cookies=user_cookies)

        ac.test_idor(metadata, auth_cookies=user_cookies)

        ac.generate_report(out_file=f"access_control_report_{ts}.json", reports_dir=REPORT_DIR, open_after=False)
        print("[AC] Completed")
    except Exception as e:
        print(f"[AC] Error: {e}")

    # ------------------ Full Scan Report ------------------
    try:
        full_report = generate_full_scan_report(reports_dir=REPORT_DIR, out_file=f"full_scan_{ts}.html")
        print(f"[+] Full scan report generated: {full_report}")
    except Exception as e:
        print(f"[!] Failed to generate full scan report: {e}")

    print("Full scan completed. Reports are in the 'reports/' directory.")

if __name__ == "__main__":
    main()
