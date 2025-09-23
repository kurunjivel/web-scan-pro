# run_scan.py
import requests
from crawler import WebCrawler
from sqli_tester import SQLiTester
from xss_tester import XssTester
from auth_tester import AuthTester

def login(session, login_url, username, password):
    from bs4 import BeautifulSoup
    resp = session.get(login_url)
    soup = BeautifulSoup(resp.content,'html.parser')
    token = ''
    tinput = soup.find('input',{'name':'user_token'})
    if tinput: token = tinput.get('value','')
    data = {'username':username,'password':password,'Login':'Login','user_token':token}
    login_resp = session.post(login_url,data=data)
    return login_resp.status_code==200 and "Login failed" not in login_resp.text

def main():
    login_url = "http://localhost:8080/login.php"
    protected_url = "http://localhost:8080/dashboard.php"
    username = "admin"
    password = "password"

    session = requests.Session()
    if not login(session, login_url, username, password):
        print("Login failed! Exiting...")
        return

    # Crawl
    crawler = WebCrawler(login_url, session=session)
    crawler.crawl()
    crawler.save_results()

    # SQLi test
    sqli = SQLiTester(session=session)
    sqli.run_tests(crawler.results)
    sqli.generate_report()

    # XSS test
    xss = XssTester(session=session)
    xss.run_tests(crawler.results)
    xss.generate_report()

    # Auth test
    auth = AuthTester(session=session, login_url=login_url, protected_url=protected_url)
    auth.run_tests()
    auth.generate_report()

    print("Scanning completed. Reports generated.")

if __name__ == "__main__":
    main()
