
import requests

from WebScanPro.Crawler import WebCrawler
from WebScanPro.SQLiTester import SQLiTester


def login(session, login_url, username, password, user_token):
    login_data = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': user_token
    }
    response = session.post(login_url, data=login_data)
    if response.ok:
        print("Logged in successfully!")
    else:
        print("Login failed!")
    return response.ok

if __name__ == "__main__":
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0'
    })

    # Login details
    login_url = "http://localhost:8080/login.php"
    username = "admin"
    password = "password"
    user_token = "9c3ce7f4749551b26a0e93cafd62c7d2"  # Get this from inspecting the form

    if not login(session, login_url, username, password, user_token):
        print("Cannot proceed without login.")
        exit()

    start_url = "http://localhost:8080/login.php"

    crawler = WebCrawler(start_url, session=session)
    crawler.crawl()
    crawler.save_results()

    tester = SQLiTester(session=session)
    tester.run_tests(crawler.results)
    tester.generate_report()

    print("Crawling and SQL Injection testing completed.")
