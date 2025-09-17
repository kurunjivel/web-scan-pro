import requests
from crawler import WebCrawler
from sqli_tester import SQLiTester
from xss_tester import XssTester

def login(session, login_url, username, password):

    response = session.get(login_url)
    if response.status_code != 200:
        print("Failed to fetch login page.")
        return False

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(response.content, 'html.parser')


    user_token = ''
    token_input = soup.find('input', {'name': 'user_token'})
    if token_input:
        user_token = token_input.get('value', '')

# Login process
    data = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': user_token
    }

    login_response = session.post(login_url, data=data)
    if "Login failed" in login_response.text or login_response.status_code != 200:
        print("Login failed!")
        return False

    print("Logged in successfully!")
    return True



def main():

# Keep session alive for the entire peocess

    session = requests.Session()
    login_url = "http://localhost:8080/login.php"
    username = "admin"
    password = "password"
    if not login(session, login_url, username, password):
        return

# Crawl the website
    start_url = "http://localhost:8080/login.php"
    crawler = WebCrawler(start_url, session=session)
    crawler.crawl()
    crawler.save_results()


# Run SQLInjection testing
    sqli_tester = SQLiTester(session=session)
    sqli_tester.run_tests(crawler.results)
    sqli_tester.generate_report()


#  XSS testing
    xss_tester = XssTester(session=session)
    xss_tester.run_tests(crawler.results)
    xss_tester.generate_report()

    print("Crawling and testing completed.")

if __name__ == "__main__":
    main()
