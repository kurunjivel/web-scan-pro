import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import json
import logging
import time
from collections import deque

class WebCrawler:
    def __init__(self, start_url, session=None, output_file='crawler_output.json', delay=1):
        self.start_url = start_url
        self.domain = urlparse(start_url).netloc
        self.visited = set()
        self.queue = deque([start_url])
        self.results = []
        self.output_file = output_file
        self.delay = delay
        self.session = session or requests.Session()
        logging.basicConfig(filename='crawler.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def extract_metadata(self, soup, url):
        metadata = {
            'url': url,
            'title': soup.title.string if soup.title else '',
            'meta_description': '',
            'headings': [],
            'forms': [],
            'query_params': parse_qs(urlparse(url).query)
        }

        # Meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            metadata['meta_description'] = meta_desc.get('content', '')

        # Headings
        for tag in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            headings = soup.find_all(tag)
            metadata['headings'].extend([h.get_text(strip=True) for h in headings])

        # Forms
        forms = soup.find_all('form')
        for form in forms:
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_data = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'placeholder': inp.get('placeholder', ''),
                    'value': inp.get('value', ''),
                    'required': inp.has_attr('required')
                }
                form_data['inputs'].append(input_data)
            metadata['forms'].append(form_data)

        return metadata

    def crawl(self):
        while self.queue:
            current_url = self.queue.popleft()
            if current_url in self.visited:
                continue
            print(current_url)
            self.visited.add(current_url)

            try:
                logging.info(f"Crawling: {current_url}")
                response = self.session.get(current_url, timeout=10)
                response.raise_for_status()

                soup = BeautifulSoup(response.content, 'html.parser')
                page_data = self.extract_metadata(soup, current_url)
                page_data['crawl_date'] = time.strftime('%Y-%m-%d %H:%M:%S')
                self.results.append(page_data)

                # Find new links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = urljoin(current_url, link['href'])
                    if self.is_same_domain(href) and href not in self.visited:
                        self.queue.append(href)

                time.sleep(self.delay)

            except requests.RequestException as e:
                logging.error(f"Error crawling {current_url}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error on {current_url}: {e}")

    def save_results(self):
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        logging.info(f"Results saved to {self.output_file}")
