import requests 
from bs4 import BeautifulSoup 
from urllib.parse import urljoin, urlparse 
import threading 
import os 
import random 
from datetime import datetime 
 
class WebCrawler: 
    def __init__(self, start_url, max_depth=2, domain_restriction=True): 
        self.start_url = start_url 
        self.max_depth = max_depth 
        self.visited = set() 
        self.domain_restriction = domain_restriction 
        self.base_domain = urlparse(start_url).netloc 
 
        # Create directories for logs, saving pages, and vulnerabilities 
        self.log_dir = 'logs' 
        self.pages_dir = 'crawled_pages' 
        self.vuln_dir = 'vulnerabilities' 
        os.makedirs(self.log_dir, exist_ok=True) 
        os.makedirs(self.pages_dir, exist_ok=True) 
        os.makedirs(self.vuln_dir, exist_ok=True) 
 
        # Determine the next log file name with a timestamp 
        self.log_file = self.get_next_log_file() 
 
        # User-Agent list for rotation 
        self.user_agents = [ 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3', 
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36', 
            'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko', 
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0' 
        ] 
 
        # Flag to control the running state 
        self.running = True 
 
    def get_next_log_file(self): 
        """Generate a unique log file name based on a timestamp.""" 
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") 
        return os.path.join(self.log_dir, f'crawl_log_{timestamp}.txt') 
 
    def check_vulnerabilities(self, url, soup, headers): 
        """Check for vulnerabilities and log detailed information.""" 
        vulnerabilities = [] 
 
        # Check for missing security headers 
        missing_headers = [] 
        required_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security'] 
        for header in required_headers: 
            if header not in headers: 
                missing_headers.append(header) 
 
        if missing_headers: 
            vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}") 
 
        # Extract software/version information from the headers 
        for header, value in headers.items(): 
            if header.lower() in ['server', 'x-powered-by']: 
                vulnerabilities.extend(self.query_vulnerability_databases(value)) 
 
        # Save vulnerabilities if any are found 
        if vulnerabilities: 
            vuln_filename = os.path.join(self.vuln_dir, f"vulnerabilities_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.txt") 
            with open(vuln_filename, 'w', encoding='utf-8') as vuln_file: 
                vuln_file.write(f"Vulnerabilities found on {url}:\n") 
                for vuln in vulnerabilities: 
                    vuln_file.write(f"- {vuln}\n") 
                print(f"Vulnerabilities logged for {url}") 
 
    def query_vulnerability_databases(self, software_info): 
        """Query multiple vulnerability databases for vulnerabilities related to the software information.""" 
        vulnerabilities = [] 
         
        # Query NVD API 
        vulnerabilities.extend(self.query_nvd_api(software_info)) 
         
        # Query CVE Details API 
        vulnerabilities.extend(self.query_cve_details_api(software_info)) 
         
        # Query VulnDB API 
        vulnerabilities.extend(self.query_vulndb_api(software_info)) 
         
        # Query SecurityFocus API 
        vulnerabilities.extend(self.query_securityfocus_api(software_info)) 
         
        # Query Exploit DB API 
        vulnerabilities.extend(self.query_exploit_db_api(software_info)) 
         
        return vulnerabilities 
 
    def query_nvd_api(self, software_info): 
        """Query the NVD API for
for vulnerabilities related to the software information.""" 
        nvd_search_url = "https://services.nvd.nist.gov/rest/json/v2/vulnerabilities" 
        params = { 
            "keyword": software_info, 
            "resultsPerPage": 5, 
            "startIndex": 0 
        } 
 
        try: 
            response = requests.get(nvd_search_url, params=params) 
            response.raise_for_status() 
 
            if response.text.strip() == "":  # Check for empty response 
                return [f"No data returned from NVD API for {software_info}"] 
 
            data = response.json() 
            vulnerabilities = [] 
            if 'result' in data and 'CVE_Items' in data['result']: 
                for item in data['result']['CVE_Items']: 
                    cve_id = item['cve']['CVE_data_meta']['ID'] 
                    description = item['cve']['description']['description_data'][0]['value'] 
                    cvss = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 'N/A') 
                    references = [ref['url'] for ref in item.get('cve', {}).get('references', {}).get('reference_data', [])] 
 
                    # Build the detailed log entry with the CVE link 
                    cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" 
                    vuln_entry = f"{cve_id}: {description}\n" 
                    vuln_entry += f"  CVSS Score: {cvss}\n" 
                    vuln_entry += f"  CVE Link: {cve_link}\n" 
                    if references: 
                        vuln_entry += "  References:\n" 
                        for ref in references: 
                            vuln_entry += f"    {ref}\n" 
                    vulnerabilities.append(vuln_entry) 
 
            return vulnerabilities 
 
        except requests.RequestException as e: 
            print(f"Error querying NVD API: {e}") 
            return [f"Error querying NVD API for {software_info}: {e}"] 
 
    def query_cve_details_api(self, software_info): 
        """Query the CVE Details API for vulnerabilities related to the software information.""" 
        cve_details_base_url = "https://www.cvedetails.com/json-feed.php" 
        params = { 
            "product": software_info 
        } 
 
        try: 
            response = requests.get(cve_details_base_url, params=params) 
            if response.status_code == 403: 
                print(f"403 Forbidden: Access denied for {cve_details_base_url}") 
                return [f"403 Forbidden when querying CVE Details API for {software_info}"] 
 
            response.raise_for_status() 
 
            if response.text.strip() == "":  # Check for empty response 
                return [f"No data returned from CVE Details API for {software_info}"] 
 
            data = response.json() 
            vulnerabilities = [] 
            if 'CVE_Items' in data: 
                for item in data['CVE_Items']: 
                    cve_id = item['cve']['CVE_data_meta']['ID'] 
                    description = item['cve']['description']['description_data'][0]['value'] 
                    cvss = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 'N/A') 
                    references = [ref['url'] for ref in item.get('cve', {}).get('references', {}).get('reference_data', [])] 
 
                    # Build the detailed log entry with the CVE link 
                    cve_link = f"https://www.cvedetails.com/cve/{cve_id}/" 
                    vuln_entry = f"{cve_id}: {description}\n" 
                    vuln_entry += f"  CVSS Score: {cvss}\n" 
                    vuln_entry += f"  CVE Link: {cve_link}\n" 
                    if references: 
                        vuln_entry += "  References:\n" 
                        for ref in references: 
                            vuln_entry += f"    {ref}\n" 
                    vulnerabilities.append(vuln_entry) 
 
            return vulnerabilities 
 
        except requests.RequestException as e: 
            print(f"Error querying CVE Details API: {e}") 
            return [f"Error querying CVE Details API for {software_info}: {e}"] 
 
    def query_vulndb_api(self, software_info): 
        """Query the VulnDB API for vulnerabilities related to the software information.""" 
        # VulnDB API endpoint and parameters (example, adjust based on VulnDB documentation) 
        vulndb_base_url = "https://vulndb.example.com/api/v1/search" 
        params = { 
            "query": software_info 
        } 
 
        try: 
            response = requests.get(vulndb_base_url, params=params) 
            response.raise_for_status() 
 
            if response.text.strip() == "":  # Check for empty response 
                return [f"No data returned from VulnDB API for {software_info}"] 
 
            data = response.json() 
            vulnerabilities = [] 
            if 'vulnerabilities' in data: 
                for item in data['vulnerabilities']: 
                    cve_id = item.get('id', 'N/A') 
                    description = item.get('description', 'No description available') 
                    cvss = item.get('cvss', 'N/A') 
                    references = item.get('references', []) 
 
                    # Build the detailed log entry with the CVE link 
                    cve_link = f"https://vulndb.example.com/vulnerabilities/{cve_id}" 
                    vuln_entry = f"{cve_id}: {description}\n" 
                    vuln_entry += f"  CVSS Score: {cvss}\n" 
                    vuln_entry += f"  CVE Link: {cve_link}\n" 
                    if references: 
                        vuln_entry += "  References:\n" 
                        for ref in references: 
                            vuln_entry += f"    {ref}\n" 
                    vulnerabilities.append(vuln_entry) 
 
            return vulnerabilities 
 
        except requests.RequestException as e: 
            print(f"Error querying VulnDB API: {e}") 
            return [f"Error querying VulnDB API for {software_info}: {e}"] 
 
    def query_securityfocus_api(self, software_info): 
        """Query the SecurityFocus API for vulnerabilities related to the software information.""" 
        # SecurityFocus API endpoint and parameters (example, adjust based on SecurityFocus documentation) 
        securityfocus_base_url = "https://www.securityfocus.com/vulnerabilities" 
        params = { 
            "search": software_info 
        } 
 
        try: 
            response = requests.get(securityfocus_base_url, params=params) 
            response.raise_for_status() 
 
            if response.text.strip() == "":  # Check for empty response 
                return [f"No data returned from SecurityFocus API for {software_info}"] 
 
            soup = BeautifulSoup(response.text, 'html.parser') 
            vulnerabilities = [] 
            # Parse the SecurityFocus response (example, adjust based on SecurityFocus response format) 
            for item in soup.find_all('div', class_='vuln-list-item'): 
                cve_id = item.find('a', class_='vuln-id').text.strip() 
                description = item.find('div', class_='vuln-description').text.strip() 
                cvss = item.find('span', class_='cvss-score').text.strip() 
                references = [a['href'] for a in item.find_all('a', class_='vuln-ref')] 
 
                # Build the detailed log entry with the CVE link 
                cve_link = f"https://www.securityfocus.com/bid/{cve_id}" 
                vuln_entry = f"{cve_id}: {description}\n" 
                vuln_entry += f"  CVSS Score: {cvss}\n" 
                vuln_entry += f"  CVE Link: {cve_link}\n" 
                if references: 
                    vuln_entry += "  References:\n" 
                    for ref in references: 
                        vuln_entry += f"    {ref}\n" 
                vulnerabilities.append(vuln_entry) 
 
            return vulnerabilities 
 
        except requests.RequestException as e: 
            print(f"Error querying SecurityFocus API: {e}") 
            return [f"Error querying SecurityFocus API for {software_info}: {e}"] 
 
    def query_exploit_db_api(self,

software_info): 
        """Query the Exploit Database API for vulnerabilities related to the software information.""" 
        # Exploit DB API endpoint and parameters (example, adjust based on Exploit DB documentation) 
        exploitdb_base_url = "https://www.exploit-db.com/api/v1/search" 
        params = { 
            "query": software_info 
        } 
 
        try: 
            response = requests.get(exploitdb_base_url, params=params) 
            response.raise_for_status() 
 
            if response.text.strip() == "":  # Check for empty response 
                return [f"No data returned from Exploit DB API for {software_info}"] 
 
            data = response.json() 
            vulnerabilities = [] 
            if 'exploits' in data: 
                for item in data['exploits']: 
                    cve_id = item.get('id', 'N/A') 
                    description = item.get('description', 'No description available') 
                    cvss = item.get('cvss', 'N/A') 
                    references = item.get('references', []) 
 
                    # Build the detailed log entry with the exploit link 
                    exploit_link = f"https://www.exploit-db.com/exploits/{cve_id}" 
                    vuln_entry = f"{cve_id}: {description}\n" 
                    vuln_entry += f"  CVSS Score: {cvss}\n" 
                    vuln_entry += f"  Exploit Link: {exploit_link}\n" 
                    if references: 
                        vuln_entry += "  References:\n" 
                        for ref in references: 
                            vuln_entry += f"    {ref}\n" 
                    vulnerabilities.append(vuln_entry) 
 
            return vulnerabilities 
 
        except requests.RequestException as e: 
            print(f"Error querying Exploit DB API: {e}") 
            return [f"Error querying Exploit DB API for {software_info}: {e}"] 
 
    def save_page(self, url, content): 
        """Save the page content to a file.""" 
        file_path = os.path.join(self.pages_dir, f"{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.html") 
        with open(file_path, 'w', encoding='utf-8') as file: 
            file.write(content) 
        print(f"Page saved to {file_path}") 
 
    def crawl(self, url, depth=0): 
        """Crawl the web pages.""" 
        if depth > self.max_depth or url in self.visited: 
            return 
 
        self.visited.add(url) 
 
        try: 
            headers = {'User-Agent': random.choice(self.user_agents)} 
            response = requests.get(url, headers=headers, timeout=10) 
            response.raise_for_status() 
            self.save_page(url, response.text) 
 
            soup = BeautifulSoup(response.text, 'html.parser') 
            self.check_vulnerabilities(url, soup, response.headers) 
 
            for link in soup.find_all('a', href=True): 
                next_url = urljoin(url, link['href']) 
                if not self.domain_restriction or urlparse(next_url).netloc == self.base_domain: 
                    threading.Thread(target=self.crawl, args=(next_url, depth + 1)).start() 
 
        except requests.RequestException as e: 
            with open(self.log_file, 'a', encoding='utf-8') as log_file: 
                log_file.write(f"Failed to retrieve {url}: {e}\n") 
            print(f"Error: {e}") 
 
if __name__ == "__main__":
    # Ask the user for a website to crawl
    start_url = input("Enter the URL of the website to crawl: ").strip()

    # Validate URL
    if not start_url.startswith(('http://', 'https://')):
        print("Invalid URL. Please make sure it starts with 'http://' or 'https://'.")
    else:
        crawler = WebCrawler(start_url)
        crawler.crawl(start_url)