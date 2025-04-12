import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from .db_manager import DatabaseManager

class OWASPScanner:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'HexaVulnScanner/1.0 (Security Research)'
        }

    def scan(self, target_url):
        vulnerabilities = []
        
        try:
            # Basic security headers check
            headers = self._check_security_headers(target_url)
            vulnerabilities.extend(self._analyze_security_headers(headers))

            # Check for SSL/TLS vulnerabilities
            ssl_vulns = self._check_ssl_tls(target_url)
            vulnerabilities.extend(ssl_vulns)

            # Crawl for injection points
            urls = self._crawl_site(target_url)
            with ThreadPoolExecutor(max_workers=5) as executor:
                injection_results = list(executor.map(self._check_injection_points, urls))
                for result in injection_results:
                    vulnerabilities.extend(result)

            # Check for misconfigurations
            misconfig_vulns = self._check_misconfigurations(target_url)
            vulnerabilities.extend(misconfig_vulns)

            # Save results to database
            self.db_manager.save_owasp_results(target_url, vulnerabilities)

        except Exception as e:
            print(f"Error during OWASP scan: {str(e)}")
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Critical',
                'description': f'Scan failed: {str(e)}'
            })

        return vulnerabilities

    def _check_security_headers(self, target_url):
        try:
            response = self.session.get(target_url)
            return self._analyze_security_headers(response.headers)
        except Exception as e:
            print(f"Error checking security headers: {str(e)}")
            return []

    def _analyze_security_headers(self, headers):
        vulnerabilities = []
        critical_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header - Clickjacking possible',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header - MIME-sniffing possible',
            'Strict-Transport-Security': 'Missing HSTS header - SSL/TLS downgrade possible',
            'Content-Security-Policy': 'Missing CSP header - XSS and injection risks',
            'X-XSS-Protection': 'Missing X-XSS-Protection header - XSS protection not enforced'
        }

        for header, message in critical_headers.items():
            if not headers.get(header):
                vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'Medium',
                    'description': message
                })

        return vulnerabilities

    def _check_ssl_tls(self, target_url):
        vulnerabilities = []
        try:
            response = self.session.get(target_url, verify=True)
            if not response.url.startswith('https'):
                vulnerabilities.append({
                    'type': 'SSL/TLS',
                    'severity': 'High',
                    'description': 'Site not using HTTPS - Data transmission not secure'
                })
        except requests.exceptions.SSLError:
            vulnerabilities.append({
                'type': 'SSL/TLS',
                'severity': 'Critical',
                'description': 'Invalid SSL certificate or SSL/TLS configuration issues'
            })
        return vulnerabilities

    def _crawl_site(self, target_url, max_pages=10):
        visited = set()
        to_visit = {target_url}
        base_domain = urlparse(target_url).netloc

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop()
            if url in visited:
                continue

            try:
                response = self.session.get(url)
                visited.add(url)

                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href:
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == base_domain:
                            to_visit.add(full_url)
            except:
                continue

        return list(visited)

    def _check_injection_points(self, url):
        vulnerabilities = []
        payloads = {
            'sql': ["' OR '1'='1", "1; DROP TABLE users--"],
            'xss': ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"],
            'cmd': ["; ls -la", "& dir"]
        }

        for injection_type, tests in payloads.items():
            for payload in tests:
                try:
                    response = self.session.get(f"{url}?param={payload}")
                    if self._detect_vulnerability(injection_type, response):
                        vulnerabilities.append({
                            'type': f'{injection_type.upper()} Injection',
                            'severity': 'High',
                            'description': f'Potential {injection_type.upper()} injection at {url}'
                        })
                except:
                    continue

        return vulnerabilities

    def _detect_vulnerability(self, injection_type, response):
        indicators = {
            'sql': ['sql', 'mysql', 'sqlite', 'postgresql', 'error in your sql'],
            'xss': ['<script>', 'alert(', 'onerror='],
            'cmd': ['directory of', 'volume in drive', 'root:x:']
        }
        
        return any(indicator.lower() in response.text.lower() 
                  for indicator in indicators.get(injection_type, []))

    def _check_misconfigurations(self, target_url):
        vulnerabilities = []
        sensitive_files = [
            '/robots.txt',
            '/.git/config',
            '/.env',
            '/wp-config.php',
            '/phpinfo.php',
            '/admin',
            '/config'
        ]

        for file in sensitive_files:
            try:
                response = self.session.get(urljoin(target_url, file))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Misconfiguration',
                        'severity': 'High',
                        'description': f'Sensitive file/directory exposed: {file}'
                    })
            except:
                continue

        return vulnerabilities 