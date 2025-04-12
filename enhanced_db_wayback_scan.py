import asyncio
from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class EnhancedDBWaybackScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'HexaVulnScanner/1.0 (Security Research)'
        }
        self.wayback_base_url = 'http://web.archive.org/cdx/search/cdx'

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Check for database leaks
            db_leaks = self._check_database_leaks(target_url)
            vulnerabilities.extend(db_leaks)

            # Check historical content
            historical_vulns = self._check_wayback_machine(target_url)
            vulnerabilities.extend(historical_vulns)

        except Exception as e:
            print(f"DB/Wayback scan error: {str(e)}")
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Info',
                'description': f'DB/Wayback scan failed: {str(e)}'
            })

        return vulnerabilities

    def _check_database_leaks(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        sensitive_files = [
            # Database files
            '.sql', 'dump.sql', 'backup.sql', 'db.sql', 'database.sql',
            '.sqlite', '.sqlite3', 'db.sqlite', 'database.db',
            'mysql.sql', 'postgresql.sql', 'mongodb.archive',
            # Database connection files
            'db.config', 'database.yml', 'database.xml',
            'connection.config', 'db.properties',
            # Backup files
            'backup/', 'dump/', 'sql/', 'database/',
            '.bak', '.backup', '.dump',
            # Environment files that might contain DB credentials
            '.env', 'config.php', 'wp-config.php',
            'settings.py', 'config.js', 'config.json'
        ]

        base_url = target_url.rstrip('/')
        for file in sensitive_files:
            try:
                url = f"{base_url}/{file}"
                response = self.session.head(url, allow_redirects=False)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Database Leak',
                        'severity': 'Critical',
                        'description': f'Potential database or configuration file exposed: {file}',
                        'url': url
                    })
                    
                    # If it's a readable file, check its content
                    if any(file.endswith(ext) for ext in ['.env', '.config', '.json', '.xml', '.yml', '.properties']):
                        content_response = self.session.get(url)
                        if self._contains_sensitive_data(content_response.text):
                            vulnerabilities.append({
                                'type': 'Credential Leak',
                                'severity': 'Critical',
                                'description': f'Potential database credentials exposed in {file}',
                                'url': url
                            })
            except:
                continue

        return vulnerabilities

    def _check_wayback_machine(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Query the Wayback Machine CDX API
            domain = urlparse(target_url).netloc
            params = {
                'url': domain,
                'output': 'json',
                'collapse': 'timestamp',
                'filter': '!statuscode:[45]..'
            }
            response = requests.get(self.wayback_base_url, params=params)
            snapshots = response.json()

            if len(snapshots) > 1:  # First row is header
                # Check the most recent 10 snapshots
                for snapshot in snapshots[1:11]:
                    timestamp = snapshot[1]
                    archived_url = f'http://web.archive.org/web/{timestamp}/{snapshot[2]}'
                    
                    try:
                        # Check archived version for sensitive information
                        archived_response = self.session.get(archived_url)
                        if archived_response.status_code == 200:
                            # Check for sensitive data in archived content
                            if self._contains_sensitive_data(archived_response.text):
                                vulnerabilities.append({
                                    'type': 'Historical Exposure',
                                    'severity': 'High',
                                    'description': f'Sensitive information found in archived version from {timestamp}',
                                    'archived_url': archived_url
                                })
                    except:
                        continue

        except Exception as e:
            print(f"Wayback Machine check error: {str(e)}")

        return vulnerabilities

    def _contains_sensitive_data(self, content: str) -> bool:
        sensitive_patterns = [
            # Database connection strings
            r'(?i)(mongodb|mysql|postgresql|redis)://[^\s<>"]+',
            r'(?i)database_url["\s]*=["\s]*[^\s<>"]+',
            r'(?i)connection_string["\s]*=["\s]*[^\s<>"]+',
            # Credentials
            r'(?i)(password|passwd|pwd|secret|key)["\s]*=["\s]*[^\s<>"]+',
            r'(?i)username["\s]*=["\s]*[^\s<>"]+',
            # API keys and tokens
            r'(?i)(api[_-]?key|token|secret)["\s]*=["\s]*[^\s<>"]+',
            # IP addresses
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            # Common database ports
            r'(?i)port["\s]*=["\s]*([3306|5432|27017|6379]+)'
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, content):
                return True
        return False