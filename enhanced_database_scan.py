import asyncio
from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json

class EnhancedDatabaseScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'HexaVulnScanner/1.0 (Security Research)'
        }
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "1' WAITFOR DELAY '0:0:5'--",
            "admin' --",
            "admin' #",
            "' HAVING 1=1--",
            "') OR ('1'='1",
            "); DROP TABLE users--"
        ]
        self.db_config_patterns = {
            'mysql': r'mysql:\/\/[^\s]+',
            'postgresql': r'postgres:\/\/[^\s]+',
            'mongodb': r'mongodb:\/\/[^\s]+',
            'redis': r'redis:\/\/[^\s]+',
            'oracle': r'oracle:\/\/[^\s]+'
        }

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Check for SQL injection vulnerabilities
            sql_vulns = self._check_sql_injection(target_url)
            vulnerabilities.extend(sql_vulns)

            # Check for exposed database ports
            port_vulns = self._check_database_ports(target_url)
            vulnerabilities.extend(port_vulns)

            # Check for database configuration issues
            config_vulns = self._check_database_configs(target_url)
            vulnerabilities.extend(config_vulns)

            # Check for NoSQL injection vulnerabilities
            nosql_vulns = self._check_nosql_injection(target_url)
            vulnerabilities.extend(nosql_vulns)

        except Exception as e:
            print(f"Database scan error: {str(e)}")
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Info',
                'description': f'Database scan failed: {str(e)}'
            })

        return vulnerabilities

    def _check_sql_injection(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query)
        
        # Test each parameter for SQL injection
        for param in params:
            for payload in self.sql_injection_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = target_url.split('?')[0] + '?' + '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                
                try:
                    response = self.session.get(test_url)
                    if self._detect_sql_error(response.text):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'description': f'Potential SQL injection vulnerability in parameter: {param}',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload
                        })
                except:
                    continue

        return vulnerabilities

    def _check_database_ports(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        domain = urlparse(target_url).netloc
        common_db_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            1521: 'Oracle',
            1433: 'MS SQL Server'
        }

        for port, db_type in common_db_ports.items():
            try:
                response = self.session.get(f'http://{domain}:{port}', timeout=2)
                vulnerabilities.append({
                    'type': 'Exposed Database Port',
                    'severity': 'Critical',
                    'description': f'Exposed {db_type} database port: {port}',
                    'port': port,
                    'database_type': db_type
                })
            except:
                continue

        return vulnerabilities

    def _check_database_configs(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        config_files = [
            'config.php', 'wp-config.php', 'configuration.php',
            'config.js', 'config.json', 'settings.py',
            'database.yml', 'application.properties'
        ]

        for config_file in config_files:
            try:
                url = urljoin(target_url, config_file)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    # Check for database connection strings
                    for db_type, pattern in self.db_config_patterns.items():
                        matches = re.findall(pattern, response.text)
                        if matches:
                            vulnerabilities.append({
                                'type': 'Exposed Database Configuration',
                                'severity': 'Critical',
                                'description': f'Exposed {db_type} database configuration in {config_file}',
                                'url': url,
                                'database_type': db_type
                            })
            except:
                continue

        return vulnerabilities

    def _check_nosql_injection(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$exists": true}',
            '{"$regex": ".*"}'
        ]

        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query)

        for param in params:
            for payload in nosql_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = target_url.split('?')[0] + '?' + '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])

                try:
                    response = self.session.get(test_url)
                    if self._detect_nosql_error(response.text):
                        vulnerabilities.append({
                            'type': 'NoSQL Injection',
                            'severity': 'Critical',
                            'description': f'Potential NoSQL injection vulnerability in parameter: {param}',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload
                        })
                except:
                    continue

        return vulnerabilities

    def _detect_sql_error(self, response_text: str) -> bool:
        error_patterns = [
            'sql syntax',
            'mysql error',
            'postgresql error',
            'ora-\\d{5}',
            'sql server error',
            'unclosed quotation mark',
            'unterminated string literal'
        ]
        return any(re.search(pattern, response_text.lower()) for pattern in error_patterns)

    def _detect_nosql_error(self, response_text: str) -> bool:
        error_patterns = [
            'mongodb error',
            'cannot use $',
            'illegal operator',
            'malformed query',
            'invalid json'
        ]
        return any(re.search(pattern, response_text.lower()) for pattern in error_patterns)