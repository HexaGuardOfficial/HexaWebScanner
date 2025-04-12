import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin, urlparse
import concurrent.futures
import time
from typing import List, Dict, Any
import os
from dotenv import load_dotenv
import asyncio
from concurrent.futures import ThreadPoolExecutor
import socket
import whois
import dns.resolver
from datetime import datetime

class EnhancedStaticScanner:
    def __init__(self):
        self.hf_api_key = "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"
        self.hf_api_url = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn"
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        self.max_threads = 20
        self.vulnerabilities = []

    async def scan_website(self, target_url: str) -> Dict[str, Any]:
        """Main scanning function that orchestrates all checks"""
        try:
            # Basic URL validation
            if not self._validate_url(target_url):
                return {"error": "Invalid URL provided"}

            # Get website content
            response = self._get_website_content(target_url)
            if not response:
                return {"error": "Could not fetch website content"}

            # Run all security checks in parallel
            tasks = [
                self._check_security_headers(response),
                self._check_forms(response.text),
                self._check_links(response.text),
                self._check_scripts(response.text),
                self._check_meta_tags(response.text),
                self._analyze_with_huggingface(response.text),
                self._check_sql_injection(target_url),
                self._check_xss_vulnerabilities(target_url),
                self._check_sensitive_files(target_url),
                self._check_ssl_tls(target_url),
                self._check_dns_security(target_url),
                self._check_subdomain_security(target_url)
            ]

            # Execute all checks in parallel
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                results = list(executor.map(lambda f: f, tasks))

            # Combine all vulnerabilities
            for result in results:
                if isinstance(result, list):
                    self.vulnerabilities.extend(result)

            # Get AI-enhanced analysis
            ai_analysis = await self._get_ai_analysis(target_url)
            if ai_analysis:
                self.vulnerabilities.extend(ai_analysis)

            return {
                "target_url": target_url,
                "vulnerabilities": self.vulnerabilities,
                "scan_time": datetime.now().isoformat(),
                "total_vulnerabilities": len(self.vulnerabilities)
            }

        except Exception as e:
            return {"error": f"Scanning failed: {str(e)}"}

    def _validate_url(self, url: str) -> bool:
        """Validate the target URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def _get_website_content(self, url: str) -> requests.Response:
        """Fetch website content with proper headers"""
        try:
            return self.session.get(url, timeout=10)
        except:
            return None

    async def _check_security_headers(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Check for security-related headers"""
        vulnerabilities = []
        security_headers = {
            "X-Frame-Options": "Prevents clickjacking",
            "X-XSS-Protection": "XSS protection",
            "X-Content-Type-Options": "Prevents MIME type sniffing",
            "Content-Security-Policy": "Content Security Policy",
            "Strict-Transport-Security": "Enforces HTTPS",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser features"
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    "type": "Missing Security Header",
                    "severity": "Medium",
                    "description": f"Missing {header} header: {description}",
                    "recommendation": f"Add {header} header to improve security"
                })

        return vulnerabilities

    async def _check_forms(self, content: str) -> List[Dict[str, Any]]:
        """Analyze forms for potential vulnerabilities"""
        vulnerabilities = []
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            # Check for CSRF protection
            if not form.find('input', {'name': 'csrf_token'}) and not form.find('input', {'name': '_csrf'}):
                vulnerabilities.append({
                    "type": "CSRF Vulnerability",
                    "severity": "High",
                    "description": "Form missing CSRF protection",
                    "recommendation": "Implement CSRF tokens in all forms"
                })

            # Check for password fields without proper attributes
            password_fields = form.find_all('input', {'type': 'password'})
            for field in password_fields:
                if not field.get('autocomplete', '').lower() == 'off':
                    vulnerabilities.append({
                        "type": "Password Field Vulnerability",
                        "severity": "Medium",
                        "description": "Password field missing proper security attributes",
                        "recommendation": "Add autocomplete='off' to password fields"
                    })

        return vulnerabilities

    async def _check_links(self, content: str) -> List[Dict[str, Any]]:
        """Check for potentially dangerous links"""
        vulnerabilities = []
        soup = BeautifulSoup(content, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href', '')
            if href.startswith('javascript:'):
                vulnerabilities.append({
                    "type": "JavaScript Link",
                    "severity": "Medium",
                    "description": "Potentially dangerous JavaScript link found",
                    "recommendation": "Avoid using javascript: links"
                })

        return vulnerabilities

    async def _check_scripts(self, content: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript code for vulnerabilities"""
        vulnerabilities = []
        soup = BeautifulSoup(content, 'html.parser')
        scripts = soup.find_all('script')

        for script in scripts:
            script_content = script.string or ''
            # Check for eval() usage
            if 'eval(' in script_content:
                vulnerabilities.append({
                    "type": "JavaScript Vulnerability",
                    "severity": "High",
                    "description": "Use of eval() detected",
                    "recommendation": "Avoid using eval() as it can lead to code injection"
                })

        return vulnerabilities

    async def _check_meta_tags(self, content: str) -> List[Dict[str, Any]]:
        """Check meta tags for security configurations"""
        vulnerabilities = []
        soup = BeautifulSoup(content, 'html.parser')
        meta_tags = soup.find_all('meta')

        for meta in meta_tags:
            if meta.get('http-equiv', '').lower() == 'refresh':
                vulnerabilities.append({
                    "type": "Meta Refresh",
                    "severity": "Low",
                    "description": "Meta refresh tag found",
                    "recommendation": "Avoid using meta refresh tags"
                })

        return vulnerabilities

    async def _analyze_with_huggingface(self, content: str) -> List[Dict[str, Any]]:
        """Use Hugging Face API for advanced vulnerability analysis"""
        vulnerabilities = []
        try:
            headers = {"Authorization": f"Bearer {self.hf_api_key}"}
            payload = {
                "inputs": content[:1000],  # Limit content length
                "parameters": {
                    "max_length": 150,
                    "min_length": 30
                }
            }
            
            response = requests.post(self.hf_api_url, headers=headers, json=payload)
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    analysis = result[0].get('summary_text', '')
                    if 'vulnerability' in analysis.lower() or 'security' in analysis.lower():
                        vulnerabilities.append({
                            "type": "AI-Detected Vulnerability",
                            "severity": "High",
                            "description": f"AI analysis detected potential security issues: {analysis}",
                            "recommendation": "Review the website content for potential security vulnerabilities"
                        })
        except Exception as e:
            print(f"Error in Hugging Face analysis: {str(e)}")

        return vulnerabilities

    async def _check_sql_injection(self, url: str) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities"""
        vulnerabilities = []
        sql_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin' --",
            "1' ORDER BY 1--"
        ]

        try:
            for payload in sql_payloads:
                response = self.session.get(f"{url}?param={payload}")
                if self._detect_sql_error(response.text):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "description": "Potential SQL injection vulnerability detected",
                        "recommendation": "Implement proper input validation and parameterized queries"
                    })
        except:
            pass

        return vulnerabilities

    async def _check_xss_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ]

        try:
            for payload in xss_payloads:
                response = self.session.get(f"{url}?param={payload}")
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "XSS Vulnerability",
                        "severity": "High",
                        "description": "Potential XSS vulnerability detected",
                        "recommendation": "Implement proper input sanitization and output encoding"
                    })
        except:
            pass

        return vulnerabilities

    async def _check_sensitive_files(self, url: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files"""
        vulnerabilities = []
        sensitive_files = [
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/.git/config',
            '/.htaccess',
            '/robots.txt'
        ]

        for file in sensitive_files:
            try:
                response = self.session.get(urljoin(url, file))
                if response.status_code == 200:
                    vulnerabilities.append({
                        "type": "Sensitive File Exposure",
                        "severity": "High",
                        "description": f"Sensitive file exposed: {file}",
                        "recommendation": "Remove or restrict access to sensitive files"
                    })
            except:
                continue

        return vulnerabilities

    async def _check_ssl_tls(self, url: str) -> List[Dict[str, Any]]:
        """Check SSL/TLS configuration"""
        vulnerabilities = []
        try:
            if not url.startswith('https://'):
                vulnerabilities.append({
                    "type": "SSL/TLS",
                    "severity": "High",
                    "description": "Website not using HTTPS",
                    "recommendation": "Implement HTTPS with proper SSL/TLS configuration"
                })
        except:
            pass

        return vulnerabilities

    async def _check_dns_security(self, url: str) -> List[Dict[str, Any]]:
        """Check DNS security"""
        vulnerabilities = []
        try:
            domain = urlparse(url).netloc
            whois_info = whois.whois(domain)
            
            # Check for DNS security features
            try:
                dns.resolver.resolve(domain, 'TXT')
            except:
                vulnerabilities.append({
                    "type": "DNS Security",
                    "severity": "Medium",
                    "description": "Missing DNS security features (DNSSEC, SPF, DMARC)",
                    "recommendation": "Implement DNS security features"
                })
        except:
            pass

        return vulnerabilities

    async def _check_subdomain_security(self, url: str) -> List[Dict[str, Any]]:
        """Check subdomain security"""
        vulnerabilities = []
        try:
            domain = urlparse(url).netloc
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'dev', 'test']
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    socket.gethostbyname(full_domain)
                    vulnerabilities.append({
                        "type": "Subdomain Security",
                        "severity": "Medium",
                        "description": f"Common subdomain found: {full_domain}",
                        "recommendation": "Review and secure all subdomains"
                    })
                except:
                    continue
        except:
            pass

        return vulnerabilities

    async def _get_ai_analysis(self, url: str) -> List[Dict[str, Any]]:
        """Get AI-enhanced analysis using Hugging Face API"""
        vulnerabilities = []
        try:
            headers = {"Authorization": f"Bearer {self.hf_api_key}"}
            payload = {
                "inputs": f"Analyze security vulnerabilities for website: {url}",
                "parameters": {
                    "max_length": 200,
                    "min_length": 50
                }
            }
            
            response = requests.post(self.hf_api_url, headers=headers, json=payload)
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    analysis = result[0].get('summary_text', '')
                    if 'vulnerability' in analysis.lower() or 'security' in analysis.lower():
                        vulnerabilities.append({
                            "type": "AI-Enhanced Analysis",
                            "severity": "High",
                            "description": f"AI-enhanced analysis detected: {analysis}",
                            "recommendation": "Review AI findings and implement recommended security measures"
                        })
        except Exception as e:
            print(f"Error in AI analysis: {str(e)}")

        return vulnerabilities

async def main():
    # Example usage
    target_url = input("Enter the website URL to scan: ")
    scanner = EnhancedStaticScanner()
    results = await scanner.scan_website(target_url)
    
    # Print results
    print("\nScan Results:")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main()) 