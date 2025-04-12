import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from .enhanced_owasp_scan import EnhancedOWASPScanner
from .enhanced_cve_scan import EnhancedCVEScanner
from .enhanced_zeroday_ai import EnhancedZeroDayAI
from .enhanced_db_wayback_scan import EnhancedDBWaybackScanner
from .enhanced_database_scan import EnhancedDatabaseScanner
from .db_manager import DatabaseManager
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import socket
import whois
import dns.resolver
from datetime import datetime

class ParallelVulnerabilityScanner:
    def __init__(self):
        self.owasp_scanner = EnhancedOWASPScanner()
        self.cve_scanner = EnhancedCVEScanner()
        self.zeroday_scanner = EnhancedZeroDayAI()
        self.db_wayback_scanner = EnhancedDBWaybackScanner()
        self.database_scanner = EnhancedDatabaseScanner()
        self.db_manager = DatabaseManager()
        self.max_threads = 20

    async def scan(self, target_url: str) -> Dict[str, Any]:
        try:
            # Stage 1: Footprinting
            footprint_data = await self._footprinting(target_url)
            
            # Stage 2: Scanning
            scan_data = await self._scanning(target_url)
            
            # Stage 3: Enumeration
            enum_data = await self._enumeration(target_url)
            
            # Stage 4-6: Parallel Vulnerability Assessment
            vulnerabilities = await self._parallel_vulnerability_assessment(target_url)
            
            # Combine all results
            result = {
                'timestamp': datetime.now().isoformat(),
                'target_url': target_url,
                'footprint': footprint_data,
                'scan_info': scan_data,
                'enumeration': enum_data,
                'vulnerabilities': vulnerabilities
            }
            
            # Save comprehensive results
            self.db_manager.save_scan_results(target_url, result)
            
            return result
            
        except Exception as e:
            return {
                'error': True,
                'message': f'Scan failed: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }

    async def _footprinting(self, target_url: str) -> Dict[str, Any]:
        """Stage 1: Information Gathering"""
        try:
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            # Parallel footprinting tasks
            whois_info = await asyncio.to_thread(whois.whois, domain)
            dns_records = await self._get_dns_records(domain)
            subdomains = await self._discover_subdomains(domain)
            
            return {
                'whois': whois_info,
                'dns_records': dns_records,
                'subdomains': subdomains,
                'domain': domain
            }
        except Exception as e:
            print(f"Footprinting error: {str(e)}")
            return {}

    async def _scanning(self, target_url: str) -> Dict[str, Any]:
        """Stage 2: Network Scanning"""
        try:
            parsed_url = urlparse(target_url)
            host = parsed_url.netloc
            
            # Port scanning and service detection
            open_ports = await self._scan_ports(host)
            services = await self._detect_services(host, open_ports)
            
            return {
                'open_ports': open_ports,
                'services': services
            }
        except Exception as e:
            print(f"Scanning error: {str(e)}")
            return {}

    async def _enumeration(self, target_url: str) -> Dict[str, Any]:
        """Stage 3: System Enumeration"""
        try:
            # Web technology enumeration
            response = await asyncio.to_thread(requests.get, target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            technologies = []
            headers = dict(response.headers)
            
            # Check common technology indicators
            if 'X-Powered-By' in headers:
                technologies.append(headers['X-Powered-By'])
            if 'Server' in headers:
                technologies.append(headers['Server'])
            
            # Extract endpoints
            endpoints = set()
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    endpoints.add(urljoin(target_url, href))
            
            return {
                'technologies': technologies,
                'headers': headers,
                'endpoints': list(endpoints)
            }
        except Exception as e:
            print(f"Enumeration error: {str(e)}")
            return {}

    async def _parallel_vulnerability_assessment(self, target_url: str) -> Dict[str, List[Dict[str, Any]]]:
        """Stages 4-6: Parallel Vulnerability Assessment"""
        try:
            # Create tasks for parallel execution
            tasks = [
                asyncio.to_thread(self.owasp_scanner.scan, target_url),
                asyncio.to_thread(self.cve_scanner.scan, target_url),
                asyncio.to_thread(self.zeroday_scanner.scan, target_url),
                asyncio.to_thread(self.db_wayback_scanner.scan, target_url),
                asyncio.to_thread(self.database_scanner.scan, target_url)
            ]
            
            # Execute all scans in parallel
            results = await asyncio.gather(*tasks)
            
            # Organize results into four columns
            owasp_top_50 = results[0][:50] if len(results[0]) > 50 else results[0]  # First 50 OWASP findings
            cve_findings = results[1]  # Already limited to 10000 in CVE scanner
            
            # Combine DB wayback and database findings into 'other' category
            other_findings = []
            other_findings.extend(results[3])  # DB wayback findings
            other_findings.extend(results[4])  # Database findings
            
            # Zero-day findings from AI analysis
            zeroday_findings = results[2]
            
            return {
                'column_1_owasp_top_50': owasp_top_50,
                'column_2_cve_findings': cve_findings,
                'column_3_other_findings': other_findings,
                'column_4_zeroday_findings': zeroday_findings
            }
        except Exception as e:
            print(f"Vulnerability assessment error: {str(e)}")
            return {}

    async def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get various DNS records for the domain"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        results = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                results[record_type] = []
        
        return results

    async def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using common patterns"""
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api']
        discovered = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                await asyncio.to_thread(socket.gethostbyname, full_domain)
                discovered.append(full_domain)
            except socket.gaierror:
                continue
        
        return discovered

    async def _scan_ports(self, host: str) -> List[int]:
        """Scan for open ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = await asyncio.to_thread(sock.connect_ex, (host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        
        return open_ports

    async def _detect_services(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Detect services running on open ports"""
        services = {}
        for port in ports:
            try:
                service = socket.getservbyport(port)
                services[port] = service
            except Exception:
                services[port] = 'unknown'
        return services