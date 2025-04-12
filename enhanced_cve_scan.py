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
from datetime import datetime, timedelta
import hashlib
from typing import List, Dict, Any

class EnhancedCVEScanner:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_duration = timedelta(hours=24)
        self.max_threads = 20
        self.top_cve_count = 10000

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Get target information
            target_info = self._gather_target_info(target_url)
            
            # Get cached CVE data or fetch new data
            cve_data = self._get_cve_data()
            
            # Parallel vulnerability checking
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_cve = {executor.submit(self._check_vulnerability, target_info, cve): cve 
                                for cve in cve_data}
                
                for future in future_to_cve:
                    try:
                        result = future.result()
                        if result:
                            vulnerabilities.append(result)
                    except Exception as e:
                        print(f"Error checking CVE: {str(e)}")

            # Save results to database
            self.db_manager.save_cve_results(target_url, vulnerabilities)

        except Exception as e:
            print(f"Error during CVE scan: {str(e)}")
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Critical',
                'description': f'CVE scan failed: {str(e)}'
            })

        return vulnerabilities

    def _gather_target_info(self, target_url: str) -> Dict[str, Any]:
        """Gather detailed information about the target system"""
        info = {
            'url': target_url,
            'technologies': [],
            'versions': {},
            'headers': {},
            'server_info': {}
        }
        
        try:
            response = requests.get(target_url)
            info['headers'] = dict(response.headers)
            
            # Extract server information
            if 'Server' in response.headers:
                info['server_info']['server'] = response.headers['Server']
            
            # Extract technology versions from headers
            tech_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
            for header in tech_headers:
                if header in response.headers:
                    info['versions'][header] = response.headers[header]
            
        except Exception as e:
            print(f"Error gathering target info: {str(e)}")
        
        return info

    def _get_cve_data(self) -> List[Dict[str, Any]]:
        """Get CVE data with caching mechanism"""
        cache_key = f"cve_cache_{datetime.now().strftime('%Y%m%d')}"
        cached_data = self.db_manager.get_cache(cache_key)

        if cached_data and (datetime.now() - cached_data['timestamp']) < self.cache_duration:
            return cached_data['data']

        cve_data = []
        try:
            # Fetch top CVEs in batches
            for start_index in range(0, self.top_cve_count, 2000):
                params = {
                    'startIndex': start_index,
                    'resultsPerPage': min(2000, self.top_cve_count - start_index),
                    'sortBy': 'cvssV3Severity',
                    'sortOrder': 'desc'
                }
                response = requests.get(self.nvd_api_url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    cve_data.extend(data.get('vulnerabilities', []))

            # Cache the fetched data
            cache_data = {
                'timestamp': datetime.now(),
                'data': cve_data
            }
            self.db_manager.set_cache(cache_key, cache_data)

        except Exception as e:
            print(f"Error fetching CVE data: {str(e)}")
            # Use last known good cache if available
            last_cache = self.db_manager.get_cache(cache_key)
            if last_cache:
                return last_cache['data']

        return cve_data

    def _check_vulnerability(self, target_info: Dict[str, Any], cve: Dict[str, Any]) -> Dict[str, Any]:
        """Check if target is vulnerable to a specific CVE"""
        try:
            cve_data = cve.get('cve', {})
            descriptions = cve_data.get('descriptions', [])
            metrics = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0]
            
            # Extract CVE details
            cve_id = cve_data.get('id')
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
            cvss_score = metrics.get('cvssData', {}).get('baseScore', 0)
            severity = metrics.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            
            # Check for version-based vulnerabilities
            for version_key, version_value in target_info['versions'].items():
                if version_value.lower() in description.lower():
                    return {
                        'type': 'CVE',
                        'cve_id': cve_id,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'description': description,
                        'affected_component': version_key,
                        'recommendation': 'Update affected component to latest version'
                    }
            
            # Check for technology-based vulnerabilities
            for tech in target_info['technologies']:
                if tech.lower() in description.lower():
                    return {
                        'type': 'CVE',
                        'cve_id': cve_id,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'description': description,
                        'affected_component': tech,
                        'recommendation': 'Review and patch affected technology'
                    }
            
            # Check for server-based vulnerabilities
            if 'server' in target_info['server_info']:
                server = target_info['server_info']['server'].lower()
                if server in description.lower():
                    return {
                        'type': 'CVE',
                        'cve_id': cve_id,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'description': description,
                        'affected_component': 'Server',
                        'recommendation': 'Update server software to latest version'
                    }
                    
        except Exception as e:
            print(f"Error checking CVE {cve_id}: {str(e)}")
        
        return None