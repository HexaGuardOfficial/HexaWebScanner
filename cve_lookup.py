import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .db_manager import DatabaseManager

class CVELookup:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()

    def lookup(self, target_url):
        vulnerabilities = []
        
        try:
            # Detect technologies used by the target
            tech_stack = self._detect_technologies(target_url)
            
            # Fetch relevant CVEs based on detected technologies
            for tech, version in tech_stack.items():
                cve_params = {
                    'keywordSearch': f'{tech} {version}',
                    'resultsPerPage': 20,
                    'startIndex': 0
                }
                
                response = self.session.get(self.cve_api_url, params=cve_params)
                if response.status_code == 200:
                    cves = response.json().get('vulnerabilities', [])
                    
                    for cve in cves:
                        if self._is_relevant_cve(cve, tech, version):
                            vulnerabilities.append(self._format_cve(cve, tech))

            # Save results to database
            self.db_manager.save_cve_results(target_url, vulnerabilities)

        except Exception as e:
            print(f"Error during CVE lookup: {str(e)}")
            vulnerabilities.append({
                'type': 'Lookup Error',
                'severity': 'Critical',
                'description': f'CVE lookup failed: {str(e)}'
            })

        return vulnerabilities

    def _detect_technologies(self, target_url):
        tech_stack = {}
        try:
            response = self.session.get(target_url)
            headers = response.headers
            content = response.text
            
            # Server technology
            if 'Server' in headers:
                server = headers['Server']
                tech_stack['server'] = self._extract_version(server)
            
            # Web frameworks
            frameworks = {
                'Django': r'django.[\d\.]+',
                'Flask': r'Flask/[\d\.]+',
                'Laravel': r'Laravel/[\d\.]+',
                'ASP.NET': r'ASP.NET[\s\d\.]+',
            }
            
            for framework, pattern in frameworks.items():
                if match := re.search(pattern, content):
                    tech_stack[framework.lower()] = match.group(0)
            
            # JavaScript frameworks
            if 'react' in content.lower():
                tech_stack['react'] = 'detected'
            if 'angular' in content.lower():
                tech_stack['angular'] = 'detected'
            if 'vue' in content.lower():
                tech_stack['vue'] = 'detected'
                
            # Database hints
            if any(db in content.lower() for db in ['mysql', 'postgresql', 'mongodb']):
                tech_stack['database'] = 'detected'

        except Exception as e:
            print(f"Error detecting technologies: {str(e)}")
        
        return tech_stack

    def _extract_version(self, text):
        version_pattern = r'[\d\.]+(?:\-?\w+)?'
        if match := re.search(version_pattern, text):
            return match.group(0)
        return 'unknown'

    def _is_relevant_cve(self, cve, tech, version):
        try:
            cve_data = cve.get('cve', {})
            descriptions = cve_data.get('descriptions', [{}])[0].get('value', '').lower()
            
            # Check if the technology is mentioned in the CVE
            if tech.lower() not in descriptions:
                return False
                
            # Version comparison if available
            if version != 'unknown' and version != 'detected':
                affected_versions = re.findall(r'[\d\.]+', descriptions)
                if not any(self._version_matches(version, v) for v in affected_versions):
                    return False
            
            return True
        except:
            return False

    def _version_matches(self, current, affected):
        try:
            current_parts = [int(x) for x in current.split('.')]
            affected_parts = [int(x) for x in affected.split('.')]
            
            # Compare version numbers
            for i in range(min(len(current_parts), len(affected_parts))):
                if current_parts[i] < affected_parts[i]:
                    return True
                elif current_parts[i] > affected_parts[i]:
                    return False
            return len(current_parts) <= len(affected_parts)
        except:
            return False

    def _format_cve(self, cve, tech):
        cve_data = cve.get('cve', {})
        metrics = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
        
        return {
            'type': 'CVE',
            'id': cve_data.get('id', 'Unknown'),
            'severity': metrics.get('baseSeverity', 'Unknown'),
            'score': metrics.get('baseScore', 0.0),
            'technology': tech,
            'description': cve_data.get('descriptions', [{}])[0].get('value', 'No description available')
        } 