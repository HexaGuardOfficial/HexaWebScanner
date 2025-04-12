import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
from db_manager import DatabaseManager
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any
import re
from urllib.parse import urljoin
from datetime import datetime
import hashlib
from huggingface_hub import InferenceClient

class EnhancedZeroDayAI:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.api_token = os.getenv('HUGGINGFACE_API_TOKEN')
        if not self.api_token:
            raise ValueError("HUGGINGFACE_API_TOKEN environment variable not set")
        
        self.client = InferenceClient(token=self.api_token)
        self.model = "microsoft/codebert-base-mlm"
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.pattern_threshold = 0.85
        self.session = requests.Session()

    async def scan(self, target_url: str) -> List[Dict[str, Any]]:
        """Run comprehensive vulnerability scan"""
        vulnerabilities = []
        
        try:
            # Extract endpoints
            endpoints = await self._extract_advanced_endpoints(target_url)
            
            # Analyze response anomalies
            response_vulns = await self._analyze_response_anomalies(target_url, endpoints)
            vulnerabilities.extend(response_vulns)
            
            # Analyze security patterns
            pattern_vulns = await self._analyze_security_patterns(target_url)
            vulnerabilities.extend(pattern_vulns)
            
            # Use Hugging Face model for advanced analysis
            ai_vulns = await self._analyze_with_ai(target_url, endpoints)
            vulnerabilities.extend(ai_vulns)
            
        except Exception as e:
            print(f"Error in ZeroDay AI scan: {str(e)}")
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Critical',
                'description': f'ZeroDay AI scan failed: {str(e)}'
            })
            
        return vulnerabilities

    def _gather_enhanced_info(self, target_url: str) -> Dict[str, Any]:
        info = {
            'url': target_url,
            'headers': {},
            'technologies': [],
            'endpoints': [],
            'response_patterns': [],
            'behavior_metrics': {},
            'security_features': [],
            'traffic_patterns': []
        }
        
        try:
            response = requests.get(target_url)
            info['headers'] = dict(response.headers)
            
            # Enhanced HTML parsing
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect technologies and frameworks
            info['technologies'] = self._detect_advanced_technologies(soup, response.headers)
            
            # Extract endpoints and APIs
            info['endpoints'] = self._extract_advanced_endpoints(target_url)
            
            # Analyze response patterns
            info['response_patterns'] = self._analyze_advanced_patterns(response)
            
            # Gather behavior metrics
            info['behavior_metrics'] = self._gather_behavior_metrics(target_url)
            
            # Analyze security features
            info['security_features'] = self._analyze_security_features(response)
            
            # Monitor traffic patterns
            info['traffic_patterns'] = self._monitor_traffic_patterns(target_url)
            
        except Exception as e:
            print(f"Error gathering enhanced target info: {str(e)}")
            
        return info

    def _detect_advanced_technologies(self, soup, headers) -> List[str]:
        technologies = []
        
        # Server technology detection
        if 'Server' in headers:
            technologies.append(f"Server: {headers['Server']}")
        
        # Framework detection
        framework_patterns = {
            'React': ['react', 'reactjs', 'react-root'],
            'Angular': ['ng-', 'angular', 'ng2-'],
            'Vue.js': ['vue', 'nuxt', 'vuex'],
            'Django': ['csrftoken', 'django'],
            'Laravel': ['laravel', 'csrf-token'],
            'Spring': ['spring', 'jsessionid'],
            'Node.js': ['express', 'node'],
            'WordPress': ['wp-', 'wordpress']
        }
        
        for tech, patterns in framework_patterns.items():
            if any(pattern in str(soup).lower() for pattern in patterns):
                technologies.append(tech)
        
        return technologies

    def _analyze_behavior(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Analyze request/response patterns
            response_anomalies = self._analyze_response_anomalies(target_info['response_patterns'])
            if response_anomalies:
                vulnerabilities.append({
                    'type': 'Zero-Day',
                    'subtype': 'Behavioral Anomaly',
                    'severity': 'High',
                    'confidence': 0.85,
                    'description': 'Unusual response patterns detected',
                    'details': response_anomalies,
                    'recommendation': 'Review and investigate unusual behavior patterns'
                })

            # Analyze traffic patterns
            traffic_anomalies = self._analyze_traffic_anomalies(target_info['traffic_patterns'])
            if traffic_anomalies:
                vulnerabilities.append({
                    'type': 'Zero-Day',
                    'subtype': 'Traffic Anomaly',
                    'severity': 'High',
                    'confidence': 0.9,
                    'description': 'Suspicious traffic patterns detected',
                    'details': traffic_anomalies,
                    'recommendation': 'Investigate unusual traffic patterns'
                })

        except Exception as e:
            print(f"Error in behavior analysis: {str(e)}")

        return vulnerabilities

    def _detect_patterns(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Analyze security patterns
            security_patterns = self._analyze_security_patterns(target_info)
            if security_patterns:
                vulnerabilities.extend(security_patterns)

            # Check for known vulnerability patterns
            vuln_patterns = self._check_vulnerability_patterns(target_info)
            if vuln_patterns:
                vulnerabilities.extend(vuln_patterns)

        except Exception as e:
            print(f"Error in pattern detection: {str(e)}")

        return vulnerabilities

    def _detect_anomalies(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Convert behavior metrics to features
            features = self._extract_features(target_info)
            
            # Train and predict anomalies
            self.anomaly_detector.fit(features)
            predictions = self.anomaly_detector.predict(features)
            
            # Analyze anomalies
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    vulnerabilities.append({
                        'type': 'Zero-Day',
                        'subtype': 'Anomaly',
                        'severity': 'Critical',
                        'confidence': 0.95,
                        'description': 'Potential zero-day vulnerability detected through anomaly detection',
                        'feature_index': i,
                        'recommendation': 'Investigate anomalous behavior pattern'
                    })

        except Exception as e:
            print(f"Error in anomaly detection: {str(e)}")

        return vulnerabilities

    def _advanced_ai_analysis(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            # Prepare data for AI analysis
            analysis_data = self._prepare_ai_data(target_info)
            
            # Send to AI model for analysis
            response = requests.post(
                self.model_url,
                headers=self.headers,
                json={"inputs": analysis_data}
            )
            
            if response.status_code == 200:
                predictions = response.json()
                
                # Process AI predictions
                for pred in predictions:
                    if pred['confidence'] > self.pattern_threshold:
                        vulnerabilities.append({
                            'type': 'Zero-Day',
                            'subtype': 'AI Detection',
                            'severity': pred.get('severity', 'High'),
                            'confidence': pred['confidence'],
                            'description': pred.get('description', 'Potential zero-day vulnerability detected'),
                            'recommendation': pred.get('recommendation', 'Review and investigate AI findings')
                        })

        except Exception as e:
            print(f"Error in AI analysis: {str(e)}")

        return vulnerabilities

    def _extract_features(self, target_info: Dict[str, Any]) -> np.ndarray:
        features = []
        try:
            # Extract numerical features from behavior metrics
            metrics = target_info['behavior_metrics']
            features.extend([
                metrics.get('response_time', 0),
                metrics.get('request_frequency', 0),
                metrics.get('error_rate', 0),
                len(target_info['endpoints']),
                len(target_info['technologies'])
            ])
            
            # Normalize features
            features = np.array(features).reshape(1, -1)
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            features = np.zeros((1, 5))  # Default features if extraction fails
            
        return features

    def _prepare_ai_data(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'url': target_info['url'],
            'headers': json.dumps(target_info['headers']),
            'technologies': target_info['technologies'],
            'endpoints': target_info['endpoints'],
            'response_patterns': target_info['response_patterns'],
            'behavior_metrics': target_info['behavior_metrics'],
            'security_features': target_info['security_features']
        }

    async def _extract_advanced_endpoints(self, target_url: str) -> list:
        """Extract and analyze endpoints from the target URL"""
        endpoints = []
        try:
            # Get the main page
            response = self.session.get(target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links and forms
            links = soup.find_all('a')
            forms = soup.find_all('form')
            
            # Process links
            for link in links:
                href = link.get('href')
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    endpoints.append(href)
            
            # Process forms
            for form in forms:
                action = form.get('action')
                if action:
                    endpoints.append(action)
            
            # Clean and normalize endpoints
            normalized_endpoints = []
            for endpoint in endpoints:
                if endpoint.startswith('/'):
                    normalized_endpoints.append(target_url.rstrip('/') + endpoint)
                elif endpoint.startswith(target_url):
                    normalized_endpoints.append(endpoint)
                else:
                    try:
                        full_url = urljoin(target_url, endpoint)
                        normalized_endpoints.append(full_url)
                    except:
                        continue
            
            return list(set(normalized_endpoints))
            
        except Exception as e:
            print(f"Error extracting endpoints: {str(e)}")
            return []

    async def _analyze_response_anomalies(self, target_url: str, endpoints: list) -> list:
        """Analyze response patterns for anomalies"""
        vulnerabilities = []
        try:
            # Collect response data
            response_data = []
            for endpoint in endpoints:
                try:
                    response = self.session.get(endpoint)
                    
                    # Extract features
                    features = [
                        len(response.content),
                        len(response.headers),
                        response.status_code,
                        len(response.text.split()),
                        response.elapsed.total_seconds()
                    ]
                    response_data.append(features)
                except:
                    continue
            
            if response_data:
                # Convert to numpy array
                X = np.array(response_data)
                
                # Fit and predict
                self.anomaly_detector.fit(X)
                predictions = self.anomaly_detector.predict(X)
                
                # Find anomalies
                for i, pred in enumerate(predictions):
                    if pred == -1:  # Anomaly detected
                        vulnerabilities.append({
                            'type': 'Response Anomaly',
                            'endpoint': endpoints[i],
                            'description': 'Unusual response pattern detected',
                            'severity': 'Medium'
                        })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error analyzing response anomalies: {str(e)}")
            return []

    async def _analyze_security_patterns(self, target_url: str) -> list:
        """Analyze security patterns and potential vulnerabilities"""
        vulnerabilities = []
        try:
            response = self.session.get(target_url)
            
            # Check for sensitive information exposure
            sensitive_patterns = [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'api[_-]?key\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret[_-]?key\s*=\s*[\'"][^\'"]+[\'"]',
                r'database\s*=\s*[\'"][^\'"]+[\'"]',
                r'admin\s*=\s*[\'"][^\'"]+[\'"]',
                r'root\s*=\s*[\'"][^\'"]+[\'"]',
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            ]
            
            for pattern in sensitive_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'pattern': pattern,
                        'description': 'Sensitive information exposed in response',
                        'severity': 'High'
                    })
            
            # Check for security misconfigurations
            security_checks = {
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'Strict-Transport-Security': 'Missing HSTS header'
            }
            
            for header, message in security_checks.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'header': header,
                        'description': message,
                        'severity': 'Medium'
                    })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error analyzing security patterns: {str(e)}")
            return []

    async def _analyze_with_ai(self, target_url: str, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Use Hugging Face model to analyze potential vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Prepare data for AI analysis
            analysis_data = {
                'url': target_url,
                'endpoints': endpoints,
                'response_headers': self.session.get(target_url).headers,
                'technologies': self._detect_technologies(target_url)
            }
            
            # Send to Hugging Face model
            response = self.client.text_generation(
                model=self.model,
                inputs=json.dumps(analysis_data),
                parameters={
                    'max_length': 500,
                    'temperature': 0.7,
                    'top_p': 0.9
                }
            )
            
            # Parse AI response
            ai_results = json.loads(response)
            if 'vulnerabilities' in ai_results:
                vulnerabilities.extend(ai_results['vulnerabilities'])
                
        except Exception as e:
            print(f"Error in AI analysis: {str(e)}")
            
        return vulnerabilities
        
    def _detect_technologies(self, target_url: str) -> List[str]:
        """Detect technologies used by the target"""
        technologies = []
        try:
            response = self.session.get(target_url)
            
            # Check headers for technology indicators
            headers = response.headers
            if 'Server' in headers:
                technologies.append(headers['Server'])
            if 'X-Powered-By' in headers:
                technologies.append(headers['X-Powered-By'])
                
            # Check HTML for framework indicators
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta', {'name': 'generator'})
            for tag in meta_tags:
                if tag.get('content'):
                    technologies.append(tag['content'])
                    
        except Exception as e:
            print(f"Error detecting technologies: {str(e)}")
            
        return list(set(technologies))