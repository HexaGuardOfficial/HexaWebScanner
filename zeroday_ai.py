import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
from .db_manager import DatabaseManager

class ZeroDayAI:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.api_token = os.getenv('HUGGINGFACE_API_TOKEN')
        self.model_url = "https://api-inference.huggingface.co/models/microsoft/codebert-base-mlm"
        self.headers = {"Authorization": f"Bearer {self.api_token}"}

    def scan(self, target_url):
        vulnerabilities = []
        
        try:
            # Gather target information
            target_info = self._gather_target_info(target_url)
            
            # Analyze potential vulnerabilities using AI
            ai_results = self._analyze_with_ai(target_info)
            
            # Process and format results
            for result in ai_results:
                if result['confidence'] > 0.7:  # Only include high-confidence predictions
                    vulnerabilities.append({
                        'type': 'Zero-Day',
                        'severity': self._calculate_severity(result),
                        'confidence': round(result['confidence'] * 100, 2),
                        'description': result['description'],
                        'recommendation': result['recommendation']
                    })

            # Save results to database
            self.db_manager.save_zeroday_results(target_url, vulnerabilities)

        except Exception as e:
            print(f"Error during zero-day scan: {str(e)}")
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Critical',
                'description': f'Zero-day scan failed: {str(e)}'
            })

        return vulnerabilities

    def _gather_target_info(self, target_url):
        """Gather relevant information about the target for AI analysis"""
        info = {
            'url': target_url,
            'headers': {},
            'technologies': [],
            'endpoints': [],
            'response_patterns': []
        }
        
        try:
            response = requests.get(target_url)
            info['headers'] = dict(response.headers)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract technologies
            info['technologies'] = self._detect_technologies(soup, response.headers)
            
            # Find potential endpoints
            info['endpoints'] = self._extract_endpoints(soup, target_url)
            
            # Analyze response patterns
            info['response_patterns'] = self._analyze_response_patterns(response)
            
        except Exception as e:
            print(f"Error gathering target info: {str(e)}")
            
        return info

    def _detect_technologies(self, soup, headers):
        technologies = []
        
        # Check headers for server info
        if 'Server' in headers:
            technologies.append(f"Server: {headers['Server']}")
            
        # Check for common frameworks
        if soup.find(attrs={"data-react-root": True}):
            technologies.append("React")
        if soup.find(attrs={"ng-version": True}):
            technologies.append("Angular")
        if soup.find(attrs={"data-vue-root": True}):
            technologies.append("Vue.js")
            
        return technologies

    def _extract_endpoints(self, soup, base_url):
        endpoints = set()
        
        # Extract links and forms
        for link in soup.find_all('a'):
            href = link.get('href')
            if href:
                endpoints.add(self._normalize_url(href, base_url))
                
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                endpoints.add(self._normalize_url(action, base_url))
                
        return list(endpoints)

    def _normalize_url(self, url, base_url):
        if url.startswith('/'):
            parsed_base = urlparse(base_url)
            return f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
        return url

    def _analyze_response_patterns(self, response):
        patterns = []
        
        # Check for security headers
        security_headers = [
            'X-Frame-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'X-Content-Type-Options'
        ]
        
        for header in security_headers:
            if header not in response.headers:
                patterns.append(f"Missing {header}")
                
        return patterns

    def _analyze_with_ai(self, target_info):
        """Use Hugging Face model to analyze potential zero-day vulnerabilities"""
        try:
            # Prepare input for the model
            input_text = json.dumps({
                'url': target_info['url'],
                'technologies': target_info['technologies'],
                'patterns': target_info['response_patterns']
            })
            
            # Query the model
            response = requests.post(
                self.model_url,
                headers=self.headers,
                json={"inputs": input_text}
            )
            
            if response.status_code == 200:
                predictions = response.json()
                return self._process_ai_predictions(predictions, target_info)
            
        except Exception as e:
            print(f"Error in AI analysis: {str(e)}")
            
        return []

    def _process_ai_predictions(self, predictions, target_info):
        """Process and format AI predictions"""
        results = []
        
        try:
            for pred in predictions:
                # Extract meaningful insights from the model's output
                vulnerability = {
                    'confidence': pred.get('score', 0),
                    'description': pred.get('vulnerability_description', ''),
                    'recommendation': self._generate_recommendation(pred, target_info)
                }
                results.append(vulnerability)
                
        except Exception as e:
            print(f"Error processing AI predictions: {str(e)}")
            
        return results

    def _calculate_severity(self, result):
        """Calculate severity based on AI confidence and vulnerability type"""
        confidence = result['confidence']
        
        if confidence > 0.9:
            return 'Critical'
        elif confidence > 0.8:
            return 'High'
        elif confidence > 0.7:
            return 'Medium'
        else:
            return 'Low'

    def _generate_recommendation(self, prediction, target_info):
        """Generate specific recommendations based on the AI prediction"""
        base_rec = prediction.get('recommendation', 'No specific recommendation available.')
        
        # Add context-specific recommendations
        if 'Missing Content-Security-Policy' in target_info['response_patterns']:
            base_rec += " Implement a strong Content Security Policy."
            
        if 'React' in target_info['technologies']:
            base_rec += " Ensure React security best practices are followed."
            
        return base_rec 