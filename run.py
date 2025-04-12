import argparse
import asyncio
import os
from typing import List, Dict
import requests
from dotenv import load_dotenv
from enhanced_owasp_scan import EnhancedOWASPScanner
from enhanced_static_scanner import EnhancedStaticScanner
from enhanced_zeroday_ai import EnhancedZeroDayAI
from enhanced_cve_scan import EnhancedCVEScanner
from report_generator import generate_report
import json
import sys
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import datetime

# Load environment variables
load_dotenv()

class VulnerabilityScannerCLI:
    def __init__(self):
        self.huggingface_api_key = os.getenv("HUGGINGFACE_API_KEY")
        self.scanners = {
            "owasp": EnhancedOWASPScanner(),
            "static": EnhancedStaticScanner(),
            "zeroday": EnhancedZeroDayAI(),
            "cve": EnhancedCVEScanner()
        }

    async def scan_url(self, url: str) -> Dict:
        """Run all vulnerability scans on the given URL"""
        results = {}
        
        for scanner_name, scanner in self.scanners.items():
            try:
                print(f"Running {scanner_name} scan...")
                if hasattr(scanner, 'scan'):
                    results[scanner_name] = await scanner.scan(url)
                else:
                    results[scanner_name] = scanner.scan(url)
            except Exception as e:
                print(f"Error in {scanner_name} scan: {str(e)}")
                results[scanner_name] = {"error": str(e)}
        
        return results

    def generate_ai_report(self, scan_results: Dict) -> str:
        """Generate a report using Hugging Face API"""
        if not self.huggingface_api_key:
            raise ValueError("HUGGINGFACE_API_KEY not found in environment variables")

        # Prepare the prompt for the AI
        prompt = f"""
        Please analyze these vulnerability scan results and generate a comprehensive security report:
        {json.dumps(scan_results, indent=2)}
        
        Include:
        1. Executive Summary
        2. Critical Findings
        3. Risk Assessment
        4. Recommendations
        5. Technical Details
        """

        # Call Hugging Face API
        headers = {
            "Authorization": f"Bearer {self.huggingface_api_key}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            "https://api.huggingface.co/models/gpt2-large",
            headers=headers,
            json={"inputs": prompt}
        )

        if response.status_code != 200:
            raise Exception(f"Hugging Face API error: {response.text}")

        return response.json()[0]["generated_text"]

    async def run(self, url: str):
        """Main execution method"""
        print(f"Starting vulnerability scan for {url}")
        
        # Run all scans
        scan_results = await self.scan_url(url)
        
        # Generate AI report
        print("Generating AI report...")
        ai_report = self.generate_ai_report(scan_results)
        
        # Save results
        output_dir = "scan_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Save raw scan results
        with open(f"{output_dir}/raw_scan_results.json", "w") as f:
            json.dump(scan_results, f, indent=2)
        
        # Save AI report
        with open(f"{output_dir}/ai_report.txt", "w") as f:
            f.write(ai_report)
        
        print(f"\nScan completed! Results saved in {output_dir}/")
        print("\nAI Report Summary:")
        print(ai_report)

async def run_parallel_scans(target_url: str, huggingface_token: str):
    """Run all vulnerability scans in parallel with improved performance"""
    # Set the Hugging Face token as environment variable
    os.environ['HUGGINGFACE_API_TOKEN'] = huggingface_token
    
    # Initialize scanners
    scanners = {
        'owasp': EnhancedOWASPScanner(),
        'cve': EnhancedCVEScanner(),
        'zeroday': EnhancedZeroDayAI()
    }
    
    # Create tasks for parallel execution
    tasks = []
    for scanner_name, scanner in scanners.items():
        if hasattr(scanner, 'scan'):
            tasks.append(asyncio.create_task(scanner.scan(target_url)))
        else:
            tasks.append(asyncio.create_task(asyncio.to_thread(scanner.scan, target_url)))
    
    # Run all scans concurrently and gather results
    results = {}
    start_time = time.time()
    
    # Use asyncio.gather with return_exceptions=True to handle errors gracefully
    scan_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for scanner_name, result in zip(scanners.keys(), scan_results):
        if isinstance(result, Exception):
            results[scanner_name] = [{
                'type': 'Scan Error',
                'severity': 'Critical',
                'description': f'{scanner_name} scan failed: {str(result)}'
            }]
        else:
            results[scanner_name] = result
    
    # Generate report
    report = generate_report(results)
    
    # Add performance metrics
    end_time = time.time()
    report['performance_metrics'] = {
        'total_scan_time': f"{end_time - start_time:.2f} seconds",
        'scans_completed': len([r for r in scan_results if not isinstance(r, Exception)]),
        'scans_failed': len([r for r in scan_results if isinstance(r, Exception)]),
        'timestamp': datetime.now().isoformat()
    }
    
    # Save report to file
    filename = f'scan_report_{target_url.replace("://", "_").replace("/", "_")}.json'
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4)
    
    return report

def main():
    # Ask for Hugging Face API token
    huggingface_token = input("Please enter your Hugging Face API token: ").strip()
    if not huggingface_token:
        print("Error: Hugging Face API token is required")
        sys.exit(1)
    
    # Ask for target URL
    target_url = input("Enter the website URL to scan: ").strip()
    if not target_url:
        print("Error: Target URL is required")
        sys.exit(1)
    
    # Ensure URL starts with http:// or https://
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print(f"\nStarting parallel vulnerability scan for {target_url}...")
    print("Running OWASP, CVE, and ZeroDay AI scans concurrently...")
    
    try:
        # Run scans
        report = asyncio.run(run_parallel_scans(target_url, huggingface_token))
        
        # Print summary
        print("\nScan Summary:")
        print(f"Total scan time: {report['performance_metrics']['total_scan_time']}")
        print(f"Total vulnerabilities found: {report['summary']['total_vulnerabilities']}")
        print("\nVulnerability Breakdown:")
        print(f"Critical: {report['summary']['critical']}")
        print(f"High: {report['summary']['high']}")
        print(f"Medium: {report['summary']['medium']}")
        print(f"Low: {report['summary']['low']}")
        
        # Print detailed results
        print("\nDetailed Results:")
        for scanner, results in report['scan_results'].items():
            print(f"\n{scanner.upper()} Scan Results:")
            for vuln in results:
                print(f"- [{vuln.get('severity', 'Unknown')}] {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
        
        print(f"\nReport saved to {target_url.replace('://', '_').replace('/', '_')}.json")
        
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 