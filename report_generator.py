import json
import csv
from datetime import datetime
from db_manager import DatabaseManager

def generate_report(scan_results, output_format='json'):
    """Generate a vulnerability scan report."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if output_format == 'json':
        report = {
            'timestamp': timestamp,
            'scan_results': scan_results,
            'summary': {
                'total_vulnerabilities': sum(1 for scanner in scan_results.values() 
                                          for vuln in scanner if isinstance(vuln, dict) and 'type' in vuln),
                'critical': sum(1 for scanner in scan_results.values() 
                              for vuln in scanner if isinstance(vuln, dict) and vuln.get('severity') == 'Critical'),
                'high': sum(1 for scanner in scan_results.values() 
                          for vuln in scanner if isinstance(vuln, dict) and vuln.get('severity') == 'High'),
                'medium': sum(1 for scanner in scan_results.values() 
                            for vuln in scanner if isinstance(vuln, dict) and vuln.get('severity') == 'Medium'),
                'low': sum(1 for scanner in scan_results.values() 
                         for vuln in scanner if isinstance(vuln, dict) and vuln.get('severity') == 'Low')
            }
        }
        return report
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

class ReportGenerator:
    def __init__(self):
        self.db = DatabaseManager()

    def generate_report(self, target_url, format_type='pdf'):
        vulnerabilities = self.db.get_vulnerabilities(target_url)
        
        if format_type == 'json':
            return self._generate_json_report(vulnerabilities)
        elif format_type == 'csv':
            return self._generate_csv_report(vulnerabilities)
        else:
            return self._generate_pdf_report(vulnerabilities)

    def _generate_json_report(self, vulnerabilities):
        return json.dumps(vulnerabilities, indent=4)

    def _generate_csv_report(self, vulnerabilities):
        output = []
        for vuln in vulnerabilities:
            output.append([vuln['type'], vuln['severity'], vuln['description']])
        return output

    def _generate_pdf_report(self, vulnerabilities):
        # Implement PDF generation logic
        return "PDF Report Generated"

    def save_report(self, report_data):
        """Save report to database"""
        return self.db.save_report(report_data)
    
    def get_report(self, report_id):
        """Retrieve report from database"""
        return self.db.get_report(report_id)
    
    def list_reports(self):
        """List all reports"""
        return self.db.list_reports() 