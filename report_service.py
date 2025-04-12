from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import csv
import io
from fpdf import FPDF
from .log_service import LogSection

class ReportService:
    def __init__(self):
        self.severity_levels = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }

    def generate_report(self, scan_results: Dict[str, Any], format: str = 'json') -> Any:
        """Generate a vulnerability report in the specified format"""
        if format.lower() == 'json':
            return self._generate_json_report(scan_results)
        elif format.lower() == 'csv':
            return self._generate_csv_report(scan_results)
        elif format.lower() == 'pdf':
            return self._generate_pdf_report(scan_results)
        else:
            raise ValueError(f'Unsupported format: {format}')

    def _generate_json_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate a JSON format report"""
        report = self._create_base_report(scan_results)
        return json.dumps(report, indent=2)

    def _generate_csv_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate a CSV format report"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        headers = ['Vulnerability Type', 'Section', 'Severity', 'Affected Endpoint',
                  'Description', 'Proof of Concept', 'Mitigation Steps']
        writer.writerow(headers)
        
        # Write vulnerabilities
        for section in LogSection:
            vulns = scan_results.get('vulnerabilities', {}).get(f'column_{section.value}_findings', [])
            for vuln in vulns:
                writer.writerow([
                    vuln.get('type', ''),
                    section.value,
                    vuln.get('severity', ''),
                    vuln.get('affected_endpoint', ''),
                    vuln.get('description', ''),
                    vuln.get('poc', ''),
                    vuln.get('mitigation', '')
                ])
        
        return output.getvalue()

    def _generate_pdf_report(self, scan_results: Dict[str, Any]) -> bytes:
        """Generate a PDF format report"""
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Vulnerability Assessment Report', 0, 1, 'C')
        pdf.ln(10)
        
        # Summary
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Executive Summary', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        self._add_summary_section(pdf, scan_results)
        
        # Vulnerabilities by section
        for section in LogSection:
            vulns = scan_results.get('vulnerabilities', {}).get(f'column_{section.value}_findings', [])
            if vulns:
                pdf.add_page()
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, f'{section.value.upper()} Findings', 0, 1, 'L')
                self._add_vulnerabilities_section(pdf, vulns)
        
        return pdf.output(dest='S').encode('latin1')

    def _create_base_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a base report structure"""
        return {
            'timestamp': datetime.now().isoformat(),
            'target_url': scan_results.get('target_url', ''),
            'scan_duration': self._calculate_duration(scan_results),
            'summary': self._create_summary(scan_results),
            'vulnerabilities': self._organize_vulnerabilities(scan_results),
            'footprint': scan_results.get('footprint', {}),
            'scan_info': scan_results.get('scan_info', {}),
            'enumeration': scan_results.get('enumeration', {})
        }

    def _calculate_duration(self, scan_results: Dict[str, Any]) -> float:
        """Calculate scan duration in seconds"""
        start_time = datetime.fromisoformat(scan_results.get('timestamp', ''))
        end_time = datetime.now()
        return (end_time - start_time).total_seconds()

    def _create_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of findings"""
        summary = {
            'total_vulnerabilities': 0,
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        vulns = scan_results.get('vulnerabilities', {})
        for section in LogSection:
            section_vulns = vulns.get(f'column_{section.value}_findings', [])
            summary['total_vulnerabilities'] += len(section_vulns)
            for vuln in section_vulns:
                severity = vuln.get('severity', 'info').lower()
                summary['severity_counts'][severity] += 1
        
        return summary

    def _organize_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Organize vulnerabilities by section and severity"""
        organized = {}
        vulns = scan_results.get('vulnerabilities', {})
        
        for section in LogSection:
            section_vulns = vulns.get(f'column_{section.value}_findings', [])
            organized[section.value] = sorted(
                section_vulns,
                key=lambda x: self.severity_levels.get(x.get('severity', 'info').lower(), 0),
                reverse=True
            )
        
        return organized

    def _add_summary_section(self, pdf: FPDF, scan_results: Dict[str, Any]) -> None:
        """Add summary section to PDF report"""
        summary = self._create_summary(scan_results)
        pdf.multi_cell(0, 10, f"Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
        pdf.multi_cell(0, 10, 'Severity Distribution:')
        for severity, count in summary['severity_counts'].items():
            pdf.multi_cell(0, 10, f"{severity.capitalize()}: {count}")

    def _add_vulnerabilities_section(self, pdf: FPDF, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Add vulnerabilities section to PDF report"""
        for vuln in vulnerabilities:
            pdf.set_font('Arial', 'B', 10)
            pdf.multi_cell(0, 10, f"Type: {vuln.get('type', '')}")
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 10, f"Severity: {vuln.get('severity', '')}")
            pdf.multi_cell(0, 10, f"Affected Endpoint: {vuln.get('affected_endpoint', '')}")
            pdf.multi_cell(0, 10, f"Description: {vuln.get('description', '')}")
            pdf.multi_cell(0, 10, f"Proof of Concept: {vuln.get('poc', '')}")
            pdf.multi_cell(0, 10, f"Mitigation Steps: {vuln.get('mitigation', '')}")
            pdf.ln(10)