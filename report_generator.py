import json
from datetime import datetime
import os
from colorama import Fore, Style

class ReportGenerator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.security_headers = {}
        self.vulnerability_stats = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        self.injection_points = {
            'url_params': 0,
            'forms': 0,
            'headers': 0,
            'cookies': 0
        }
        
    def _format_injection_points(self, injection_points):
        """Format injection points for HTML display"""
        if not injection_points:
            return "No specific injection points documented."
            
        html = '<div class="injection-points-list">'
        for point in injection_points:
            effectiveness_color = {
                'High': '#4caf50',
                'Medium': '#ff9800',
                'Low': '#f44336'
            }.get(point.get('effectiveness', 'Low'), '#9e9e9e')
            
            html += f"""
                <div class="injection-point">
                    <span class="location" style="font-weight: bold;">{point.get('location', 'Unknown')}:</span>
                    <span class="method">{point.get('method', 'Not specified')}</span>
                    <span class="effectiveness" style="color: {effectiveness_color};">({point.get('effectiveness', 'Unknown')} effectiveness)</span>
                </div>
            """
        html += '</div>'
        return html
        
    def add_finding(self, url, payload, method, context, risk_level, analysis_results):
        """Add a new finding to the report"""
        finding = {
            'url': url,
            'payload': payload,
            'method': method,
            'context': context,
            'risk_level': risk_level,
            'analysis': analysis_results,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        
        # Update vulnerability stats
        if risk_level in self.vulnerability_stats:
            self.vulnerability_stats[risk_level] += 1
            
        # Update injection points
        if 'form' in method.lower():
            self.injection_points['forms'] += 1
        elif 'get' in method.lower() or 'post' in method.lower():
            self.injection_points['url_params'] += 1
        elif 'header' in context.lower():
            self.injection_points['headers'] += 1
        elif 'cookie' in context.lower():
            self.injection_points['cookies'] += 1
        
    def generate_html_report(self):
        """Generate HTML report with enhanced payload information"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS Scan Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .finding {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .critical {{ background-color: #ffebee; border-color: #ffcdd2; }}
        .high {{ background-color: #fff3e0; border-color: #ffe0b2; }}
        .medium {{ background-color: #fff8e1; border-color: #ffecb3; }}
        .low {{ background-color: #e8f5e9; border-color: #c8e6c9; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        .summary {{ margin: 20px 0; padding: 15px; background-color: #f5f5f5; }}
        .metadata {{ margin: 10px 0; padding: 10px; background-color: rgba(255, 255, 255, 0.7); border-radius: 3px; }}
        .metadata-item {{ margin: 5px 0; }}
        .metadata-label {{ font-weight: bold; color: #666; }}
        .technique-tag {{ display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 12px; background-color: #e3f2fd; color: #1976d2; font-size: 0.9em; }}
        .mitigation {{ background-color: #fff3e0; padding: 10px; margin-top: 10px; border-left: 4px solid #fb8c00; }}
        .browser-support {{ color: #666; font-style: italic; margin-top: 5px; }}
        .injection-points {{ margin-top: 15px; padding: 10px; background-color: #f5f5f5; border-radius: 3px; }}
        .injection-points-list {{ margin-top: 8px; }}
        .injection-point {{ margin: 5px 0; padding: 5px; border-left: 3px solid #2196f3; }}
        .location {{ color: #1976d2; }}
        .method {{ margin-left: 8px; color: #666; }}
        .effectiveness {{ margin-left: 8px; font-style: italic; }}
    </style>
</head>
<body>
    <h1>XSS Scan Report</h1>
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Target URL: {self.target_url}</p>
        <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Findings: {len(self.findings)}</p>
    </div>"""

        
        for finding in self.findings:
            risk_class = finding['risk_level'].lower()
            metadata = finding.get('metadata', {})
            
            html += f"""
    <div class="finding {risk_class}">
        <h2>Finding: {finding['risk_level']} Risk</h2>
        <p><strong>URL:</strong> {finding['url']}</p>
        <p><strong>Method:</strong> {finding['method']}</p>
        
        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Context:</span> {finding['context']}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Category:</span> {metadata.get('category', 'Unknown')}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Technique:</span>
                <span class="technique-tag">{metadata.get('technique', 'Unknown')}</span>
            </div>
        </div>
        
        <h3>Payload Details</h3>
        <pre>{finding['payload']}</pre>
        
        <div class="metadata">
            <p><strong>Description:</strong><br>
            {metadata.get('description', 'No description available.')}</p>
            
            <div class="browser-support">
                <strong>Browser Support:</strong><br>
                {metadata.get('browser_support', 'All modern browsers')}
            </div>
            
            <div class="injection-points">
                <strong>Injection Points:</strong><br>
                {self._format_injection_points(metadata.get('injection_points', []))}
            </div>
            
            <div class="mitigation">
                <strong>Recommended Mitigation:</strong><br>
                {metadata.get('mitigation', 'Implement proper input validation and output encoding.')}
            </div>
        </div>
        
        <h3>Analysis Results</h3>
        <pre>{json.dumps(finding['analysis'], indent=4)}</pre>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        filename = f'report_{self.timestamp}.html'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML report generated: {filename}{Style.RESET_ALL}")
        
    def generate_json_report(self):
        """Generate JSON report"""
        report = {
            'target_url': self.target_url,
            'timestamp': self.timestamp,
            'findings': self.findings
        }
        
        filename = f'report_{self.timestamp}.json'
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        print(f"{Fore.GREEN}[+] JSON report generated: {filename}{Style.RESET_ALL}")
        
    def print_summary(self):
        """Print summary of findings"""
        print(f"\n{Fore.CYAN}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Target URL: {self.target_url}")
        print(f"Total Findings: {len(self.findings)}")
        
        print("\nRisk Level Distribution:")
        for risk, count in self.vulnerability_stats.items():
            color = {
                'Critical': Fore.RED,
                'High': Fore.MAGENTA,
                'Medium': Fore.YELLOW,
                'Low': Fore.GREEN
            }[risk]
            print(f"{color}{risk}: {count}{Style.RESET_ALL}")
            
        print("\nInjection Points:")
        for point, count in self.injection_points.items():
            print(f"{Fore.CYAN}{point.replace('_', ' ').title()}: {count}{Style.RESET_ALL}")
            
        print(f"\nReports generated:")
        print(f"- report_{self.timestamp}.html")
        print(f"- report_{self.timestamp}.json")
