"""
ASL V6 CORE — Autonomous Bug Bounty Hunter (Working Core)
==========================================================
A streamlined, dependency-free version that demonstrates the core vulnerability hunting capabilities.
This version works without external dependencies and focuses on the essential functionality.
"""

import sys
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add paths for imports
_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(_ROOT / "src"))
sys.path.append(str(_ROOT / "v2"))

# Simple console class for output
class SimpleConsole:
    def print(self, *args, **kwargs):
        print(*args)
    
    def rule(self, title=""):
        print(f"\n{'='*60}")
        if title:
            print(f" {title} ")
            print('='*60)
    
    def print_panel(self, content, title="", style=""):
        print(f"\n{title}")
        print("-" * len(title))
        print(content)
        print()

console = SimpleConsole()

class VulnerabilityScanner:
    """Core vulnerability scanning engine"""
    
    def __init__(self):
        self.timeout = 10
        self.user_agent = "ASL-V6-BountyHunter/1.0"
        
    def fetch_url(self, url: str) -> Optional[dict]:
        """Fetch a URL and return response data"""
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': self.user_agent}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read().decode('utf-8', errors='ignore')
                return {
                    'status': response.getcode(),
                    'headers': dict(response.getheaders()),
                    'content': content[:50000],  # Limit size
                    'url': url
                }
        except Exception as e:
            return {
                'status': 0,
                'error': str(e),
                'content': '',
                'headers': {},
                'url': url
            }
    
    def reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform reconnaissance on the target"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        console.print(f"[RECON] Starting reconnaissance on {target}")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'headers': {},
            'cookies': [],
            'interesting_paths': [],
            'tech_stack': [],
            'apis': [],
            'js_files': [],
            'subdomains': [],
            'raw_data': ''
        }
        
        # Get main page
        main_response = self.fetch_url(target)
        if not main_response or 'error' in main_response:
            console.print(f"[ERROR] Could not fetch {target}")
            return results
            
        results['headers'] = main_response.get('headers', {})
        results['content'] = main_response.get('content', '')
        results['status'] = main_response.get('status', 0)
        
        # Extract cookies
        set_cookie = results['headers'].get('Set-Cookie', '')
        if isinstance(set_cookie, str):
            results['cookies'] = [c.strip() for c in set_cookie.split(',') if c.strip()]
        
        # Technology detection
        tech_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Drupal': ['sites/all', 'modules/', 'themes/'],
            'Joomla': ['administrator/', 'components/', 'modules/'],
            'Shopify': ['Shopify', 'myshopify.com'],
            'Magento': ['/skin/', '/js/', '/app/'],
            'Laravel': ['laravel_session', 'X-Powered-By: Laravel'],
            'Django': ['csrftoken', 'sessionid'],
            'React': ['react', '__PRELOADED_STATE__'],
            'Vue.js': ['vue', '__VUE__'],
            'Angular': ['ng-version', 'angular'],
        }
        
        content_lower = results['content'].lower()
        headers_str = str(results['headers']).lower()
        
        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator in content_lower or indicator in headers_str:
                    results['tech_stack'].append(tech)
                    break
        
        # Find interesting paths
        common_paths = [
            '/.env', '/.git/config', '/.git/HEAD', '/robots.txt', '/sitemap.xml',
            '/admin/', '/admin/login', '/dashboard/', '/wp-admin/', '/wp-login.php',
            '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/backup.sql', '/database.sql', '/dump.sql', '/db.sql',
            '/config.php', '/settings.py', '/config.js', '/config.json',
            '/web.config', '/.htaccess', '/.htpasswd',
            '/swagger-ui/', '/swagger.json', '/api-docs/', '/openapi.json',
            '/actuator/', '/actuator/env', '/actuator/health',
            '/console/', '/shell/', '/bash/', '/cmd/', '/terminal/'
        ]
        
        for path in common_paths:
            test_url = urllib.parse.urljoin(target, path)
            response = self.fetch_url(test_url)
            if response and response.get('status') in [200, 201, 204, 301, 302, 401, 403]:
                results['interesting_paths'].append({
                    'path': path,
                    'status': response.get('status'),
                    'size': len(response.get('content', '')),
                    'url': test_url
                })
                if response.get('status') == 200:
                    results['raw_data'] += f"[FOUND] {path} -> {response.get('status')}\n"
        
        # Find API endpoints
        api_patterns = [
            r'/api/v\d+/[\w/-]+',
            r'/rest/[\w/-]+',
            r'/services/[\w/-]+',
            r'/wp-json/wp/v2/[\w/-]+',
            r'/graphql'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, results['content'], re.IGNORECASE)
            for match in matches:
                if match not in results['apis']:
                    results['apis'].append(match)
        
        # Find JavaScript files
        js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
        js_matches = re.findall(js_pattern, results['content'], re.IGNORECASE)
        for js_file in js_matches[:10]:  # Limit to first 10
            if js_file.startswith('http'):
                full_url = js_file
            else:
                full_url = urllib.parse.urljoin(target, js_file)
            results['js_files'].append({
                'url': full_url,
                'path': js_file
            })
        
        # Basic subdomain enumeration (common ones)
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.netloc
        
        common_subs = ['www', 'api', 'dev', 'staging', 'test', 'admin', 'portal', 'app', 'mail']
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            test_url = f"{parsed.scheme}://{subdomain}"
            response = self.fetch_url(test_url)
            if response and response and response.get('status') in [200, 301, 302, 401, 403]:
                results['subdomains'].append(subdomain)
                results['raw_data'] += f"[SUBDOMAIN] {subdomain}\n"
        
        return results
    
    def analyze_for_vulnerabilities(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze reconnaissance data for potential vulnerabilities"""
        vulnerabilities = []
        
        # Check for sensitive file exposure
        sensitive_files = ['/.env', '/.git/config', '/phpinfo.php', '/info.php', 
                          '/debug.php', '/test.php', '/backup.sql', '/database.sql']
        
        for path_info in recon_data.get('interesting_paths', []):
            path = path_info.get('path', '')
            status = path_info.get('status', 0)
            
            if status == 200 and path in sensitive_files:
                vuln = {
                    'title': f'Sensitive File Exposure: {path}',
                    'description': f'The file {path} is publicly accessible, potentially exposing sensitive information.',
                    'severity': 'High' if 'env' in path or 'git' in path else 'Medium',
                    'cvss_score': 7.5 if 'env' in path or 'git' in path else 5.5,
                    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' if 'env' in path or 'git' in path else 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                    'endpoint': path,
                    'method': 'GET',
                    'poc_payload': f'Simply visit {recon_data["target"]}{path} in your browser or with curl',
                    'expected_response': '200 OK with file contents',
                    'bounty_tier': '$200 - $800' if 'env' in path or 'git' in path else '$100 - $400',
                    'remediation': f'Restrict access to {path} via server configuration or remove the file from production.',
                    'cwe_id': 'CWE-200' if 'env' in path or 'git' in path else 'CWE-538',
                    'references': ['https://cwe.mitre.org/data/definitions/200.html', 'https://cwe.mitre.org/data/definitions/538.html']
                }
                vulnerabilities.append(vuln)
        
        # Check for debug endpoints
        debug_endpoints = ['/debug', '/console', '/shell', '/cmd', '/terminal', '/phpinfo.php']
        for path_info in recon_data.get('interesting_paths', []):
            path = path_info.get('path', '')
            if any(debug in path for debug in debug_endpoints) and path_info.get('status') == 200:
                vuln = {
                    'title': f'Debug Endpoint Exposure: {path}',
                    'description': f'A debug or administrative endpoint ({path}) is exposed, potentially revealing sensitive information or allowing command execution.',
                    'severity': 'High',
                    'cvss_score': 8.0,
                    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                    'endpoint': path,
                    'method': 'GET',
                    'poc_payload': f'Visit {recon_data["target"]}{path} to access the debug interface',
                    'expected_response': '200 OK with debug interface or information',
                    'bounty_tier': '$300 - $1000',
                    'remediation': 'Disable or remove debug endpoints in production environments.',
                    'cwe_id': 'CWE-497',
                    'references': ['https://cwe.mitre.org/data/definitions/497.html']
                }
                vulnerabilities.append(vuln)
        
        # Check for missing security headers
        headers = {k.lower(): v for k, v in recon_data.get('headers', {}).items()}
        security_headers = {
            'strict-transport-security': 'HSTS missing',
            'content-security-policy': 'CSP missing',
            'x-frame-options': 'X-Frame-Options missing (clickjacking risk)',
            'x-content-type-options': 'X-Content-Type-Options missing',
            'x-xss-protection': 'X-XSS-Protection missing',
            'referrer-policy': 'Referrer-Policy missing'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                vuln = {
                    'title': f'Missing Security Header: {header.replace("-", " ").title()}',
                    'description': f'The {header} security header is not present, which could lead to various client-side vulnerabilities.',
                    'severity': 'Low' if header in ['x-xss-protection', 'referrer-policy'] else 'Medium',
                    'cvss_score': 4.0 if header in ['x-xss-protection', 'referrer-policy'] else 5.5,
                    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                    'endpoint': '/',
                    'method': 'GET',
                    'poc_payload': 'Check response headers for missing security headers',
                    'expected_response': 'Response should include security headers',
                    'bounty_tier': '$50 - $200',
                    'remediation': f'Add the {header} header to HTTP responses with appropriate values.',
                    'cwe_id': 'CWE-693',
                    'references': ['https://cwe.mitre.org/data/definitions/693.html']
                }
                vulnerabilities.append(vuln)
        
        # Check for directory listing
        for path_info in recon_data.get('interesting_paths', []):
            path = path_info.get('path', '')
            if path.endswith('/') and path_info.get('status') == 200:
                content = path_info.get('content', '').lower()
                if 'index of' in content or 'directory listing' in content:
                    vuln = {
                        'title': f'Directory Listing Enabled: {path}',
                        'description': f'The web server is displaying directory listings for {path}, potentially exposing sensitive files.',
                        'severity': 'Medium',
                        'cvss_score': 6.5,
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                        'endpoint': path,
                        'method': 'GET',
                        'poc_payload': f'Visit {recon_data["target"]}{path} to see directory listing',
                        'expected_response': '200 OK with directory listing',
                        'bounty_tier': '$150 - $500',
                        'remediation': 'Disable directory listing in web server configuration.',
                        'cwe_id': 'CWE-548',
                        'references': ['https://cwe.mitre.org/data/definitions/548.html']
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def generate_report(self, target: str, recon_data: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate a formatted security report"""
        report_lines = [
            "=" * 80,
            "ASL V6 AUTONOMOUS BOUNTY HUNTER - SECURITY ASSESSMENT REPORT",
            "=" * 80,
            f"Target: {target}",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Scanner: ASL V6 Engine",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"Target scanned: {target}",
            f"Total findings: {len(vulnerabilities)}",
            f"High risk: {len([v for v in vulnerabilities if v['severity'] == 'High'])}",
            f"Medium risk: {len([v for v in vulnerabilities if v['severity'] == 'Medium'])}",
            f"Low risk: {len([v for v in vulnerabilities if v['severity'] == 'Low'])}",
            "",
            "ASSET DISCOVERY",
            "-" * 40,
            f"Technologies detected: {', '.join(set(recon_data.get('tech_stack', []))) or 'None identified'}",
            f"Subdomains found: {len(recon_data.get('subdomains', []))}",
            f"Interesting paths: {len([p for p in recon_data.get('interesting_paths', []) if p.get('status') == 200])}",
            f"API endpoints discovered: {len(recon_data.get('apis', []))}",
            "",
            "VULNERABILITY FINDINGS",
            "-" * 40
        ]
        
        if not vulnerabilities:
            report_lines.append("No vulnerabilities detected during this scan.")
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                report_lines.extend([
                    f"{i}. {vuln['title']} [{vuln['severity']}]",
                    f"   CVSS Score: {vuln['cvss_score']} ({vuln['cvss_vector']})",
                    f"   Endpoint: {vuln['endpoint']} ({vuln['method']})",
                    f"   Description: {vuln['description']}",
                    f"   Proof of Concept: {vuln['poc_payload']}",
                    f"   Expected Result: {vuln['expected_response']}",
                    f"   Bounty Estimate: {vuln['bounty_tier']}",
                    f"   Fix: {vuln['remediation']}",
                    f"   CWE: {vuln['cwe_id']}",
                    "",
                    "   " + "-" * 50,
                    ""
                ])
        
        report_lines.extend([
            "",
            "RECOMMENDATIONS",
            "-" * 40,
            "1. Address all High and Medium severity findings immediately",
            "2. Implement a Web Application Firewall (WAF) for additional protection",
            "3. Conduct regular security scanning and penetration testing",
            "4. Keep all software and dependencies up to date",
            "5. Implement proper input validation and output encoding",
            "",
            "NOTE: This report was generated by the ASL V6 Autonomous Bug Hunter.",
            "For more information, visit: https://github.com/asl-security/asl-engine",
            "=" * 80
        ])
        
        return "\n".join(report_lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python v6_bounty_hunter.py <target_url>")
        print("Example: python v6_bounty_hunter.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = VulnerabilityScanner()
    
    console.rule("ASL V6 AUTONOMOUS BOUNTY HUNTER")
    console.print(f"Target: {target}")
    console.print("Starting security assessment...\n")
    
    # Phase 1: Reconnaissance
    recon_data = scanner.reconnaissance(target)
    
    if 'error' in recon_data and recon_data['error']:
        console.print(f"[ERROR] Reconnaissance failed: {recon_data['error']}")
        sys.exit(1)
    
    # Show recon summary
    console.print(f"[RECON] Found {len(recon_data.get('tech_stack', []))} technologies")
    console.print(f"[RECON] Discovered {len([p for p in recon_data.get('interesting_paths', []) if p.get('status') == 200])} accessible endpoints")
    console.print(f"[RECON] Identified {len(recon_data.get('subdomains', []))} subdomains")
    console.print(f"[RECON] Found {len(recon_data.get('apis', []))} potential API endpoints\n")
    
    # Phase 2: Vulnerability Analysis
    vulnerabilities = scanner.analyze_for_vulnerabilities(recon_data)
    
    # Sort by severity (High > Medium > Low)
    severity_order = {'High': 3, 'Medium': 2, 'Low': 1}
    vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
    
    # Generate and display report
    report = scanner.generate_report(target, recon_data, vulnerabilities)
    print(report)
    
    # Save report to file
    safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"ASL_V6_Report_{safe_target}_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(report)
        print(f"\n[SAVE] Report saved to: {filename}")
    except Exception as e:
        print(f"\n[WARNING] Could not save report: {e}")

if __name__ == "__main__":
    main()