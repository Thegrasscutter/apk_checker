#!/usr/bin/env python3
"""
Android WebView Security Scanner
Scans decompiled APK smali files for vulnerable WebView configurations
"""

import os
import re
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# ANSI color codes
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

class WebViewScanner:
    def __init__(self, apk_path: str, output_dir: str = '/app'):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.log_file = os.path.join(output_dir, 'webview_scan_logs.txt')
        self.findings = defaultdict(list)
        self.webview_classes = {}
        
        # Initialize log file
        with open(self.log_file, 'w') as f:
            f.write("WebView Security Scanner - Scan Log\n")
            f.write("="*70 + "\n\n")
    
    def _log(self, message: str, color: str = ''):
        """Log message to both console and file"""
        # Print to console with color
        if color:
            print(f"{color}{message}{NC}")
        else:
            print(message)
        
        # Write to log file without color codes
        with open(self.log_file, 'a') as f:
            f.write(message + '\n')
        
    def scan(self):
        """Main scanning function"""
        self._log(f"[*] Scanning APK: {self.apk_path}")
        self._log("[*] Looking for WebView implementations...")
        
        # First pass: identify all WebView-related classes
        self._identify_webview_classes()
        
        # Second pass: analyze each WebView class
        for class_path, class_info in self.webview_classes.items():
            self._analyze_webview_class(class_path, class_info)
        
        # Generate report
        self._generate_report()
        
    def _identify_webview_classes(self):
        """Identify all classes that use WebView"""
        for root, dirs, files in os.walk(self.apk_path):
            for file in files:
                if file.endswith('.smali'):
                    filepath = os.path.join(root, file)
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Check if file contains WebView
                        if 'Landroid/webkit/WebView;' in content:
                            class_name = self._extract_class_name(content, filepath)
                            self.webview_classes[filepath] = {
                                'class_name': class_name,
                                'content': content,
                                'has_webview_field': False,
                                'issues': []
                            }
                    except Exception as e:
                        self._log(f"[-] Error reading {filepath}: {e}", YELLOW)
    
    def _extract_class_name(self, content: str, filepath: str) -> str:
        """Extract class name from smali file"""
        match = re.search(r'\.class\s+.*?\s+(L[^;]+;)', content)
        if match:
            return match.group(1).replace('/', '.')
        return os.path.basename(filepath).replace('.smali', '')
    
    def _analyze_webview_class(self, filepath: str, class_info: dict):
        """Analyze a WebView class for security issues"""
        content = class_info['content']
        class_name = class_info['class_name']
        
        self._log(f"\n[*] Analyzing: {class_name}")
        
        # Check for WebView field
        has_webview_field = self._check_webview_field(content)
        class_info['has_webview_field'] = has_webview_field
        
        if not has_webview_field:
            return
        
        # Security checks
        issues = []
        
        # 1. JavaScript Enabled
        js_enabled = self._check_javascript_enabled(content)
        if js_enabled:
            issues.append({
                'type': 'JavaScript Enabled',
                'severity': 'MEDIUM',
                'details': 'setJavaScriptEnabled(true) found'
            })
            self._log(f"    [!] JavaScript Enabled", RED)
        
        # 2. JavaScript Bridge Exposed
        js_bridge = self._check_javascript_bridge(content)
        if js_bridge:
            issues.append({
                'type': 'JavaScript Bridge Exposed',
                'severity': 'HIGH',
                'details': f'addJavascriptInterface found: {js_bridge}'
            })
            self._log(f"    [!] JavaScript Bridge: {js_bridge}", RED)
        
        # 3. URL Loading
        url_loading = self._check_url_loading(content)
        if url_loading:
            issues.append({
                'type': 'Loads URLs',
                'severity': 'INFO',
                'details': f'URL loading patterns: {url_loading}'
            })
            self._log(f"    [*] Loads URLs: {url_loading}")
        
        # 4. WebView NOT Destroyed
        not_destroyed = self._check_not_destroyed(content)
        if not_destroyed:
            issues.append({
                'type': 'WebView Not Destroyed',
                'severity': 'HIGH',
                'details': 'destroy() not called in lifecycle methods'
            })
            self._log(f"    [!] WebView NOT Destroyed", RED)
        
        # 5. WebView NOT Blanked
        not_blanked = self._check_not_blanked(content)
        if not_blanked:
            issues.append({
                'type': 'WebView Not Blanked',
                'severity': 'MEDIUM',
                'details': 'about:blank not loaded before destruction'
            })
            self._log(f"    [!] WebView NOT Blanked", RED)
        
        # 6. File Access Enabled
        file_access = self._check_file_access(content)
        if file_access:
            issues.append({
                'type': 'File Access Enabled',
                'severity': 'HIGH',
                'details': 'setAllowFileAccess(true) found'
            })
            self._log(f"    [!] File Access Enabled", RED)
        
        # 7. Geolocation Enabled
        geolocation = self._check_geolocation(content)
        if geolocation:
            issues.append({
                'type': 'Geolocation Enabled',
                'severity': 'MEDIUM',
                'details': 'setGeolocationEnabled(true) found'
            })
            self._log(f"    [!] Geolocation Enabled", RED)
        
        # 8. SSL Error Bypass
        ssl_bypass = self._check_ssl_bypass(content)
        if ssl_bypass:
            issues.append({
                'type': 'SSL Error Bypass',
                'severity': 'CRITICAL',
                'details': 'handler.proceed() found in onReceivedSslError'
            })
            self._log(f"    [!] SSL Error Bypass (CRITICAL)", RED)
        
        # 9. HTML Injection via loadData
        html_injection = self._check_html_injection(content)
        if html_injection:
            issues.append({
                'type': 'HTML Injection Risk',
                'severity': 'MEDIUM',
                'details': 'loadData with external HTML content'
            })
            self._log(f"    [!] HTML Injection Risk", RED)
        
        # Calculate overall severity
        severity = self._calculate_severity(issues)
        
        # Store findings
        if issues:
            self.findings['vulnerable_webviews'].append({
                'class': class_name,
                'file': filepath,
                'severity': severity,
                'issues': issues
            })
            
            # Categorize by severity
            if severity == 'CRITICAL':
                self.findings['critical'].append(class_name)
            elif severity == 'HIGH':
                self.findings['high'].append(class_name)
            elif severity == 'MEDIUM':
                self.findings['medium'].append(class_name)
    
    def _check_webview_field(self, content: str) -> bool:
        """Check if class has WebView field"""
        pattern = r'\.field\s+.*?Landroid/webkit/WebView;'
        return bool(re.search(pattern, content))
    
    def _check_javascript_enabled(self, content: str) -> bool:
        """Check if JavaScript is enabled"""
        # Look for setJavaScriptEnabled with true value
        pattern = r'setJavaScriptEnabled.*?\n.*?const/4.*?0x1'
        return bool(re.search(pattern, content, re.DOTALL))
    
    def _check_javascript_bridge(self, content: str) -> List[str]:
        """Check for JavaScript bridge exposure"""
        bridges = []
        
        # Look for addJavascriptInterface
        if 'addJavascriptInterface' in content:
            # Extract interface names
            interface_pattern = r'const-string\s+\w+,\s+"([^"]+)".*?addJavascriptInterface'
            matches = re.finditer(interface_pattern, content, re.DOTALL)
            for match in matches:
                bridges.append(match.group(1))
            
            # Also look for interface class names
            class_pattern = r'L[^;]+JavaScriptInterface;'
            class_matches = re.findall(class_pattern, content)
            bridges.extend([m.split('/')[-1].replace(';', '') for m in class_matches])
        
        return list(set(bridges)) if bridges else None
    
    def _check_url_loading(self, content: str) -> List[str]:
        """Check URL loading patterns"""
        patterns = []
        
        if 'loadUrl' in content:
            patterns.append('loadUrl')
        if 'loadData' in content:
            patterns.append('loadData')
        if 'loadDataWithBaseURL' in content:
            patterns.append('loadDataWithBaseURL')
        
        return patterns if patterns else None
    
    def _check_not_destroyed(self, content: str) -> bool:
        """Check if WebView is NOT destroyed"""
        has_lifecycle = bool(re.search(r'\.method.*?on(Destroy|Stop)', content))
        has_destroy_call = 'Landroid/webkit/WebView;->destroy()V' in content
        
        return has_lifecycle and not has_destroy_call
    
    def _check_not_blanked(self, content: str) -> bool:
        """Check if WebView is NOT blanked before destruction"""
        has_lifecycle = bool(re.search(r'\.method.*?on(Destroy|Stop)', content))
        has_blank = 'about:blank' in content
        
        return has_lifecycle and not has_blank
    
    def _check_file_access(self, content: str) -> bool:
        """Check if file access is enabled"""
        if 'setAllowFileAccess' not in content:
            return False
        
        # Check if set to true (const/4 v?, 0x1)
        pattern = r'setAllowFileAccess.*?\n.*?const/4.*?0x1'
        return bool(re.search(pattern, content, re.DOTALL))
    
    def _check_geolocation(self, content: str) -> bool:
        """Check if geolocation is enabled"""
        if 'setGeolocationEnabled' not in content:
            return False
        
        pattern = r'setGeolocationEnabled.*?\n.*?const/4.*?0x1'
        return bool(re.search(pattern, content, re.DOTALL))
    
    def _check_ssl_bypass(self, content: str) -> bool:
        """Check for SSL error bypass"""
        has_ssl_error = 'onReceivedSslError' in content
        has_proceed = 'Landroid/webkit/SslErrorHandler;->proceed()V' in content
        
        return has_ssl_error and has_proceed
    
    def _check_html_injection(self, content: str) -> bool:
        """Check for HTML injection via loadData"""
        if 'loadData' not in content:
            return False
        
        # Check if loading from external source (announcements, descriptions, etc)
        external_sources = ['getDescription', 'getContent', 'getHtml', 'PropertyAnnouncement']
        return any(source in content for source in external_sources)
    
    def _calculate_severity(self, issues: List[dict]) -> str:
        """Calculate overall severity based on issues"""
        severities = [issue['severity'] for issue in issues]
        
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_report(self):
        """Generate final report"""
        self._log("\n" + "="*70)
        self._log("WEBVIEW SECURITY SCAN REPORT")
        self._log("="*70)
        
        total_webviews = len(self.webview_classes)
        vulnerable = len(self.findings['vulnerable_webviews'])
        
        self._log(f"\n[*] Total WebView Classes: {total_webviews}")
        self._log(f"[*] Vulnerable WebViews: {vulnerable}")
        self._log(f"\n[!] Critical: {len(self.findings['critical'])}", RED)
        self._log(f"[!] High: {len(self.findings['high'])}", RED)
        self._log(f"[!] Medium: {len(self.findings['medium'])}", RED)
        
        # Critical findings
        if self.findings['critical']:
            self._log("\n" + "="*70)
            self._log("CRITICAL SEVERITY WEBVIEWS")
            self._log("="*70)
            for class_name in self.findings['critical']:
                self._log(f"\n  [!] {class_name}", RED)
                # Find details
                for vuln in self.findings['vulnerable_webviews']:
                    if vuln['class'] == class_name:
                        for issue in vuln['issues']:
                            self._log(f"      - {issue['type']}: {issue['details']}")
        
        # High findings
        if self.findings['high']:
            self._log("\n" + "="*70)
            self._log("HIGH SEVERITY WEBVIEWS")
            self._log("="*70)
            for class_name in self.findings['high']:
                self._log(f"\n  [!] {class_name}", RED)
                for vuln in self.findings['vulnerable_webviews']:
                    if vuln['class'] == class_name:
                        for issue in vuln['issues']:
                            if issue['severity'] in ['HIGH', 'CRITICAL']:
                                self._log(f"      - {issue['type']}: {issue['details']}")
        
        # Medium findings
        if self.findings['medium']:
            self._log("\n" + "="*70)
            self._log("MEDIUM SEVERITY WEBVIEWS")
            self._log("="*70)
            for class_name in self.findings['medium']:
                self._log(f"\n  [!] {class_name}", RED)
        
        # Non-blanked WebViews
        non_blanked = [v for v in self.findings['vulnerable_webviews'] 
                       if any(i['type'] == 'WebView Not Blanked' for i in v['issues'])]
        
        if non_blanked:
            self._log("\n" + "="*70)
            self._log("WEBVIEWS NOT BLANKED (Persistent JavaScript Risk)")
            self._log("="*70)
            for vuln in non_blanked:
                self._log(f"\n  [!] {vuln['class']}", RED)
                self._log(f"      File: {vuln['file']}")
        
        # Non-destroyed WebViews
        non_destroyed = [v for v in self.findings['vulnerable_webviews'] 
                         if any(i['type'] == 'WebView Not Destroyed' for i in v['issues'])]
        
        if non_destroyed:
            self._log("\n" + "="*70)
            self._log("WEBVIEWS NOT DESTROYED (Memory Leak + Persistent Execution)")
            self._log("="*70)
            for vuln in non_destroyed:
                self._log(f"\n  [!] {vuln['class']}", RED)
                self._log(f"      File: {vuln['file']}")
        
        # JavaScript Bridge exposed
        js_bridge_exposed = [v for v in self.findings['vulnerable_webviews'] 
                             if any(i['type'] == 'JavaScript Bridge Exposed' for i in v['issues'])]
        
        if js_bridge_exposed:
            self._log("\n" + "="*70)
            self._log("WEBVIEWS WITH JAVASCRIPT BRIDGE EXPOSED")
            self._log("="*70)
            for vuln in js_bridge_exposed:
                self._log(f"\n  [!] {vuln['class']}", RED)
                for issue in vuln['issues']:
                    if issue['type'] == 'JavaScript Bridge Exposed':
                        self._log(f"      Interfaces: {issue['details']}")
        
        # Save JSON report
        self._save_json_report()
        
        self._log("\n" + "="*70)
        self._log("[*] Scan complete!")
        self._log(f"[*] Detailed report saved to: {os.path.join(self.output_dir, 'webview_security_report.json')}")
        self._log(f"[*] Log file saved to: {self.log_file}")
        self._log("="*70 + "\n")
    
    def _save_json_report(self):
        """Save detailed JSON report"""
        report = {
            'summary': {
                'total_webviews': len(self.webview_classes),
                'vulnerable': len(self.findings['vulnerable_webviews']),
                'critical': len(self.findings['critical']),
                'high': len(self.findings['high']),
                'medium': len(self.findings['medium'])
            },
            'findings': self.findings['vulnerable_webviews'],
            'critical_classes': self.findings['critical'],
            'high_classes': self.findings['high'],
            'medium_classes': self.findings['medium']
        }
        
        json_path = os.path.join(self.output_dir, 'webview_security_report.json')
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also save detailed text report
        txt_path = os.path.join(self.output_dir, 'webview_security_report.txt')
        with open(txt_path, 'w') as f:
            f.write("ANDROID WEBVIEW SECURITY SCAN REPORT\n")
            f.write("="*70 + "\n\n")
            
            for vuln in self.findings['vulnerable_webviews']:
                f.write(f"\nClass: {vuln['class']}\n")
                f.write(f"Severity: {vuln['severity']}\n")
                f.write(f"File: {vuln['file']}\n")
                f.write(f"\nIssues:\n")
                for issue in vuln['issues']:
                    f.write(f"  [{issue['severity']}] {issue['type']}\n")
                    f.write(f"      {issue['details']}\n")
                f.write("\n" + "-"*70 + "\n")


def main():
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Android WebView Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with default output directory
  python3 webview_scanner.py /app/android_decompiled
  
  # Scan with custom output directory
  python3 webview_scanner.py /app/android_decompiled -o /custom/output
        """
    )
    
    parser.add_argument(
        'apk_path',
        help='Path to decompiled APK directory'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='/app',
        help='Output directory for reports and logs (default: /app)'
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.apk_path):
        print(f"{RED}[-] Error: Path does not exist: {args.apk_path}{NC}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    scanner = WebViewScanner(args.apk_path, args.output)
    scanner.scan()


if __name__ == '__main__':
    main()