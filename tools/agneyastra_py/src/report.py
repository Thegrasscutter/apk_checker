"""
Report generation and management for Agneyastra.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional
from jinja2 import Template


class Report:
    """Thread-safe report management for Agneyastra results."""
    
    def __init__(self):
        self.api_keys: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def add_correlation_score(self, api_key: str, score: float) -> None:
        """Add correlation score for an API key."""
        with self._lock:
            api_key_report = self._get_or_create_api_key_report(api_key)
            api_key_report["correlation_score"] = score
    
    def add_secrets(self, api_key: str, service_type: str, secrets: Dict[str, List[str]]) -> None:
        """Add extracted secrets for an API key."""
        with self._lock:
            api_key_report = self._get_or_create_api_key_report(api_key)
            if "secrets" not in api_key_report:
                api_key_report["secrets"] = {}
            api_key_report["secrets"][service_type] = secrets

    def add_config(self, api_key: str, config: Dict[str, Any]) -> None:
        """Add configuration details for an API key."""
        with self._lock:
            api_key_report = self._get_or_create_api_key_report(api_key)
            api_key_report["config"] = config
    
    def add_service_report(self, api_key: str, service_name: str, sub_service_name: str, 
                          auth_result: Dict[str, Any], data: Dict[str, List[Dict[str, Any]]]) -> None:
        """Add service-specific report for an API key."""
        with self._lock:
            api_key_report = self._get_or_create_api_key_report(api_key)
            
            if service_name == "auth":
                if "auth" not in api_key_report:
                    api_key_report["auth"] = {}
                api_key_report["auth"][sub_service_name] = auth_result
            else:
                if "services" not in api_key_report:
                    api_key_report["services"] = {}
                if service_name not in api_key_report["services"]:
                    api_key_report["services"][service_name] = {}
                if sub_service_name not in api_key_report["services"][service_name]:
                    api_key_report["services"][service_name][sub_service_name] = {}
                
                # Merge data with existing results
                for bucket, results in data.items():
                    if bucket in api_key_report["services"][service_name][sub_service_name]:
                        # Merge with existing result
                        existing = api_key_report["services"][service_name][sub_service_name][bucket]
                        for result in results:
                            if (existing.get("Vulnerable") == "vulnerable:true" and 
                                result.get("Vulnerable") == "vulnerable:true"):
                                # Merge auth types if both are vulnerable
                                existing_auth = existing.get("AuthType", "")
                                new_auth = result.get("AuthType", "")
                                if new_auth and new_auth not in existing_auth:
                                    if existing_auth:
                                        existing["AuthType"] = f"{existing_auth},{new_auth}"
                                    else:
                                        existing["AuthType"] = new_auth
                            else:
                                # Replace with new result
                                api_key_report["services"][service_name][sub_service_name][bucket] = result
                    else:
                        # Add new result
                        if results:
                            api_key_report["services"][service_name][sub_service_name][bucket] = results[0]
    
    def _get_or_create_api_key_report(self, api_key: str) -> Dict[str, Any]:
        """Get or create an API key report entry."""
        for report in self.api_keys:
            if report["api_key"] == api_key:
                return report
        
        # Create new report
        new_report = {
            "api_key": api_key,
            "correlation_score": 0,
            "auth": {},
            "services": {},
            "secrets": None
        }
        self.api_keys.append(new_report)
        return new_report
    
    def to_json(self) -> str:
        """Convert report to JSON string."""
        with self._lock:
            report_data = {"api_keys": self.api_keys}
            return json.dumps(report_data, indent=2)
    
    async def generate_html_report(self, report_path: str, template_file: str) -> None:
        """Generate HTML report using template."""
        try:
            # Read template file
            template_path = Path(template_file) if template_file else None
            if not template_path or not template_path.exists():
                # Try Jinja2 template first
                template_path = Path(__file__).parent / "templates" / "template.html"
                
                
            
            if not template_path.exists():
                logging.warning("Template file not found, creating basic HTML report")
                await self._generate_basic_html_report(report_path)
                return
            
            with open(template_path, 'r') as f:
                template_content = f.read()
            
            # Create Jinja2 template
            template = Template(template_content)
            
            # Render template with report data
            from datetime import datetime
            with self._lock:
                html_content = template.render(
                    api_keys=self.api_keys,
                    report_data={"api_keys": self.api_keys},
                    date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # Write HTML file
            with open(report_path, 'w') as f:
                f.write(html_content)
            
            logging.info(f"HTML report generated: {report_path}")
            
        except Exception as e:
            logging.error(f"Error generating HTML report: {e}")
            await self._generate_basic_html_report(report_path)
    
    async def _generate_basic_html_report(self, report_path: str) -> None:
        """Generate a basic HTML report when template is not available."""
        basic_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Agneyastra Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .api-key {{ margin: 20px 0; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
        .vulnerable {{ color: #d9534f; font-weight: bold; }}
        .safe {{ color: #5cb85c; font-weight: bold; }}
        .error {{ color: #f0ad4e; font-weight: bold; }}
        .service {{ margin: 10px 0; }}
        .details {{ margin-left: 20px; font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Agneyastra Firebase Security Report</h1>
        <p>Generated by Agneyastra Python version</p>
    </div>
    
    {content}
</body>
</html>
        """
        
        content = ""
        with self._lock:
            for api_report in self.api_keys:
                api_key = api_report["api_key"]
                content += f'<div class="api-key">'
                content += f'<h2>API Key: {api_key[:10]}...</h2>'
                content += f'<p>Correlation Score: {api_report.get("correlation_score", 0)}</p>'
                
                # Auth results
                if "auth" in api_report:
                    content += '<h3>Authentication</h3>'
                    for auth_type, result in api_report["auth"].items():
                        status_class = self._get_status_class(result.get("Vulnerable", ""))
                        content += f'<div class="service">'
                        content += f'<strong>{auth_type}:</strong> <span class="{status_class}">{result.get("Vulnerable", "")}</span>'
                        if result.get("Error"):
                            content += f'<div class="details">Error: {result["Error"]}</div>'
                        content += '</div>'
                
                # Service results
                if "services" in api_report:
                    content += '<h3>Services</h3>'
                    for service_name, service_data in api_report["services"].items():
                        content += f'<h4>{service_name.title()}</h4>'
                        for sub_service, projects in service_data.items():
                            content += f'<h5>{sub_service.title()}</h5>'
                            for project_id, result in projects.items():
                                status_class = self._get_status_class(result.get("Vulnerable", ""))
                                content += f'<div class="service">'
                                content += f'<strong>{project_id}:</strong> <span class="{status_class}">{result.get("Vulnerable", "")}</span>'
                                if result.get("AuthType"):
                                    content += f' (Auth: {result["AuthType"]})'
                                if result.get("Error"):
                                    content += f'<div class="details">Error: {result["Error"]}</div>'
                                content += '</div>'
                
                content += '</div>'
        
        html_content = basic_template.format(content=content)
        
        with open(report_path, 'w') as f:
            f.write(html_content)
    
    def _get_status_class(self, status: str) -> str:
        """Get CSS class for vulnerability status."""
        if "vulnerable:true" in status:
            return "vulnerable"
        elif "vulnerable:false" in status:
            return "safe"
        else:
            return "error"