"""
Secrets extraction from collected Firebase data.
"""

import re
import logging
from typing import Dict, List, Any, Pattern
from pathlib import Path

from .report import Report


class SecretsExtractor:
    """Extract secrets and sensitive information from Firebase data."""
    
    def __init__(self, custom_regex_file: str = None):
        self.patterns = self._load_default_patterns()
        
        if custom_regex_file:
            self.patterns.update(self._load_custom_patterns(custom_regex_file))
    
    def _load_default_patterns(self) -> Dict[str, Pattern]:
        """Load default regex patterns for common secrets."""
        patterns = {
            "api_keys": re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?'),
            "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "aws_secret_key": re.compile(r'(?i)(aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'),
            "google_api_key": re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
            "slack_token": re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
            "github_token": re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            "jwt_token": re.compile(r'eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*'),
            "email_addresses": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'),
            "phone_numbers": re.compile(r'\\+?1?[\\s.-]?\\(?[0-9]{3}\\)?[\\s.-]?[0-9]{3}[\\s.-]?[0-9]{4}'),
            "credit_card": re.compile(r'\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b'),
            "social_security": re.compile(r'\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b'),
            "database_url": re.compile(r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*["\']?([a-zA-Z0-9.-]+://[^\\s\'"]+)["\']?'),
            "private_key": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
        }
        
        return patterns
    
    def _load_custom_patterns(self, regex_file: str) -> Dict[str, Pattern]:
        """Load custom regex patterns from file."""
        patterns = {}
        
        try:
            with open(regex_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            name, pattern = parts
                            try:
                                patterns[name.strip()] = re.compile(pattern.strip())
                            except re.error as e:
                                logging.warning(f"Invalid regex pattern '{name}': {e}")
        except Exception as e:
            logging.error(f"Error loading custom regex file: {e}")
        
        return patterns
    
    async def extract_from_api_data(self, api_key: str, report: Report) -> Dict[str, List[str]]:
        """Extract secrets from collected API data."""
        secrets = {}
        
        # Extract from report data
        with report._lock:
            for api_report in report.api_keys:
                if api_report["api_key"] == api_key:
                    secrets.update(await self._extract_from_report_data(api_report))
                    break
        
        return secrets
    
    async def _extract_from_report_data(self, api_report: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract secrets from a single API report."""
        secrets = {}
        
        # Convert report to string for pattern matching
        report_text = self._flatten_report_to_text(api_report)
        
        # Apply all patterns
        for secret_type, pattern in self.patterns.items():
            matches = pattern.findall(report_text)
            if matches:
                # Handle different regex group patterns
                if isinstance(matches[0], tuple):
                    # Pattern has groups, take the last group (usually the secret value)
                    secrets[secret_type] = [match[-1] for match in matches if match[-1]]
                else:
                    # Pattern has no groups, take the full match
                    secrets[secret_type] = list(set(matches))
        
        return secrets
    
    def _flatten_report_to_text(self, data: Any, depth: int = 0) -> str:
        """Recursively flatten report data to searchable text."""
        if depth > 10:  # Prevent infinite recursion
            return ""
        
        text = ""
        
        if isinstance(data, dict):
            for key, value in data.items():
                text += f"{key} "
                text += self._flatten_report_to_text(value, depth + 1)
        elif isinstance(data, list):
            for item in data:
                text += self._flatten_report_to_text(item, depth + 1)
        elif isinstance(data, (str, int, float)):
            text += f"{data} "
        
        return text
    
    async def extract_from_bucket_contents(self, bucket_contents: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract secrets from bucket contents."""
        secrets = {}
        
        # Extract file names and analyze them
        file_names = self._extract_file_names(bucket_contents)
        all_text = " ".join(file_names)
        
        # Apply patterns to file names and paths
        for secret_type, pattern in self.patterns.items():
            matches = pattern.findall(all_text)
            if matches:
                if isinstance(matches[0], tuple):
                    secrets[secret_type] = [match[-1] for match in matches if match[-1]]
                else:
                    secrets[secret_type] = list(set(matches))
        
        return secrets
    
    def _extract_file_names(self, contents: Dict[str, Any], names: List[str] = None) -> List[str]:
        """Recursively extract file names from bucket contents."""
        if names is None:
            names = []
        
        # Extract items (files)
        items = contents.get("items", [])
        for item in items:
            if isinstance(item, dict) and "name" in item:
                names.append(item["name"])
        
        # Extract from prefixes (directories)
        prefixes = contents.get("prefixes", {})
        if isinstance(prefixes, dict):
            for prefix_name, prefix_contents in prefixes.items():
                names.append(prefix_name)
                if isinstance(prefix_contents, dict):
                    self._extract_file_names(prefix_contents, names)
        
        return names