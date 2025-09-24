#!/usr/bin/env python3
"""
Agneyastra - A Firebase Misconfiguration Detection Tool (Python Version)

Firebase security testing tool that detects misconfigurations in:
- Authentication services
- Storage Buckets
- Firestore databases
- Realtime Database

Original Go version by: Bhavarth Karmarkar
Python port maintains the same functionality and API compatibility.
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from src.auth import AuthService
from src.bucket import BucketService
from src.config import Config, load_config
from src.correlation import CorrelationEngine
from src.credentials import CredentialStore
from src.firestore import FirestoreService
from src.report import Report
from src.rtdb import RTDBService
from src.secrets import SecretsExtractor
from src.utils import Utils
from enum import Enum

class Status(Enum):
            """Status enumeration for service checks."""
            VULNERABLE = "vulnerable:true"
            SAFE = "vulnerable:false"
            ERROR = "error"
            UNKNOWN = "vulnerable:unknown"

class Agneyastra:
    """Main Agneyastra application class."""
    
    def __init__(self):
        self.config = Config()
        self.credential_store = CredentialStore()
        self.report = Report()
        self.utils = Utils()
        
    async def run(self, args: argparse.Namespace) -> None:
        """Main entry point for the application."""
        try:
            await self.utils.ensure_config_files()
            # Initialize configuration
            await self._initialize_config(args)
            
            # Process API keys and project configs
            await self._process_api_keys(args)
            
            # Run the requested services
            if args.all:
                await self._run_all_services()
            else:
                await self._run_specific_services(args)
                
            # Post-processing
            if args.correlate and args.pentest_data:
                await self._run_correlation(args.pentest_data)
                
            if args.secrets_extract:
                await self._extract_secrets()
                
            # Generate reports
            await self._generate_reports(args)
            
        except Exception as e:
            logging.error(f"Error during execution: {e}")
            sys.exit(1)
    
    async def _initialize_config(self, args: argparse.Namespace) -> None:
        """Initialize configuration from files and arguments."""
        if args.config:
            config_data = load_config(args.config)
            self.config.update(config_data)
        else:
            # Try to load default config
            config_path = Path.home() / ".config" / "agneyastra" / "config.yaml"
            if config_path.exists():
                config_data = load_config(str(config_path))
                self.config.update(config_data)
        
        # Set debug mode
        if args.debug:
            logging.basicConfig(level=logging.DEBUG)
            self.config.debug = True
        else:
            logging.basicConfig(level=logging.INFO)
    
    async def _process_api_keys(self, args: argparse.Namespace) -> None:
        """Process API keys and fetch project configurations."""
        
        # Get API keys
        if args.key:
            self.config.api_keys = [args.key]
            if args.project_id:
                project_ids = [pid.strip() for pid in args.project_id.split(",") if pid.strip()]
                self.config.project_ids[args.key] = project_ids
        elif args.key_file:
            api_keys, project_ids_map = await self.utils.read_api_keys_from_file(args.key_file)
            self.config.api_keys = api_keys
            self.config.project_ids.update(project_ids_map)
        else:
            raise ValueError("API key is required. Use --key or --key_file")
        
        # Fetch project configurations
        for api_key in self.config.api_keys:
            try:
                project_config = await self.utils.get_project_config(api_key)
                self.config.project_configs[api_key] = project_config
                
                if api_key not in self.config.project_ids or not self.config.project_ids[api_key]:
                    # Extract project IDs from config if not provided
                    domains, authorized_domains = self.utils.extract_domains_from_project_config(project_config)
                    self.config.project_ids[api_key] = domains
                    if "localhost" in authorized_domains:
                        self.report.add_config(
                            api_key,
                            {
                                "domains": {
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "Localhost domain detected, should be removed in production",
                                    "Details": {
                                        "Domains": project_config
                                    }
                                }
                            }
                        )
                    else:
                        self.report.add_config(
                            api_key,
                            {
                                "domains": {
                                    "Vulnerable": Status.UNKNOWN.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "Check authorized domains for misconfigurations",
                                    "Details": {
                                        "Domains": project_config
                                    }
                                }
                            }
                        )
                logging.info(f"Processed API key: {api_key[:10]}...")
                
            except Exception as e:
                logging.error(f"Error processing API key {api_key[:10]}...: {e}")
                continue
    
    async def _run_all_services(self) -> None:
        """Run all Firebase service checks."""
        logging.info("Checking all services for misconfigurations")
        
        tasks = []
        for api_key in self.config.api_keys:
            project_ids = self.config.project_ids.get(api_key, [])
            
            # Auth service
            auth_service = AuthService(api_key, self.credential_store, self.report)
            tasks.append(auth_service.run_all_checks())
            
            # Bucket service
            bucket_service = BucketService(api_key, project_ids, self.credential_store, self.report)
            tasks.append(bucket_service.run_all_checks())
            
            # Firestore service
            firestore_service = FirestoreService(api_key, project_ids, self.credential_store, self.report)
            tasks.append(firestore_service.run_all_checks())
            
            # RTDB service
            rtdb_service = RTDBService(api_key, project_ids, self.credential_store, self.report)
            tasks.append(rtdb_service.run_all_checks())
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_specific_services(self, args: argparse.Namespace) -> None:
        """Run specific service checks based on arguments."""
        # This would be expanded based on subcommands
        # For now, just run all if no specific service is specified
        if not any([args.auth, args.bucket, args.firestore, args.rtdb]):
            await self._run_all_services()
    
    async def _run_correlation(self, pentest_data_file: str) -> None:
        """Run correlation analysis."""
        logging.info("Running correlation analysis...")
        correlation_engine = CorrelationEngine()
        
        for api_key in self.config.api_keys:
            score = await correlation_engine.calculate_score(api_key, pentest_data_file)
            self.report.add_correlation_score(api_key, score)
    
    async def _extract_secrets(self) -> None:
        """Extract secrets from collected data."""
        logging.info("Extracting secrets...")
        secrets_extractor = SecretsExtractor()
        
        for api_key in self.config.api_keys:
            secrets = await secrets_extractor.extract_from_api_data(api_key, self.report)
            if secrets:
                self.report.add_secrets(api_key, "extracted", secrets)
    
    async def _generate_reports(self, args: argparse.Namespace) -> None:
        """Generate and output reports."""
        # JSON report to stdout
        json_report = self.report.to_json()
        print(json_report)
        
        # HTML report if requested
        if args.report_path:
            template_file = args.template_file or str(Path.home() / ".config" / "agneyastra" / "template.html")
            await self.report.generate_html_report(args.report_path, template_file)
            logging.info(f"HTML report generated: {args.report_path}")


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Agneyastra - Firebase Misconfiguration Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python agneyastra.py --key YOUR_API_KEY --all
  
  # Service specific scan
  python agneyastra.py --key YOUR_API_KEY --bucket
  
  # With correlation and secrets extraction
  python agneyastra.py --key YOUR_API_KEY --all --correlate --pentest-data data.json --secrets-extract
        """
    )
    
    # Core arguments
    parser.add_argument("--key", help="Firebase API key")
    parser.add_argument("--key_file", help="Path to file containing Firebase API keys")
    parser.add_argument("--project_id", help="Firebase project ID (comma-separated for multiple)")
    
    # Service selection
    parser.add_argument("--all", "-a", action="store_true", 
                       help="Check all misconfigurations in all services")
    parser.add_argument("--auth", action="store_true", help="Check authentication service")
    parser.add_argument("--bucket", action="store_true", help="Check storage buckets")
    parser.add_argument("--firestore", action="store_true", help="Check Firestore database")
    parser.add_argument("--rtdb", action="store_true", help="Check Realtime Database")
    
    # Configuration
    parser.add_argument("--config", help="Custom config file path")
    parser.add_argument("--debug", "-d", action="store_true", 
                       help="Enable debug mode for detailed logging")
    
    # Analysis options
    parser.add_argument("--correlate", action="store_true", 
                       help="Run correlation analysis")
    parser.add_argument("--pentest_data", help="Path to pentest data file for correlation")
    parser.add_argument("--secrets_extract", action="store_true", 
                       help="Extract secrets from collected data")
    #parser.add_argument("--assets_extract", action="store_true", #Fix
    #                   help="Extract assets (domains, IPs, emails) from collected data")
    
    # Output options
    parser.add_argument("--report_path", default="./report.html", 
                       help="Path to store HTML report (default: ./report.html)")
    parser.add_argument("--template_file", 
                       help="Template file for HTML report")
    #parser.add_argument("--secrets_regex_file", 
    #                   help="Path to file containing secrets regexes")
    
    return parser


async def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.key and not args.key_file:
        parser.error("API key is required. Use --key or --key_file")
    
    app = Agneyastra()
    await app.run(args)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)