"""
Utility functions for Agneyastra.
"""

import aiohttp
import asyncio
import json
import random
import string
from pathlib import Path
from typing import Dict, List, Tuple, Any
import os
import logging


class Utils:
    """Utility functions for the Agneyastra application."""
    
    @staticmethod
    def random_string(length: int) -> str:
        """Generate a random string of specified length."""
        charset = string.ascii_letters + string.digits
        return ''.join(random.choice(charset) for _ in range(length))
    
    async def read_api_keys_from_file(self, file_path: str) -> Tuple[List[str], Dict[str, List[str]]]:
        """Read API keys and project IDs from file."""
        api_keys = []
        project_map = {}
        
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        parts = [part.strip() for part in line.split(',') if part.strip()]
                        if parts:
                            api_key = parts[0]
                            api_keys.append(api_key)
                            
                            # Map API key to project IDs if provided
                            if len(parts) > 1:
                                project_map[api_key] = parts[1:]
                            else:
                                project_map[api_key] = []
        except Exception as e:
            raise ValueError(f"Error reading API keys file: {e}")
        
        return api_keys, project_map
    
    async def get_project_config(self, api_key: str) -> Dict[str, Any]:
        """Fetch Firebase project configuration using API key."""
        url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={api_key}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise ValueError(f"Failed to fetch project config, status: {response.status}")
                    
                    return await response.json()
            except Exception as e:
                raise ValueError(f"Error fetching project config: {e}")
    
    def extract_domains_from_project_config(self, config: Dict[str, Any]) -> List[str]:
        """Extract domain names from project configuration."""
        domains = []
        domain_set = set()
        
        # Add project ID first
        project_id = config.get("projectId", "")
        if project_id:
            domains.append(project_id)
            domain_set.add(project_id)
        
        # Extract from authorized domains
        authorized_domains = config.get("authorizedDomains", [])

        
        for domain in authorized_domains:
            if domain.endswith(".firebaseapp.com") or domain.endswith(".web.app"):
                subdomain = domain.split(".")[0]
                if subdomain not in domain_set:
                    domains.append(subdomain)
                    domain_set.add(subdomain)
        
        
        return domains, authorized_domains
    
    async def download_file(self, url: str, file_path: Path) -> None:
        """Download a file from URL to specified path."""
        if file_path.exists():
            logging.info(f"File already exists: {file_path}")
            return
        
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise ValueError(f"Failed to download file, status: {response.status}")
                    
                    content = await response.read()
                    with open(file_path, 'wb') as file:
                        file.write(content)
                    
                    logging.info(f"Downloaded file: {file_path}")
            except Exception as e:
                raise ValueError(f"Error downloading file: {e}")
    
    async def ensure_config_files(self) -> None:
        """Ensure required configuration files exist."""
        config_dir = Path.home() / ".config" / "agneyastra"
        print(f"Ensuring config directory exists at {config_dir}")
        # Download default config if it doesn't exist
        config_file = config_dir / "config.yaml"
        if not config_file.exists():
            try:
                os.system("cp ./src/templates/config.yaml " + str(config_file))
            except:
                os.system("cp $PWD/agneyastra_py/src/templates/config.yaml " + str(config_file))


        # Download default template if it doesn't exist
        template_file = config_dir / "template.html"
        if not template_file.exists():
            try:
                os.system("cp ./src/templates/template.html " + str(template_file))
            except:
                os.system("cp $PWD/agneyastra_py/src/templates/template.html " + str(template_file))
