"""
Storage Bucket service for Firebase security testing.
"""

import aiohttp
import asyncio
import logging
from typing import Dict, List, Any, Optional
from enum import Enum

from .credentials import CredentialStore
from .report import Report
from .utils import Utils


class Status(Enum):
    """Status enumeration for service checks."""
    VULNERABLE = "vulnerable:true"
    SAFE = "vulnerable:false"
    ERROR = "error"
    UNKNOWN = "vulnerable:unknown"


class BucketService:
    """Firebase Storage Bucket service security checker."""
    
    def __init__(self, api_key: str, project_ids: List[str], credential_store: CredentialStore, report: Report):
        self.api_key = api_key
        self.project_ids = project_ids
        self.credential_store = credential_store
        self.report = report
        self.utils = Utils()
    
    async def run_all_checks(self) -> None:
        """Run all bucket security checks."""
        logging.info("Running all Firebase bucket misconfiguration checks")
        
        # Run checks for each project
        for project_id in self.project_ids:
            await self._check_bucket_read(project_id)
            await self._check_bucket_write(project_id)
            await self._check_bucket_delete(project_id)
    
    async def _check_bucket_read(self, project_id: str) -> None:
        """Check if bucket allows unauthorized read access."""
        bucket_name = f"{project_id}.appspot.com"
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o"
        
        # Try with different authentication levels
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                headers = {}
                auth_type = "public"
                
                if cred_type != "public":
                    token = self.credential_store.get_token(cred_type)
                    if not token:
                        continue
                    headers["Authorization"] = f"Bearer {token}"
                    auth_type = cred_type
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Parse bucket contents
                            contents = await self._parse_bucket_contents(bucket_name, data, headers)
                            
                            vulnerability_config = ""
                            remedy = ""
                            
                            if auth_type == "public":
                                vulnerability_config = "allow read: if true; // Allows public read access to storage objects."
                                remedy = "Restrict to authenticated users: 'allow read: if request.auth != null;'."
                            else:
                                vulnerability_config = f"allow read: if request.auth == null; // Allows unauthenticated access to storage objects."
                                remedy = "Restrict to authenticated users: 'allow read: if request.auth != null;'."
                            
                            self.report.add_service_report(
                                self.api_key, "bucket", "read",
                                {}, {project_id: [{
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": auth_type,
                                    "VulnConfig": vulnerability_config,
                                    "Remedy": remedy,
                                    "Details": {
                                        "RequestURL": url,
                                        "Contents": contents
                                        }
                                }]}
                            )
                            logging.info(f"Bucket read access vulnerable for {project_id} with {auth_type}")
                            break
                        
                        elif response.status in [401, 403]:
                            # Continue to next auth type
                            continue
                        else:
                            # Safe - no read access
                            self.report.add_service_report(
                                self.api_key, "bucket", "read",
                                {}, {project_id: [{
                                    "Vulnerable": Status.SAFE.value,
                                    "Error": "",
                                    "AuthType": auth_type,
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {"Contents": {"prefixes": None, "items": None}}
                                }]}
                            )
                            break
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "bucket", "read",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking bucket read for {project_id}: {e}")
                break
    
    async def _check_bucket_write(self, project_id: str) -> None:
        """Check if bucket allows unauthorized write access."""
        bucket_name = f"{project_id}.appspot.com"
        test_filename = f"agneyastra_test_{self.utils.random_string(8)}.txt"
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o?name={test_filename}"
        
        test_data = b"Agneyastra security test file"
        
        # Try with different authentication levels
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                headers = {"Content-Type": "text/plain"}
                auth_type = "public"
                
                if cred_type != "public":
                    token = self.credential_store.get_token(cred_type)
                    if not token:
                        continue
                    headers["Authorization"] = f"Bearer {token}"
                    auth_type = cred_type
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=test_data, headers=headers) as response:
                        if response.status == 200:
                            vulnerability_config = ""
                            remedy = ""
                            
                            if auth_type == "public":
                                vulnerability_config = "allow write: if true; // Allows public write access to storage objects."
                                remedy = "Restrict to authenticated users: 'allow write: if request.auth != null;'."
                            else:
                                vulnerability_config = f"allow write: if request.auth == null; // Allows unauthenticated access to write storage objects."
                                remedy = "Restrict to authenticated users: 'allow write: if request.auth != null;'."
                            
                            self.report.add_service_report(
                                self.api_key, "bucket", "write",
                                {}, {project_id: [{
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": auth_type,
                                    "VulnConfig": vulnerability_config,
                                    "Remedy": remedy,
                                    "POC": f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{test_filename}?alt=media",
                                    "Details": {"status_code": str(response.status)}
                                }]}
                            )
                            logging.info(f"Bucket write access vulnerable for {project_id} with {auth_type}")
                            break
                        
                        elif response.status in [401, 403]:
                            continue
                        elif response.status == 404:
                            self.report.add_service_report(
                                self.api_key, "bucket", "write",
                                {}, {project_id: [{
                                    "Vulnerable": Status.UNKNOWN.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {
                                        "Attempted POC": f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{test_filename}?alt=media",
                                        "status_code": str(response.status)
                                        }
                                }]}
                            )
                            break
                        else:
                            self.report.add_service_report(
                                self.api_key, "bucket", "write",
                                {}, {project_id: [{
                                    "Vulnerable": Status.SAFE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {"status_code": str(response.status)}
                                }]}
                            )
                            break
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "bucket", "write",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Attempted POC": f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{test_filename}?alt=media",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking bucket write for {project_id}: {e}")
                break
    
    async def _check_bucket_delete(self, project_id: str) -> None:
        """Check if bucket allows unauthorized delete access."""
        bucket_name = f"{project_id}.appspot.com"
        test_filename = f"agneyastra_delete_test_{self.utils.random_string(8)}.txt"
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{test_filename}"
        
        # Try with different authentication levels
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                headers = {}
                auth_type = "public"
                
                if cred_type != "public":
                    token = self.credential_store.get_token(cred_type)
                    if not token:
                        continue
                    headers["Authorization"] = f"Bearer {token}"
                    auth_type = cred_type
                
                async with aiohttp.ClientSession() as session:
                    async with session.delete(url, headers=headers) as response:
                        if response.status in [200, 204, 404]:  # 404 means file doesn't exist but delete was allowed
                            vulnerability_config = ""
                            remedy = ""
                            
                            if auth_type == "public":
                                vulnerability_config = "allow delete: if true; // Allows public delete access to storage objects."
                                remedy = "Disable public delete access: 'allow delete: if false;'."
                            else:
                                vulnerability_config = f"allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects."
                                remedy = "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'."
                            
                            self.report.add_service_report(
                                self.api_key, "bucket", "delete",
                                {}, {project_id: [{
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": auth_type,
                                    "VulnConfig": vulnerability_config,
                                    "Remedy": remedy,
                                    "Details": {
                                        "RequestURL": f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{test_filename}?alt=media",
                                        "status_code": str(response.status)
                                        }
                                }]}
                            )
                            logging.info(f"Bucket delete access vulnerable for {project_id} with {auth_type}")
                            break
                        
                        elif response.status in [401, 403]:
                            continue
                        else:
                            self.report.add_service_report(
                                self.api_key, "bucket", "delete",
                                {}, {project_id: [{
                                    "Vulnerable": Status.SAFE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {"status_code": str(response.status)}
                                }]}
                            )
                            break
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "bucket", "delete",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "POC file deleted": f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{test_filename}?alt=media",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking bucket delete for {project_id}: {e}")
                break
    
    async def _parse_bucket_contents(self, bucket_name: str, data: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Parse and organize bucket contents recursively."""
        contents = {
            "prefixes": {},
            "items": []
        }
        
        # Parse items (files)
        items = data.get("items", [])
        for item in items:
            contents["items"].append({
                "name": item.get("name", ""),
                "bucket": bucket_name
            })
        
        # Parse prefixes (directories) 
        prefixes = data.get("prefixes", [])
        for prefix in prefixes:
            # Recursively get contents of subdirectories
            subdir_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o?prefix={prefix}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(subdir_url, headers=headers) as response:
                        if response.status == 200:
                            subdir_data = await response.json()
                            contents["prefixes"][prefix] = await self._parse_bucket_contents(bucket_name, subdir_data, headers)
            except Exception as e:
                logging.error(f"Error parsing subdirectory {prefix}: {e}")
                contents["prefixes"][prefix] = {"prefixes": {}, "items": []}
        
        return contents