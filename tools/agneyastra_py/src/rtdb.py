"""
Realtime Database service for Firebase security testing.
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


class RTDBService:
    """Firebase Realtime Database service security checker."""
    
    def __init__(self, api_key: str, project_ids: List[str], credential_store: CredentialStore, report: Report):
        self.api_key = api_key
        self.project_ids = project_ids
        self.credential_store = credential_store
        self.report = report
        self.utils = Utils()
    
    async def run_all_checks(self) -> None:
        """Run all Realtime Database security checks."""
        logging.info("Running all Firebase RTDB misconfiguration checks")
        
        for project_id in self.project_ids:
            await self._check_rtdb_read(project_id)
            await self._check_rtdb_write(project_id)
            await self._check_rtdb_delete(project_id)
    
    def _create_rtdb_url(self, project_id: str) -> str:
        """Create RTDB URL for the given project ID."""
        return f"https://{project_id}-default-rtdb.firebaseio.com"
    
    async def _check_rtdb_read(self, project_id: str) -> None:
        """Check if RTDB allows unauthorized read access."""
        base_url = self._create_rtdb_url(project_id)
        url = f"{base_url}/.json"
        
        # Try with different authentication levels
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                params = {}
                auth_type = "public"
                
                if cred_type != "public":
                    token = self.credential_store.get_token(cred_type)
                    if not token:
                        continue
                    params["auth"] = token
                    auth_type = cred_type
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params) as response:
                        if response.status == 200:
                            data = await response.text()
                            
                            # Check if we got actual data (not null)
                            if data and data.strip() != "null":
                                self.report.add_service_report(
                                    self.api_key, "rtdb", "read",
                                    {}, {project_id: [{
                                        "Vulnerable": Status.VULNERABLE.value,
                                        "Error": "",
                                        "AuthType": auth_type,
                                        "VulnConfig": "allow read: if request.auth == null; // Allows unauthenticated access to read database.",
                                        "Remedy": "Restrict to authenticated users: 'allow read: if request.auth != null;'.",
                                        "Details": {
                                            "rtdb_url": url,
                                            "status_code": str(response.status)
                                        }
                                    }]}
                                )
                                logging.info(f"RTDB read access vulnerable for {project_id} with {auth_type}")
                                break
                        
                        elif response.status in [401, 403]:
                            # Continue to next auth type
                            continue
                        else:
                            # Safe - no read access
                            self.report.add_service_report(
                                self.api_key, "rtdb", "read",
                                {}, {project_id: [{
                                    "Vulnerable": Status.SAFE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {
                                        "rtdb_url": url,
                                        "status_code": ""
                                    }
                                }]}
                            )
                            break
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "rtdb", "read",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking RTDB read for {project_id}: {e}")
                break
    
    async def _check_rtdb_write(self, project_id: str) -> None:
        """Check if RTDB allows unauthorized write access."""
        base_url = self._create_rtdb_url(project_id)
        test_key = f"agneyastrapoc{self.utils.random_string(6)}"
        url = f"{base_url}/{test_key}.json"
        
        test_data = {"test": "agneyastra_security_test", "timestamp": "2024-01-01"}
        
        # Try with different authentication levels
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                params = {}
                auth_type = "public"
                
                if cred_type != "public":
                    token = self.credential_store.get_token(cred_type)
                    if not token:
                        continue
                    params["auth"] = token
                    auth_type = cred_type
                
                async with aiohttp.ClientSession() as session:
                    async with session.put(url, json=test_data, params=params) as response:
                        if response.status == 200:
                            self.report.add_service_report(
                                self.api_key, "rtdb", "write",
                                {}, {project_id: [{
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": auth_type,
                                    "VulnConfig": "allow write: if request.auth == null; // Allows unauthenticated access to write database.",
                                    "Remedy": "Restrict to authenticated users: 'allow write: if request.auth != null;'.",
                                    "Details": {
                                        "rtdb_url": url,
                                        "status_code": str(response.status)
                                    }
                                }]}
                            )
                            logging.info(f"RTDB write access vulnerable for {project_id} with {auth_type}")
                            break
                        
                        elif response.status in [401, 403]:
                            continue
                        else:
                            self.report.add_service_report(
                                self.api_key, "rtdb", "write",
                                {}, {project_id: [{
                                    "Vulnerable": Status.SAFE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {
                                        "rtdb_url": url,
                                        "status_code": ""
                                    }
                                }]}
                            )
                            break
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "rtdb", "write",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking RTDB write for {project_id}: {e}")
                break
    
    async def _check_rtdb_delete(self, project_id: str) -> None:
        """Check if RTDB allows unauthorized delete access."""
        base_url = self._create_rtdb_url(project_id)
        test_key = f"agneyastrapoc{self.utils.random_string(6)}"
        url = f"{base_url}/{test_key}.json"
        
        # Try with different authentication levels
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                params = {}
                auth_type = "public"
                
                if cred_type != "public":
                    token = self.credential_store.get_token(cred_type)
                    if not token:
                        continue
                    params["auth"] = token
                    auth_type = cred_type
                
                async with aiohttp.ClientSession() as session:
                    async with session.delete(url, params=params) as response:
                        if response.status in [200, 404]:  # 404 means path doesn't exist but delete was allowed
                            self.report.add_service_report(
                                self.api_key, "rtdb", "delete",
                                {}, {project_id: [{
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": auth_type,
                                    "VulnConfig": "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
                                    "Remedy": "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'.",
                                    "Details": {
                                        "rtdb_url": url,
                                        "status_code": str(response.status)
                                    }
                                }]}
                            )
                            logging.info(f"RTDB delete access vulnerable for {project_id} with {auth_type}")
                            break
                        
                        elif response.status in [401, 403]:
                            continue
                        else:
                            self.report.add_service_report(
                                self.api_key, "rtdb", "delete",
                                {}, {project_id: [{
                                    "Vulnerable": Status.SAFE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "",
                                    "Details": {
                                        "rtdb_url": url,
                                        "status_code": str(response.status)
                                    }
                                }]}
                            )
                            break
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "rtdb", "delete",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking RTDB delete for {project_id}: {e}")
                break