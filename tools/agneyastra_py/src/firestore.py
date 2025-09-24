"""
Firestore service for Firebase security testing.
"""

import aiohttp
import asyncio
import json
import logging
import re
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


class FirestoreService:
    """Firebase Firestore service security checker."""
    
    def __init__(self, api_key: str, project_ids: List[str], credential_store: CredentialStore, report: Report):
        self.api_key = api_key
        self.project_ids = project_ids
        self.credential_store = credential_store
        self.report = report
        self.utils = Utils()
    
    async def run_all_checks(self) -> None:
        """Run all Firestore security checks."""
        logging.info("Running all Firebase Firestore misconfiguration checks")
        
        for project_id in self.project_ids:
            await self._check_firestore_write(project_id)
            await self._check_firestore_read(project_id)
            await self._check_firestore_delete(project_id)
    
    async def _check_firestore_write(self, project_id: str) -> None:
        """Check if Firestore allows unauthorized write access."""
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                auth_token = None
                auth_type = "public"
                
                if cred_type != "public":
                    auth_token = self.credential_store.get_token(cred_type)
                    if not auth_token:
                        continue
                    auth_type = cred_type
                
                # Step 1: Initialize Firestore connection
                session_info = await self._initialize_firestore_session(project_id, auth_token)
                if not session_info:
                    continue
                
                # Step 2: Get stream token
                stream_token = await self._get_stream_token(project_id, session_info, auth_token)
                if not stream_token:
                    continue
                
                # Step 3: Attempt to write document
                success, doc_id = await self._write_document(project_id, session_info, stream_token, auth_token)
                
                if success:
                    self.report.add_service_report(
                        self.api_key, "firestore", "write",
                        {}, {project_id: [{
                            "Vulnerable": Status.VULNERABLE.value,
                            "Error": "",
                            "AuthType": auth_type,
                            "VulnConfig": "allow write: if request.auth == null; // Allows unauthenticated access to write storage objects.",
                            "Remedy": "Restrict to authenticated users: 'allow write: if request.auth != null;'.",
                            "POC Document ID": doc_id,
                            "Details": None
                        }]}
                    )
                    logging.info(f"Firestore write vulnerable for {project_id} with {auth_type}")
                    break
                else:
                    self.report.add_service_report(
                        self.api_key, "firestore", "write",
                        {}, {project_id: [{
                            "Vulnerable": Status.SAFE.value,
                            "Error": "",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }]}
                    )
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "firestore", "write",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking Firestore write for {project_id}: {e}")
                break
    
    async def _check_firestore_read(self, project_id: str) -> None:
        """Check if Firestore allows unauthorized read access."""
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                auth_token = None
                auth_type = "public"
                
                if cred_type != "public":
                    auth_token = self.credential_store.get_token(cred_type)
                    if not auth_token:
                        continue
                    auth_type = cred_type
                
                # Attempt to read from Firestore
                success, url = await self._read_document(project_id, auth_token)
                
                if success:
                    self.report.add_service_report(
                        self.api_key, "firestore", "read",
                        {}, {project_id: [{
                            "Vulnerable": Status.VULNERABLE.value,
                            "Error": "",
                            "AuthType": auth_type,
                            "VulnConfig": "allow read: if request.auth == null; // Allows unauthenticated access to read storage objects.",
                            "Remedy": "Restrict to authenticated users: 'allow read: if request.auth != null;'.",
                            "POC URL": url,
                            "Details": None
                        }]}
                    )
                    logging.info(f"Firestore read vulnerable for {project_id} with {auth_type}")
                    break
                else:
                    self.report.add_service_report(
                        self.api_key, "firestore", "read",
                        {}, {project_id: [{
                            "Vulnerable": Status.SAFE.value,
                            "Error": "",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }]}
                    )
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "firestore", "read",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking Firestore read for {project_id}: {e}")
                break
    
    async def _check_firestore_delete(self, project_id: str) -> None:
        """Check if Firestore allows unauthorized delete access."""
        for cred_type in self.credential_store.CRED_TYPES:
            try:
                auth_token = None
                auth_type = "public"
                
                if cred_type != "public":
                    auth_token = self.credential_store.get_token(cred_type)
                    if not auth_token:
                        continue
                    auth_type = cred_type
                
                # Step 1: Initialize Firestore connection
                session_info = await self._initialize_firestore_session(project_id, auth_token)
                if not session_info:
                    continue
                
                # Step 2: Get stream token
                stream_token = await self._get_stream_token(project_id, session_info, auth_token)
                if not stream_token:
                    continue
                
                # Step 3: Attempt to delete document
                success, doc_id = await self._delete_document(project_id, session_info, stream_token, auth_token)
                
                if success:
                    self.report.add_service_report(
                        self.api_key, "firestore", "delete",
                        {}, {project_id: [{
                            "Vulnerable": Status.VULNERABLE.value,
                            "Error": "",
                            "AuthType": auth_type,
                            "VulnConfig": "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
                            "Remedy": "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'.",
                            "POC Document ID Deleted": doc_id,
                            "Details": None
                        }]}
                    )
                    logging.info(f"Firestore delete vulnerable for {project_id} with {auth_type}")
                    break
                else:
                    self.report.add_service_report(
                        self.api_key, "firestore", "delete",
                        {}, {project_id: [{
                            "Vulnerable": Status.SAFE.value,
                            "Error": "",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }]}
                    )
            
            except Exception as e:
                self.report.add_service_report(
                    self.api_key, "firestore", "delete",
                    {}, {project_id: [{
                        "Vulnerable": Status.ERROR.value,
                        "Error": str(e),
                        "AuthType": "",
                        "VulnConfig": "",
                        "Remedy": "",
                        "Attempted Deletion of Document ID": doc_id if 'doc_id' in locals() else "",
                        "Details": None
                    }]}
                )
                logging.error(f"Error checking Firestore delete for {project_id}: {e}")
                break
    
    async def _initialize_firestore_session(self, project_id: str, auth_token: Optional[str]) -> Optional[Dict[str, str]]:
        """Initialize a Firestore session and extract session information."""
        url = f"https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel"
        params = {
            "VER": "8",
            "database": f"projects%2F{project_id}%2Fdatabases%2F(default)",
            "RID": "33570",
            "CVER": "22",
            "X-HTTP-Session-Id": "gsessionid",
            "zx": "7dl3c7vkmrvq",
            "t": "1"
        }
        
        data = f"headers=X-Goog-Api-Client:gl-js/%20fire/11.0.0%0D%0AContent-Type:text/plain%0D%0AX-Firebase-GMPID:111%0D%0A&count=1&ofs=0&req0___data__=%7B%22database%22:%22projects/{project_id}/databases/(default)%22%7D"
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, params=params, data=data, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        gsessionid = response.headers.get("x-http-session-id")
                        
                        # Extract SID from response
                        sid_match = re.search(r'\["c","(.*?)",""', body)
                        if sid_match and gsessionid:
                            return {
                                "gsessionid": gsessionid,
                                "sid": sid_match.group(1)
                            }
        except Exception as e:
            logging.error(f"Error initializing Firestore session: {e}")
        
        return None
    
    async def _get_stream_token(self, project_id: str, session_info: Dict[str, str], auth_token: Optional[str]) -> Optional[str]:
        """Get stream token for Firestore operations."""
        url = f"https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel"
        params = {
            "gsessionid": session_info["gsessionid"],
            "VER": "8", 
            "database": f"projects%2F{project_id}%2Fdatabases%2F(default)",
            "RID": "rpc",
            "SID": session_info["sid"],
            "AID": "0",
            "CI": "0",
            "TYPE": "xmlhttp",
            "zx": "cs7qqy879ulh",
            "t": "1"
        }
        
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        # Read response line by line looking for stream token
                        async for line in response.content:
                            line_str = line.decode('utf-8', errors='ignore')
                            
                            # Check for permission denied
                            if re.search(r'Missing or insufficient permissions\.|Permission denied on resource|"status":"PERMISSION_DENIED"', line_str):
                                return None
                            
                            # Look for stream token
                            token_match = re.search(r'"streamToken":\s*"(.*?)"', line_str)
                            if token_match:
                                return token_match.group(1)
        except Exception as e:
            logging.error(f"Error getting stream token: {e}")
        
        return None
    
    async def _write_document(self, project_id: str, session_info: Dict[str, str], stream_token: str, auth_token: Optional[str]) -> bool:
        """Attempt to write a document to Firestore."""
        doc_id = f"agneyastratestpoc{self.utils.random_string(6)}"
        
        url = f"https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel"
        params = {
            "VER": "8",
            "database": f"projects%2F{project_id}%2Fdatabases%2F(default)",
            "gsessionid": session_info["gsessionid"],
            "SID": session_info["sid"],
            "RID": "33571",
            "AID": "1",
            "zx": "79no8op6xwvi",
            "t": "1"
        }
        
        payload = self.utils.random_string(10)
        data = f'count=1&ofs=1&req0___data__={{"streamToken":"{stream_token}","writes":[{{"update":{{"name":"projects/{project_id}/databases/(default)/documents/agneyastra/{doc_id}","fields":{{"poc":{{"stringValue":"{payload}"}}}}}},"currentDocument":{{"exists":false}}}}]}}'
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*"
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, params=params, data=data, headers=headers) as response:
                    return response.status == 200, doc_id
        except Exception as e:
            logging.error(f"Error writing document: {e}")
            return False
    
    async def _read_document(self, project_id: str, auth_token: Optional[str]) -> bool:
        """Attempt to read a document from Firestore."""
        item_id = f"agneyastratestpoc{self.utils.random_string(6)}"
        
        # Simplified read test - this is a basic implementation
        # The actual Go version uses a more complex streaming protocol
        url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/agneyastratest/{item_id}"
        
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    # If we can read without errors, it's vulnerable
                    return response.status != 403, url
        except Exception as e:
            logging.error(f"Error reading document: {e}")
            return False
    
    async def _delete_document(self, project_id: str, session_info: Dict[str, str], stream_token: str, auth_token: Optional[str]) -> bool:
        """Attempt to delete a document from Firestore."""
        doc_id = f"agneyastratestpoc{self.utils.random_string(6)}"
        
        url = f"https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel"
        params = {
            "VER": "8",
            "database": f"projects%2F{project_id}%2Fdatabases%2F(default)",
            "gsessionid": session_info["gsessionid"],
            "SID": session_info["sid"],
            "RID": "33571",
            "AID": "1",
            "zx": "79no8op6xwvi",
            "t": "1"
        }
        
        data = f'count=1&ofs=1&req0___data__={{"streamToken":"{stream_token}","writes":[{{"delete":"projects/{project_id}/databases/(default)/documents/poc/{doc_id}"}}]}}'
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*"
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, params=params, data=data, headers=headers) as response:
                    return response.status == 200, doc_id
        except Exception as e:
            logging.error(f"Error deleting document: {e}")
            return False