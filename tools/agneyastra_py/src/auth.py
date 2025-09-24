"""
Authentication service for Firebase security testing.
"""

import aiohttp
import json
import logging
from typing import Dict, Any, Optional, Tuple
from enum import Enum

from .credentials import CredentialStore
from .report import Report


class Status(Enum):
    """Status enumeration for service checks."""
    VULNERABLE = "vulnerable:true"
    SAFE = "vulnerable:false"
    ERROR = "error"
    UNKNOWN = "vulnerable:unknown"


class AuthService:
    """Firebase Authentication service security checker."""
    
    def __init__(self, api_key: str, credential_store: CredentialStore, report: Report):
        self.api_key = api_key
        self.credential_store = credential_store
        self.report = report
    
    async def run_all_checks(self) -> None:
        """Run all authentication security checks."""
        # Anonymous authentication
        await self._check_anonymous_auth()
        
        # Custom token login
        await self._check_custom_token_login()
        
        # Send sign-in link
        await self._check_send_signin_link()
        
        # Email/password signup
        await self._check_email_password_signup()
        
        # Email/password signin
        await self._check_email_password_signin()
    
    async def _check_anonymous_auth(self) -> None:
        """Check if anonymous authentication is enabled."""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        
        payload = {
            "returnSecureToken": True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("idToken"):
                            # Store the token for later use
                            self.credential_store.set_token("anon", data["idToken"])
                            
                            self.report.add_service_report(
                                self.api_key, "auth", "anon-auth",
                                {
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "",
                                    "Remedy": "Disable Anonymous Authentication",
                                    "Details": {
                                        "RequestURL": url,
                                        "RequestPayload": json.dumps(payload),
                                        "expiresIn": data.get("expiresIn", ""),
                                        "idToken": "redacted",
                                        "localId": data.get("localId", ""),
                                        "refreshToken": "redacted"
                                    }
                                }, {}
                            )
                            logging.info("Anonymous authentication is vulnerable")
                            return
                    
                    self.report.add_service_report(
                        self.api_key, "auth", "anon-auth",
                        {
                            "Vulnerable": Status.SAFE.value,
                            "Error": "",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }, {}
                    )
                    
        except Exception as e:
            self.report.add_service_report(
                self.api_key, "auth", "anon-auth",
                {
                    "Vulnerable": Status.ERROR.value,
                    "Error": str(e),
                    "AuthType": "",
                    "VulnConfig": "",
                    "Remedy": "",
                    "Details": None
                }, {}
            )
            logging.error(f"Error checking anonymous auth: {e}")
    
    async def _check_custom_token_login(self) -> None:
        """Check if custom token login is enabled."""
        # This would require a custom token to be provided in config
        # For now, we'll simulate the check with empty token
        
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={self.api_key}"
        
        payload = {
            "token": "",  # This would come from config
            "returnSecureToken": True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("idToken"):
                            self.credential_store.set_token("custom", data["idToken"])
                            
                            self.report.add_service_report(
                                self.api_key, "auth", "custom-token-login",
                                {
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "Custom token authentication enabled",
                                    "Remedy": "Validate custom token implementation",
                                    "Details": {
                                        "RequestURL": url,
                                        "RequestPayload": json.dumps(payload),
                                        "token_valid": True
                                        }
                                }, {}
                            )
                            return
                    
                    self.report.add_service_report(
                        self.api_key, "auth", "custom-token-login",
                        {
                            "Vulnerable": Status.ERROR.value,
                            "Error": f"failed to log in with custom token, status code: {response.status}",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }, {}
                    )
                    
        except Exception as e:
            self.report.add_service_report(
                self.api_key, "auth", "custom-token-login",
                {
                    "Vulnerable": Status.ERROR.value,
                    "Error": str(e),
                    "AuthType": "",
                    "VulnConfig": "",
                    "Remedy": "",
                    "Details": None
                }, {}
            )
    
    async def _check_send_signin_link(self) -> None:
        """Check if send sign-in link is enabled."""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={self.api_key}"
        
        payload = {
            "requestType": "EMAIL_SIGNIN",
            "email": "test@example.com",  # This should come from config
            "continueUrl": "http://localhost:8888/completeAuth",
            "canHandleCodeInApp": True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("kind") and data.get("email"):
                            self.report.add_service_report(
                                self.api_key, "auth", "send-signin-link",
                                {
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "Send Sign in Link enabled in Firebase project.",
                                    "Remedy": "Disable Send Sign in Link from Firebase Console",
                                    "Details": {
                                        "RequestURL": url,
                                        "RequestPayload": json.dumps(payload),
                                        "email": data.get("email")
                                        }
                                }, {}
                            )
                            logging.info(f"Sign-in link sent to email: {data.get('email')}")
                            return
                    
                    self.report.add_service_report(
                        self.api_key, "auth", "send-signin-link",
                        {
                            "Vulnerable": Status.SAFE.value,
                            "Error": "",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }, {}
                    )
                    
        except Exception as e:
            self.report.add_service_report(
                self.api_key, "auth", "send-signin-link",
                {
                    "Vulnerable": Status.ERROR.value,
                    "Error": str(e),
                    "AuthType": "",
                    "VulnConfig": "",
                    "Remedy": "",
                    "Details": None
                }, {}
            )
    
    async def _check_email_password_signup(self) -> None:
        """Check if email/password signup is enabled."""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        
        payload = {
            "email": "",  # This should come from config
            "password": "",  # This should come from config
            "returnSecureToken": True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("idToken"):
                            self.credential_store.set_token("signup", data["idToken"])
                            
                            self.report.add_service_report(
                                self.api_key, "auth", "signup",
                                {
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "Email/Password signup enabled",
                                    "Remedy": "Disable email/password signup or add proper validation",
                                    "Details": {
                                        "RequestURL": url,
                                        "RequestPayload": json.dumps({"email": email, "password": "redacted", "returnSecureToken": True}),
                                        "signup_enabled": True
                                        }
                                }, {}
                            )
                            return
                    
                    self.report.add_service_report(
                        self.api_key, "auth", "signup",
                        {
                            "Vulnerable": Status.ERROR.value,
                            "Error": f"failed to sign up with email/password, status code: {response.status}",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }, {}
                    )
                    
        except Exception as e:
            self.report.add_service_report(
                self.api_key, "auth", "signup",
                {
                    "Vulnerable": Status.ERROR.value,
                    "Error": str(e),
                    "AuthType": "",
                    "VulnConfig": "",
                    "Remedy": "",
                    "Details": None
                }, {}
            )
    
    async def _check_email_password_signin(self) -> None:
        """Check if email/password signin is enabled."""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.api_key}"
        
        payload = {
            "email": "",  # This should come from config
            "password": "",  # This should come from config  
            "returnSecureToken": True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("idToken"):
                            self.credential_store.set_token("user_credentials", data["idToken"])
                            
                            self.report.add_service_report(
                                self.api_key, "auth", "signin",
                                {
                                    "Vulnerable": Status.VULNERABLE.value,
                                    "Error": "",
                                    "AuthType": "",
                                    "VulnConfig": "Email/Password signin enabled",
                                    "Remedy": "Ensure proper authentication validation",
                                    "Details": {
                                        "RequestURL": url,
                                        "RequestPayload": json.dumps({"email": email, "password": "redacted", "returnSecureToken": True}),
                                        "signin_enabled": True
                                        }
                                }, {}
                            )
                            return
                    
                    self.report.add_service_report(
                        self.api_key, "auth", "signin",
                        {
                            "Vulnerable": Status.SAFE.value,
                            "Error": "",
                            "AuthType": "",
                            "VulnConfig": "",
                            "Remedy": "",
                            "Details": None
                        }, {}
                    )
                    
        except Exception as e:
            self.report.add_service_report(
                self.api_key, "auth", "signin",
                {
                    "Vulnerable": Status.ERROR.value,
                    "Error": str(e),
                    "AuthType": "",
                    "VulnConfig": "",
                    "Remedy": "",
                    "Details": None
                }, {}
            )