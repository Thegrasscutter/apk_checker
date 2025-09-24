"""
Credential store for managing authentication tokens.
"""

from typing import Dict, List, Optional
import threading


class CredentialStore:
    """Thread-safe credential store for managing authentication tokens."""
    
    # Credential types in order of privilege escalation
    CRED_TYPES = ["public", "anon", "signup", "user_credentials", "custom"]
    
    def __init__(self):
        self._tokens: Dict[str, str] = {}
        self._lock = threading.Lock()
    
    def set_token(self, cred_type: str, token: str) -> None:
        """Set a token for a specific credential type."""
        with self._lock:
            self._tokens[cred_type] = token
    
    def get_token(self, cred_type: str) -> Optional[str]:
        """Get a token for a specific credential type."""
        with self._lock:
            return self._tokens.get(cred_type)
    
    def get_all_tokens(self) -> Dict[str, str]:
        """Get all stored tokens."""
        with self._lock:
            return self._tokens.copy()
    
    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        with self._lock:
            self._tokens.clear()
    
    def has_token(self, cred_type: str) -> bool:
        """Check if a token exists for the given credential type."""
        with self._lock:
            return cred_type in self._tokens and bool(self._tokens[cred_type])
    
    def get_available_cred_types(self) -> List[str]:
        """Get list of credential types that have tokens."""
        with self._lock:
            return [cred_type for cred_type in self.CRED_TYPES 
                   if cred_type in self._tokens and self._tokens[cred_type]]