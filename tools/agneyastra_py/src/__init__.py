"""
Agneyastra Python package initialization.
"""

__version__ = "1.0.0"
__author__ = "Python port of Agneyastra by Bhavarth Karmarkar"
__description__ = "Firebase Misconfiguration Detection Tool"

from .auth import AuthService
from .bucket import BucketService
from .config import Config, load_config
from .correlation import CorrelationEngine
from .credentials import CredentialStore
from .firestore import FirestoreService
from .report import Report
from .rtdb import RTDBService
from .secrets import SecretsExtractor
from .utils import Utils

__all__ = [
    "AuthService",
    "BucketService", 
    "Config",
    "CorrelationEngine",
    "CredentialStore",
    "FirestoreService",
    "Report",
    "RTDBService",
    "SecretsExtractor",
    "Utils",
    "load_config"
]