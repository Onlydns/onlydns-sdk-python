"""OnlyDNS Python SDK.

Official Python SDK for managing DNS zones and records with onlydns.com.
Designed for high developer utility and seamless AI agent tool-calling integration.
"""

from .client import OnlyDNSClient
from .config import (
    clear_config,
    get_api_key,
    get_config_dir,
    get_config_file_path,
    load_config,
    save_config,
    set_api_key,
)
from .exceptions import (
    OnlyDNSError,
    AuthenticationError,
    NotFoundError,
    APIError,
    ValidationError,
)
from .models import (
    DNSRecord,
    RecordType,
    TsigKey,
    TsigAlgorithm,
    TsigKeyCreateResponse,
    DomainTsigPermissions,
    DNSSECKeyAlgorithm,
    DNSSECKeyDigestType,
    DNSSECDsKey,
    DNSSECStatus,
    DNSDnssecStatusResponse,
    ErrorResponse,
)

__all__ = [
    "OnlyDNSClient",
    "clear_config",
    "get_api_key",
    "get_config_dir",
    "get_config_file_path",
    "load_config",
    "save_config",
    "set_api_key",
    "OnlyDNSError",
    "AuthenticationError",
    "NotFoundError",
    "APIError",
    "ValidationError",
    "DNSRecord",
    "RecordType",
    "TsigKey",
    "TsigAlgorithm",
    "TsigKeyCreateResponse",
    "DomainTsigPermissions",
    "DNSSECKeyAlgorithm",
    "DNSSECKeyDigestType",
    "DNSSECDsKey",
    "DNSSECStatus",
    "DNSDnssecStatusResponse",
    "ErrorResponse",
]

__version__ = "1.0.0"
