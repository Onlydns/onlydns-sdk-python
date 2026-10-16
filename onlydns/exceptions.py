"""Exceptions for OnlyDNS SDK."""

from typing import List, Optional


class OnlyDNSError(Exception):
    """Base exception for all OnlyDNS SDK errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[List[str]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or []

    def __str__(self) -> str:
        if self.status_code:
            base = f"[{self.status_code}] {self.message}"
        else:
            base = self.message
        if self.details:
            base += f" - Details: {'; '.join(self.details)}"
        return base


class AuthenticationError(OnlyDNSError):
    """Raised when authentication fails (HTTP 401)."""
    pass


class NotFoundError(OnlyDNSError):
    """Raised when a resource is not found (HTTP 404)."""
    pass


class ValidationError(OnlyDNSError):
    """Raised when input parameters fail validation (HTTP 400)."""
    pass


class APIError(OnlyDNSError):
    """Raised when the OnlyDNS API returns a server or unexpected error (e.g. HTTP 503)."""
    pass
