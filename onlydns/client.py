"""Client implementation for OnlyDNS API."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Union

from .config import get_api_key, load_config
from .exceptions import (
    APIError,
    AuthenticationError,
    NotFoundError,
    OnlyDNSError,
    ValidationError,
)
from .models import (
    DNSRecord,
    DNSSECStatus,
    DomainTsigPermissions,
    RecordType,
    TsigAlgorithm,
    TsigKey,
)


class OnlyDNSClient:
    """Client for interacting with OnlyDNS REST API.

    Designed for human developers and autonomous AI agents.
    Provides direct API mappings and high-level atomic helper methods.
    """

    DEFAULT_BASE_URL = "https://api.onlydns.com/v1"

    def __init__(
        self,
        api_token: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """Initialize OnlyDNSClient.

        Args:
            api_token: OnlyDNS API bearer token. If omitted, checks
                       `ONLYDNS_API_KEY` or `ONLYDNS_API_TOKEN` environment variables,
                       or stored credentials in `~/.config/onlydns/config.json`.
            base_url: Base API URL (defaults to https://api.onlydns.com/v1).
            timeout: HTTP request timeout in seconds.
        """
        token = api_token or get_api_key()
        if not token:
            raise AuthenticationError(
                "API token is required. Pass api_token, set ONLYDNS_API_KEY environment variable, "
                "or configure it with `onlydns config set-key <KEY>`."
            )
        resolved_base_url = (
            base_url
            or os.environ.get("ONLYDNS_BASE_URL")
            or load_config().get("base_url")
            or self.DEFAULT_BASE_URL
        )
        self.api_token = token
        self.base_url = resolved_base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
    ) -> Any:
        """Send HTTP request to OnlyDNS API and parse response."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            filtered_params = {k: v for k, v in params.items() if v is not None}
            if filtered_params:
                url += f"?{urllib.parse.urlencode(filtered_params)}"

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "User-Agent": "OnlyDNS-Python-SDK/1.0.0",
        }

        data_bytes = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data_bytes = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            url=url,
            data=data_bytes,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                resp_bytes = response.read()
                if status == 204 or not resp_bytes:
                    return None
                try:
                    return json.loads(resp_bytes.decode("utf-8"))
                except json.JSONDecodeError:
                    return resp_bytes.decode("utf-8")
        except urllib.error.HTTPError as e:
            status = e.code
            error_details = []
            error_title = ""
            try:
                err_data = json.loads(e.read().decode("utf-8"))
                if isinstance(err_data, dict):
                    error_title = err_data.get("title", "")
                    desc = err_data.get("description", [])
                    if isinstance(desc, list):
                        error_details = desc
                    elif isinstance(desc, str):
                        error_details = [desc]
            except Exception:
                pass

            msg = error_title or f"HTTP {status} {e.reason}"
            if status == 400:
                raise ValidationError(msg, status_code=status, details=error_details) from e
            elif status == 401:
                raise AuthenticationError(msg or "Access token is missing or invalid", status_code=status, details=error_details) from e
            elif status == 404:
                raise NotFoundError(msg or "Resource not found", status_code=status, details=error_details) from e
            else:
                raise APIError(msg, status_code=status, details=error_details) from e
        except urllib.error.URLError as e:
            raise OnlyDNSError(f"Network error: {e.reason}") from e

    # --------------------------------------------------------------------------
    # Domain & Record API Methods
    # --------------------------------------------------------------------------

    def create_domain(self, domain: str) -> None:
        """Create a new DNS domain.

        Args:
            domain: Domain name to create (e.g. 'example.com').
        """
        self._request("POST", "/dns", body={"domain": domain})

    def list_domains(self, offset: int = 0, limit: int = 200) -> List[str]:
        """List all domains in the account.

        Args:
            offset: Pagination offset.
            limit: Maximum number of domains per page (max 1000).

        Returns:
            List of domain names (e.g. ['example.com', 'example.net']).
        """
        res = self._request("GET", "/dns", params={"offset": offset, "limit": limit})
        return res if isinstance(res, list) else []

    def get_records(self, domain_name: str) -> List[DNSRecord]:
        """Get all DNS records for a domain.

        Args:
            domain_name: Domain name (e.g. 'example.com').

        Returns:
            List of DNSRecord objects.
        """
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        res = self._request("GET", f"/dns/{encoded_domain}/records")
        if not isinstance(res, list):
            return []
        return [DNSRecord.from_dict(item) for item in res]

    def replace_records(
        self,
        domain_name: str,
        records: List[Union[DNSRecord, Dict[str, Any]]],
    ) -> None:
        """Replace all DNS records on a domain (atomic bulk replace).

        Args:
            domain_name: Domain name.
            records: Complete list of DNS records to set.
        """
        payload = [
            r.to_dict() if isinstance(r, DNSRecord) else r
            for r in records
        ]
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        self._request("PUT", f"/dns/{encoded_domain}/records", body=payload)

    # --------------------------------------------------------------------------
    # High-Level Atomic Record Helpers (Optimized for AI Agents and Developers)
    # --------------------------------------------------------------------------

    def add_record(
        self,
        domain_name: str,
        name: str,
        type: Union[RecordType, str],
        records: Union[str, List[str]],
        ttl: int = 300,
    ) -> List[DNSRecord]:
        """Add or merge DNS record(s) on a domain.

        If a record with matching name and type already exists, appends new values
        and updates TTL. Otherwise, appends a new DNSRecord entry.

        Args:
            domain_name: Domain name.
            name: Hostname (e.g. '@', 'www', 'subdomain').
            type: Record type (e.g. 'A', 'CNAME', 'TXT').
            records: Single value string or list of values.
            ttl: Time-To-Live in seconds.

        Returns:
            Updated list of all DNSRecord objects on the domain.
        """
        rtype_str = type.value if isinstance(type, RecordType) else str(type).upper()
        values = [records] if isinstance(records, str) else list(records)

        current_records = self.get_records(domain_name)
        found = False

        for r in current_records:
            current_type_str = r.type.value if isinstance(r.type, RecordType) else str(r.type)
            if r.name.lower() == name.lower() and current_type_str.upper() == rtype_str:
                # Merge values deduplicating while preserving order
                for v in values:
                    if v not in r.records:
                        r.records.append(v)
                r.ttl = ttl
                found = True
                break

        if not found:
            current_records.append(
                DNSRecord(
                    name=name,
                    type=RecordType(rtype_str) if rtype_str in RecordType._value2member_map_ else rtype_str,  # type: ignore[arg-type]
                    ttl=ttl,
                    records=values,
                )
            )

        self.replace_records(domain_name, current_records)
        return current_records

    def remove_record(
        self,
        domain_name: str,
        name: str,
        type: Optional[Union[RecordType, str]] = None,
        value: Optional[str] = None,
    ) -> List[DNSRecord]:
        """Remove matching record(s) or a specific record value from a domain.

        Args:
            domain_name: Domain name.
            name: Hostname to match.
            type: Optional record type filter.
            value: Optional specific value to remove. If omitted, removes entire record entry.

        Returns:
            Updated list of all DNSRecord objects on the domain.
        """
        current_records = self.get_records(domain_name)
        rtype_str = (type.value if isinstance(type, RecordType) else str(type).upper()) if type else None

        updated_records: List[DNSRecord] = []
        for r in current_records:
            current_type_str = r.type.value if isinstance(r.type, RecordType) else str(r.type)
            name_matches = r.name.lower() == name.lower()
            type_matches = rtype_str is None or current_type_str.upper() == rtype_str

            if name_matches and type_matches:
                if value is not None:
                    r.records = [v for v in r.records if v != value]
                    if r.records:
                        updated_records.append(r)
                # If value is None, record is discarded completely
            else:
                updated_records.append(r)

        self.replace_records(domain_name, updated_records)
        return updated_records

    def update_record(
        self,
        domain_name: str,
        name: str,
        type: Union[RecordType, str],
        records: Union[str, List[str]],
        ttl: Optional[int] = None,
    ) -> List[DNSRecord]:
        """Replace all values for a specific hostname + type combination.

        Args:
            domain_name: Domain name.
            name: Hostname.
            type: Record type.
            records: New record value(s).
            ttl: Optional new TTL. If omitted, retains existing TTL or defaults to 300.

        Returns:
            Updated list of all DNSRecord objects on the domain.
        """
        rtype_str = type.value if isinstance(type, RecordType) else str(type).upper()
        values = [records] if isinstance(records, str) else list(records)

        current_records = self.get_records(domain_name)
        found = False

        for r in current_records:
            current_type_str = r.type.value if isinstance(r.type, RecordType) else str(r.type)
            if r.name.lower() == name.lower() and current_type_str.upper() == rtype_str:
                r.records = values
                if ttl is not None:
                    r.ttl = ttl
                found = True
                break

        if not found:
            current_records.append(
                DNSRecord(
                    name=name,
                    type=RecordType(rtype_str) if rtype_str in RecordType._value2member_map_ else rtype_str,  # type: ignore[arg-type]
                    ttl=ttl if ttl is not None else 300,
                    records=values,
                )
            )

        self.replace_records(domain_name, current_records)
        return current_records

    def find_records(
        self,
        domain_name: str,
        name: Optional[str] = None,
        type: Optional[Union[RecordType, str]] = None,
        value: Optional[str] = None,
    ) -> List[DNSRecord]:
        """Query and filter DNS records by name, type, and/or value without altering them.

        Args:
            domain_name: Domain name.
            name: Optional name filter (case-insensitive substring match).
            type: Optional record type filter.
            value: Optional record value filter (case-insensitive substring match).

        Returns:
            Filtered list of DNSRecord objects.
        """
        records = self.get_records(domain_name)
        rtype_str = (type.value if isinstance(type, RecordType) else str(type).upper()) if type else None
        name_lower = name.strip().lower() if name is not None else None
        val_lower = value.strip().lower() if value is not None else None

        filtered = []
        for r in records:
            current_type_str = r.type.value if isinstance(r.type, RecordType) else str(r.type)
            if name_lower is not None and name_lower not in r.name.lower():
                continue
            if rtype_str is not None and current_type_str.upper() != rtype_str:
                continue
            if val_lower is not None:
                if not any(val_lower in v.lower() for v in r.records):
                    continue
            filtered.append(r)
        return filtered

    # --------------------------------------------------------------------------
    # TSIG Key Management Methods
    # --------------------------------------------------------------------------

    def get_tsig_keys(self) -> List[TsigKey]:
        """Get all DNS TSIG keys for the account."""
        res = self._request("GET", "/dns/tsig")
        if isinstance(res, dict) and "tsigKeys" in res:
            return [TsigKey.from_dict(k) for k in res["tsigKeys"]]
        return []

    def create_tsig_key(
        self,
        algorithm: Optional[Union[TsigAlgorithm, str]] = None,
    ) -> TsigKey:
        """Create a new TSIG key for the account.

        Args:
            algorithm: Optional TSIG algorithm (e.g. 'hmac-sha256').

        Returns:
            Created TsigKey object.
        """
        body = {}
        if algorithm:
            alg_str = algorithm.value if isinstance(algorithm, TsigAlgorithm) else str(algorithm)
            body["algorithm"] = alg_str

        res = self._request("POST", "/dns/tsig", body=body if body else None)
        return TsigKey.from_dict(res)

    def get_tsig_key(self, key_name: str) -> TsigKey:
        """Get details for a specific TSIG key by name.

        Args:
            key_name: TSIG key name.

        Returns:
            TsigKey object.
        """
        encoded_key = urllib.parse.quote(key_name, safe="")
        res = self._request("GET", f"/dns/tsig/{encoded_key}")
        return TsigKey.from_dict(res)

    def delete_domain_tsig(self, domain_name: str) -> None:
        """Delete all TSIG keys associated with a domain.

        Args:
            domain_name: Domain name.
        """
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        self._request("DELETE", f"/dns/{encoded_domain}/tsig")

    def update_domain_tsig(
        self,
        domain_name: str,
        key_name: str,
        allow_axfr: bool,
        allow_dns_update: bool,
    ) -> None:
        """Update the TSIG key access settings on a domain.

        Args:
            domain_name: Domain name.
            key_name: TSIG key name.
            allow_axfr: Whether to allow AXFR zone transfers.
            allow_dns_update: Whether to allow dynamic DNS updates.
        """
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        encoded_key = urllib.parse.quote(key_name, safe="")
        body = {
            "allowAxfr": bool(allow_axfr),
            "allowDnsUpdate": bool(allow_dns_update),
        }
        self._request("PATCH", f"/dns/{encoded_domain}/tsig/{encoded_key}", body=body)

    # --------------------------------------------------------------------------
    # DNSSEC Management Methods
    # --------------------------------------------------------------------------

    def get_dnssec_status(self, domain_name: str) -> DNSSECStatus:
        """Get DNSSEC status and DS keys for a domain.

        Args:
            domain_name: Domain name.

        Returns:
            DNSSECStatus object.
        """
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        res = self._request("GET", f"/dns/{encoded_domain}/dnssec")
        return DNSSECStatus.from_dict(res if isinstance(res, dict) else {})

    def enable_dnssec(self, domain_name: str) -> None:
        """Enable DNSSEC for a domain.

        Args:
            domain_name: Domain name.
        """
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        self._request("POST", f"/dns/{encoded_domain}/dnssec")

    def disable_dnssec(self, domain_name: str) -> None:
        """Disable DNSSEC for a domain.

        Args:
            domain_name: Domain name.
        """
        encoded_domain = urllib.parse.quote(domain_name, safe="")
        self._request("DELETE", f"/dns/{encoded_domain}/dnssec")
