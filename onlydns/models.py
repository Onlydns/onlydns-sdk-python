"""Data models for OnlyDNS SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class RecordType(str, Enum):
    """Supported DNS Record Types."""
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    CNAME = "CNAME"
    TXT = "TXT"
    SRV = "SRV"
    CAA = "CAA"
    CERT = "CERT"
    HTTPS = "HTTPS"
    LOC = "LOC"
    NAPTR = "NAPTR"
    NS = "NS"
    SMIMEA = "SMIMEA"
    SSHFP = "SSHFP"
    SVCB = "SVCB"
    TLSA = "TLSA"
    URL = "URL"
    PROXY = "PROXY"


class TsigAlgorithm(str, Enum):
    """Supported TSIG Algorithms."""
    MAC_MD5 = "mac-md5"
    HMAC_SHA1 = "hmac-sha1"
    HMAC_SHA224 = "hmac-sha224"
    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA384 = "hmac-sha384"
    HMAC_SHA512 = "hmac-sha512"


class DNSSECKeyAlgorithm(int, Enum):
    """DNSSEC Key Algorithm numbers."""
    RSA_MD5 = 1
    DIFFIE_HELLMAN = 2
    DSA_SHA1 = 3
    RSA_SHA1 = 5
    DSA_NSEC3_SHA1 = 6
    RSASHA1_NSEC3_SHA1 = 7
    RSA_SHA256 = 8
    RSA_SHA512 = 10
    GOST_R_34_10_2001 = 12
    ECDSA_P256_SHA256 = 13
    ECDSA_P384_SHA384 = 14
    ED25519 = 15
    ED448 = 16
    SM2SM3 = 17
    ECC_GOST12 = 23


class DNSSECKeyDigestType(int, Enum):
    """DNSSEC Key Digest Types."""
    SHA1 = 1
    SHA256 = 2
    GOST_R_34_11_94 = 3
    SHA384 = 4


@dataclass
class DNSSECDsKey:
    """DNSSEC DS Key details."""
    key_tag: int
    algorithm: Union[DNSSECKeyAlgorithm, int]
    digest_type: Union[DNSSECKeyDigestType, int]
    digest: str

    def to_dict(self) -> Dict[str, Any]:
        alg_val = self.algorithm.value if isinstance(self.algorithm, DNSSECKeyAlgorithm) else int(self.algorithm)
        dt_val = self.digest_type.value if isinstance(self.digest_type, DNSSECKeyDigestType) else int(self.digest_type)
        return {
            "keyTag": int(self.key_tag),
            "algorithm": alg_val,
            "digestType": dt_val,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSSECDsKey":
        raw_alg = data.get("algorithm", 0)
        try:
            alg = DNSSECKeyAlgorithm(raw_alg)
        except ValueError:
            alg = raw_alg

        raw_dt = data.get("digestType", 0)
        try:
            dt = DNSSECKeyDigestType(raw_dt)
        except ValueError:
            dt = raw_dt

        return cls(
            key_tag=data.get("keyTag", 0),
            algorithm=alg,
            digest_type=dt,
            digest=data.get("digest", ""),
        )


@dataclass
class DNSSECStatus:
    """DNSSEC Status response."""
    enabled: bool = False
    nsec3param: Optional[str] = None
    keys: List[DNSSECDsKey] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "enabled": self.enabled,
            "keys": [k.to_dict() for k in self.keys],
        }
        if self.nsec3param is not None:
            d["nsec3param"] = self.nsec3param
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSSECStatus":
        raw_keys = data.get("keys", [])
        keys = [DNSSECDsKey.from_dict(k) for k in raw_keys] if isinstance(raw_keys, list) else []
        return cls(
            enabled=bool(data.get("enabled", False)),
            nsec3param=data.get("nsec3param"),
            keys=keys,
        )


DNSDnssecStatusResponse = DNSSECStatus


@dataclass
class DNSRecord:
    """Represents a DNS record collection for a given name and type."""
    name: str
    type: RecordType
    ttl: int
    records: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API payload dictionary."""
        return {
            "name": self.name,
            "type": self.type.value if isinstance(self.type, RecordType) else str(self.type),
            "ttl": int(self.ttl),
            "records": list(self.records),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSRecord":
        """Construct from API response dictionary."""
        rtype_str = data.get("type", "")
        try:
            rtype = RecordType(rtype_str)
        except ValueError:
            rtype = rtype_str  # type: ignore[assignment]

        return cls(
            name=data.get("name", ""),
            type=rtype,
            ttl=data.get("ttl", 300),
            records=data.get("records", []),
        )


@dataclass
class TsigKey:
    """Represents a TSIG Key."""
    name: str
    algorithm: TsigAlgorithm
    key: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TsigKey":
        alg_str = data.get("algorithm", "")
        try:
            alg = TsigAlgorithm(alg_str)
        except ValueError:
            alg = alg_str  # type: ignore[assignment]

        return cls(
            name=data.get("name", ""),
            algorithm=alg,
            key=data.get("key", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "algorithm": self.algorithm.value if isinstance(self.algorithm, TsigAlgorithm) else str(self.algorithm),
            "key": self.key,
        }


TsigKeyCreateResponse = TsigKey


@dataclass
class DomainTsigPermissions:
    """Permissions for a TSIG key on a specific domain."""
    allow_axfr: bool
    allow_dns_update: bool
    subdomains: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "allowAxfr": self.allow_axfr,
            "allowDnsUpdate": self.allow_dns_update,
        }
        if self.subdomains is not None:
            d["subdomains"] = list(self.subdomains)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainTsigPermissions":
        raw_subdomains = data.get("subdomains")
        subdomains: Optional[List[str]] = None
        if raw_subdomains is not None:
            if isinstance(raw_subdomains, list):
                subdomains = [str(s) for s in raw_subdomains]
            else:
                subdomains = [str(raw_subdomains)]
        return cls(
            allow_axfr=bool(data.get("allowAxfr", False)),
            allow_dns_update=bool(data.get("allowDnsUpdate", False)),
            subdomains=subdomains,
        )


@dataclass
class ErrorResponse:
    """Error response details from the API."""
    lang: str = "en-US"
    error_code: Optional[int] = None
    title: str = ""
    description: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ErrorResponse":
        return cls(
            lang=data.get("lang", "en-US"),
            error_code=data.get("errorCode"),
            title=data.get("title", ""),
            description=data.get("description", []),
        )


@dataclass
class AccountPostalAddress:
    """Account contact postal address."""
    street1: str = ""
    street2: str = ""
    street3: str = ""
    city: str = ""
    state: str = ""
    country_id: str = ""
    postal_code: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountPostalAddress":
        return cls(
            street1=data.get("street1", ""),
            street2=data.get("street2", ""),
            street3=data.get("street3", ""),
            city=data.get("city", ""),
            state=data.get("state", ""),
            country_id=data.get("countryId", ""),
            postal_code=data.get("postalCode", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "street1": self.street1,
            "street2": self.street2,
            "street3": self.street3,
            "city": self.city,
            "state": self.state,
            "countryId": self.country_id,
            "postalCode": self.postal_code,
        }


@dataclass
class BillingPackageFeatures:
    """Feature capabilities included in the billing package."""
    domains: int = 0
    records: int = 0
    queries: int = 0
    dnssec: bool = False
    tsig: bool = False
    proxy: bool = False
    custom_sso: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BillingPackageFeatures":
        return cls(
            domains=int(data.get("domains", 0)),
            records=int(data.get("records", 0)),
            queries=int(data.get("queries", 0)),
            dnssec=bool(data.get("dnssec", False)),
            tsig=bool(data.get("tsig", False)),
            proxy=bool(data.get("proxy", False)),
            custom_sso=bool(data.get("customSSO", data.get("custom_sso", False))),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": self.domains,
            "records": self.records,
            "queries": self.queries,
            "dnssec": self.dnssec,
            "tsig": self.tsig,
            "proxy": self.proxy,
            "customSSO": self.custom_sso,
        }


@dataclass
class BillingPackage:
    """Account billing package details and feature entitlements."""
    id: str = ""
    description: str = ""
    amount: float = 0.0
    features: BillingPackageFeatures = field(default_factory=BillingPackageFeatures)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BillingPackage":
        feat_data = data.get("features", {})
        return cls(
            id=data.get("id", ""),
            description=data.get("description", ""),
            amount=float(data.get("amount", 0.0)),
            features=BillingPackageFeatures.from_dict(feat_data) if isinstance(feat_data, dict) else BillingPackageFeatures(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "amount": self.amount,
            "features": self.features.to_dict(),
        }


@dataclass
class AccountInfo:
    """Account information, contact details, and feature entitlements."""
    account_id: str = ""
    active_at: Optional[str] = None
    company_name: str = ""
    first_name: str = ""
    last_name: str = ""
    address: Optional[AccountPostalAddress] = None
    package: Optional[BillingPackage] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountInfo":
        addr_data = data.get("address")
        pkg_data = data.get("package")
        return cls(
            account_id=data.get("accountId", data.get("account_id", "")),
            active_at=data.get("activeAt", data.get("active_at")),
            company_name=data.get("companyName", data.get("company_name", "")),
            first_name=data.get("firstName", data.get("first_name", "")),
            last_name=data.get("lastName", data.get("last_name", "")),
            address=AccountPostalAddress.from_dict(addr_data) if isinstance(addr_data, dict) else None,
            package=BillingPackage.from_dict(pkg_data) if isinstance(pkg_data, dict) else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accountId": self.account_id,
            "activeAt": self.active_at,
            "companyName": self.company_name,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "address": self.address.to_dict() if self.address else None,
            "package": self.package.to_dict() if self.package else None,
        }


@dataclass
class Money:
    """Monetary amount with value string and currency code."""
    value: str = "0.00"
    currency: str = "USD"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Money":
        return cls(
            value=str(data.get("value", "0.00")),
            currency=str(data.get("currency", "USD")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "currency": self.currency,
        }


@dataclass
class BillingStatusResponse:
    """Account billing state and balances."""
    account_id: str = ""
    currency: str = "USD"
    amount_due: Optional[Money] = None
    past_due_amount: Optional[Money] = None
    billing_assessed_to: Optional[str] = None
    suspended_at: Optional[str] = None
    past_due: bool = False
    suspended: bool = False
    suspended_for_non_payment: bool = False
    payment_required: bool = False
    payable: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BillingStatusResponse":
        amount_due_data = data.get("amountDue") or data.get("amount_due")
        past_due_data = data.get("pastDueAmount") or data.get("past_due_amount")
        return cls(
            account_id=str(data.get("accountId", data.get("account_id", ""))),
            currency=str(data.get("currency", "USD")),
            amount_due=Money.from_dict(amount_due_data) if isinstance(amount_due_data, dict) else None,
            past_due_amount=Money.from_dict(past_due_data) if isinstance(past_due_data, dict) else None,
            billing_assessed_to=data.get("billingAssessedTo", data.get("billing_assessed_to")),
            suspended_at=data.get("suspendedAt", data.get("suspended_at")),
            past_due=bool(data.get("pastDue", data.get("past_due", False))),
            suspended=bool(data.get("suspended", False)),
            suspended_for_non_payment=bool(data.get("suspendedForNonPayment", data.get("suspended_for_non_payment", False))),
            payment_required=bool(data.get("paymentRequired", data.get("payment_required", False))),
            payable=bool(data.get("payable", False)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accountId": self.account_id,
            "currency": self.currency,
            "amountDue": self.amount_due.to_dict() if self.amount_due else None,
            "pastDueAmount": self.past_due_amount.to_dict() if self.past_due_amount else None,
            "billingAssessedTo": self.billing_assessed_to,
            "suspendedAt": self.suspended_at,
            "pastDue": self.past_due,
            "suspended": self.suspended,
            "suspendedForNonPayment": self.suspended_for_non_payment,
            "paymentRequired": self.payment_required,
            "payable": self.payable,
        }


@dataclass
class AccountMetricUsage:
    """Usage metric item with current count and package limit."""
    current: int = 0
    limit: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricUsage":
        return cls(
            current=int(data.get("current", 0)),
            limit=int(data.get("limit", 0)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current": self.current,
            "limit": self.limit,
        }


@dataclass
class AccountMetricRecords:
    """DNS record metrics including portfolio total, peak single-zone record count, peak zone name, and per-zone plan limit."""
    total_records: int = 0
    max_zone_records: int = 0
    max_zone_name: Optional[str] = None
    limit_per_zone: int = 0
    current: Optional[int] = None
    limit: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricRecords":
        return cls(
            total_records=int(data.get("totalRecords", data.get("total_records", data.get("current", 0)))),
            max_zone_records=int(data.get("maxZoneRecords", data.get("max_zone_records", 0))),
            max_zone_name=data.get("maxZoneName", data.get("max_zone_name")),
            limit_per_zone=int(data.get("limitPerZone", data.get("limit_per_zone", data.get("limit", 0)))),
            current=data.get("current"),
            limit=data.get("limit"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "totalRecords": self.total_records,
            "maxZoneRecords": self.max_zone_records,
            "maxZoneName": self.max_zone_name,
            "limitPerZone": self.limit_per_zone,
            "current": self.current,
            "limit": self.limit,
        }


@dataclass
class AccountMetricApiRequestsPerMinute:
    """API request rate metric item with current rate, 24h average rate, and limit."""
    current: int = 0
    average_last_24_hours: float = 0.0
    limit: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricApiRequestsPerMinute":
        return cls(
            current=int(data.get("current", 0)),
            average_last_24_hours=float(data.get("averageLast24Hours", data.get("average_last_24_hours", 0.0))),
            limit=int(data.get("limit", 0)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current": self.current,
            "averageLast24Hours": self.average_last_24_hours,
            "limit": self.limit,
        }


@dataclass
class AccountMetricDNSSEC:
    """DNSSEC usage metric and package entitlement status."""
    current: int = 0
    enabled: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricDNSSEC":
        return cls(
            current=int(data.get("current", 0)),
            enabled=bool(data.get("enabled", False)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current": self.current,
            "enabled": self.enabled,
        }


@dataclass
class AccountMetricsUsage:
    """Aggregated usage metrics for an account."""
    domains: AccountMetricUsage = field(default_factory=AccountMetricUsage)
    records: AccountMetricRecords = field(default_factory=AccountMetricRecords)
    queries: AccountMetricUsage = field(default_factory=AccountMetricUsage)
    dnssec: AccountMetricDNSSEC = field(default_factory=AccountMetricDNSSEC)
    tsig_keys: AccountMetricUsage = field(default_factory=AccountMetricUsage)
    changes_last_24_hours: AccountMetricUsage = field(default_factory=AccountMetricUsage)
    api_requests_per_minute: AccountMetricApiRequestsPerMinute = field(default_factory=AccountMetricApiRequestsPerMinute)
    api_tokens: AccountMetricUsage = field(default_factory=AccountMetricUsage)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricsUsage":
        return cls(
            domains=AccountMetricUsage.from_dict(data.get("domains") or {}),
            records=AccountMetricRecords.from_dict(data.get("records") or {}),
            queries=AccountMetricUsage.from_dict(data.get("queries") or {}),
            dnssec=AccountMetricDNSSEC.from_dict(data.get("dnssec") or {}),
            tsig_keys=AccountMetricUsage.from_dict(data.get("tsigKeys") or data.get("tsig_keys") or {}),
            changes_last_24_hours=AccountMetricUsage.from_dict(data.get("changesLast24Hours") or data.get("changes_last_24_hours") or {}),
            api_requests_per_minute=AccountMetricApiRequestsPerMinute.from_dict(data.get("apiRequestsPerMinute") or data.get("api_requests_per_minute") or {}),
            api_tokens=AccountMetricUsage.from_dict(data.get("apiTokens") or data.get("api_tokens") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": self.domains.to_dict(),
            "records": self.records.to_dict(),
            "queries": self.queries.to_dict(),
            "dnssec": self.dnssec.to_dict(),
            "tsigKeys": self.tsig_keys.to_dict(),
            "changesLast24Hours": self.changes_last_24_hours.to_dict(),
            "apiRequestsPerMinute": self.api_requests_per_minute.to_dict(),
            "apiTokens": self.api_tokens.to_dict(),
        }


@dataclass
class AccountMetricsPackage:
    """Summary of active package for metrics."""
    id: str = ""
    description: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricsPackage":
        return cls(
            id=str(data.get("id", "")),
            description=str(data.get("description", "")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
        }


@dataclass
class AccountMetricsResponse:
    """Account metrics response payload."""
    account_id: str = ""
    package: Optional[AccountMetricsPackage] = None
    usage: AccountMetricsUsage = field(default_factory=AccountMetricsUsage)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountMetricsResponse":
        pkg_data = data.get("package")
        return cls(
            account_id=str(data.get("accountId", data.get("account_id", ""))),
            package=AccountMetricsPackage.from_dict(pkg_data) if isinstance(pkg_data, dict) else None,
            usage=AccountMetricsUsage.from_dict(data.get("usage") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accountId": self.account_id,
            "package": self.package.to_dict() if self.package else None,
            "usage": self.usage.to_dict(),
        }


@dataclass
class AccountOidcNonCompliantUser:
    """User who cannot use custom SSO until migration or credential reset."""
    user_id: str = ""
    user_name: str = ""
    sso_provider: Optional[str] = None
    reason: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountOidcNonCompliantUser":
        return cls(
            user_id=data.get("userId", data.get("user_id", "")),
            user_name=data.get("userName", data.get("user_name", "")),
            sso_provider=data.get("ssoProvider", data.get("sso_provider")),
            reason=data.get("reason", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "userId": self.user_id,
            "userName": self.user_name,
            "ssoProvider": self.sso_provider,
            "reason": self.reason,
        }


@dataclass
class AccountOidcConfig:
    """Account custom OIDC Single Sign-On configuration."""
    configured: bool = False
    account_id: Optional[str] = None
    discovery_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret_masked: Optional[str] = None
    enforce_sso: bool = False
    break_glass_admins_count: int = 0
    can_enforce_sso: bool = False
    non_compliant_users: List[AccountOidcNonCompliantUser] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountOidcConfig":
        raw_users = data.get("nonCompliantUsers", data.get("non_compliant_users", []))
        users = [
            AccountOidcNonCompliantUser.from_dict(u) if isinstance(u, dict) else u
            for u in raw_users
        ]
        return cls(
            configured=bool(data.get("configured", False)),
            account_id=data.get("accountId", data.get("account_id")),
            discovery_url=data.get("discoveryUrl", data.get("discovery_url")),
            client_id=data.get("clientId", data.get("client_id")),
            client_secret_masked=data.get("clientSecretMasked", data.get("client_secret_masked")),
            enforce_sso=bool(data.get("enforceSso", data.get("enforce_sso", False))),
            break_glass_admins_count=int(data.get("breakGlassAdminsCount", data.get("break_glass_admins_count", 0))),
            can_enforce_sso=bool(data.get("canEnforceSso", data.get("can_enforce_sso", False))),
            non_compliant_users=users,
            created_at=data.get("createdAt", data.get("created_at")),
            updated_at=data.get("updatedAt", data.get("updated_at")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "configured": self.configured,
            "accountId": self.account_id,
            "discoveryUrl": self.discovery_url,
            "clientId": self.client_id,
            "clientSecretMasked": self.client_secret_masked,
            "enforceSso": self.enforce_sso,
            "breakGlassAdminsCount": self.break_glass_admins_count,
            "canEnforceSso": self.can_enforce_sso,
            "nonCompliantUsers": [u.to_dict() for u in self.non_compliant_users],
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


@dataclass
class AccountOidcTestResponse:
    """Response from testing OIDC discovery URL reachability and client credentials."""
    success: bool = False
    valid: bool = False
    client_credentials_tested: Optional[bool] = None
    client_credentials_valid: Optional[bool] = None
    issuer: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    scopes_supported: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountOidcTestResponse":
        return cls(
            success=bool(data.get("success", False)),
            valid=bool(data.get("valid", False)),
            client_credentials_tested=data.get("clientCredentialsTested", data.get("client_credentials_tested")),
            client_credentials_valid=data.get("clientCredentialsValid", data.get("client_credentials_valid")),
            issuer=data.get("issuer"),
            authorization_endpoint=data.get("authorizationEndpoint", data.get("authorization_endpoint")),
            token_endpoint=data.get("tokenEndpoint", data.get("token_endpoint")),
            jwks_uri=data.get("jwksUri", data.get("jwks_uri")),
            userinfo_endpoint=data.get("userinfoEndpoint", data.get("userinfo_endpoint")),
            scopes_supported=data.get("scopesSupported", data.get("scopes_supported", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "valid": self.valid,
            "clientCredentialsTested": self.client_credentials_tested,
            "clientCredentialsValid": self.client_credentials_valid,
            "issuer": self.issuer,
            "authorizationEndpoint": self.authorization_endpoint,
            "tokenEndpoint": self.token_endpoint,
            "jwksUri": self.jwks_uri,
            "userinfoEndpoint": self.userinfo_endpoint,
            "scopesSupported": self.scopes_supported,
        }
