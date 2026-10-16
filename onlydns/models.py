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

    def to_dict(self) -> Dict[str, bool]:
        return {
            "allowAxfr": self.allow_axfr,
            "allowDnsUpdate": self.allow_dns_update,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainTsigPermissions":
        return cls(
            allow_axfr=bool(data.get("allowAxfr", False)),
            allow_dns_update=bool(data.get("allowDnsUpdate", False)),
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
