# OnlyDNS Python SDK

Official Python SDK for the [OnlyDNS System API](https://api-docs.onlydns.com/).

Designed for high developer utility and seamless AI agent tool calling with zero external dependencies.

## Features

- **Full OpenAPI Coverage**: Direct mapping to all DNS zones, records, and TSIG key operations.
- **High-Level Atomic Helpers**: Convenient `add_record`, `remove_record`, `update_record`, and `find_records` methods that simplify record manipulation for human developers and autonomous AI agents.
- **Strong Typing**: Comprehensive type hints and dataclasses for reliable IDE autocompletion and runtime validation.
- **Zero Heavy Dependencies**: Built on standard library `urllib` for lightweight execution across all Python environments.
- **Environment Aware**: Automatically resolves authentication from `ONLYDNS_API_KEY` or `ONLYDNS_API_TOKEN`.

## Installation

### From Local Source (development / testing)

When installing from the local repository directory:

```bash
# Navigate to the python SDK directory
cd onlydns-sdk/python

# Install the CLI application globally into an isolated environment using pipx
pipx install .

# Or for editable development mode
pipx install --editable .

# Alternatively, using standard pip
pip install .
```

### Direct install from Github
```bash
pipx install git+https://github.com/Onlydns/onlydns-sdk-python
```

### From PyPI (once published)

```bash
pip install onlydns-sdk
# or via pipx for CLI usage
pipx install onlydns-sdk
```

## Command Line Interface (CLI)

The Python SDK includes a built-in CLI tool (`onlydns` or `python -m onlydns`) for testing and daily DNS record management.

### 1. Authentication & Configuration

The CLI resolves API tokens from the `ONLYDNS_API_KEY` environment variable, or from stored credentials in `~/.config/onlydns/config.json`.

```bash
# Save your API key to ~/.config/onlydns/config.json
onlydns login your_api_bearer_token
# or
onlydns config set-key your_api_bearer_token

# Check current configuration status
onlydns config get-key

# Check config file path
onlydns config path

# Clear saved credentials
onlydns config clear
```

Alternatively, use an environment variable or the `-k` / `--api-key` flag:

```bash
export ONLYDNS_API_KEY="your_api_bearer_token"
# or
onlydns -k your_api_bearer_token domains list
```

### 2. Managing Domains

```bash
# List all domains
onlydns domains list

# Create a new domain
onlydns domains create mydomain.com

# Output JSON
onlydns --json domains list
```

### 3. Managing DNS Records

```bash
# List all records in a domain
onlydns records list example.com

# Add a record (or append values)
onlydns records add example.com --name api --type A --value 192.0.2.1 --ttl 300

# Update / replace all values for a record
onlydns records update example.com --name www --type CNAME --value example.com --ttl 600

# Remove a specific value or the entire record
onlydns records remove example.com --name api --type A --value 192.0.2.1
onlydns records remove example.com --name api --type A

# Find records matching name, type, and/or target value
onlydns records find example.com --name api
onlydns records find example.com --type A
onlydns records find example.com --value 192.0.2.1
onlydns records find example.com --name api --type A --value 192.0.2.1
```

### 4. DNSSEC Management

```bash
# Get DNSSEC status and DS keys
onlydns dnssec status example.com

# Enable DNSSEC
onlydns dnssec enable example.com

# Disable DNSSEC
onlydns dnssec disable example.com
```

### 5. TSIG Key Management

```bash
# List TSIG keys
onlydns tsig list

# Create a new TSIG key
onlydns tsig create --name my-key --algo hmac-sha256

# Get TSIG key details
onlydns tsig get my-key

# Set domain TSIG permissions
onlydns tsig set-permissions example.com my-key --transfer --update

# Clear domain TSIG keys
onlydns tsig clear example.com
```

## Quick Start (Python SDK)

```python
from onlydns import OnlyDNSClient, RecordType

# Initialize client (uses ONLYDNS_API_KEY from environment if not provided)
client = OnlyDNSClient(api_token="your_api_bearer_token")

# 1. List Domains
domains = client.list_domains()
print(f"Managed Domains: {domains}")

# 2. Get DNS Records
records = client.get_records("example.com")
for record in records:
    print(f"{record.name} ({record.type}): {record.records} [TTL {record.ttl}]")

# 3. High-Level Helper: Add an A Record
client.add_record(
    domain_name="example.com",
    name="api",
    type=RecordType.A,
    records="192.0.2.1",
    ttl=300
)

# 4. High-Level Helper: Update / Upsert Records
client.update_record(
    domain_name="example.com",
    name="www",
    type=RecordType.CNAME,
    records=["example.com"],
    ttl=600
)

# 5. High-Level Helper: Remove Specific Value or Record
client.remove_record(
    domain_name="example.com",
    name="api",
    type=RecordType.A
)

# 6. High-Level Helper: Find / Filter Records
matches = client.find_records(
    domain_name="example.com",
    name="api",
    type=RecordType.A,
    value="192.0.2.1"
)
```

## TSIG Key Management

```python
from onlydns import OnlyDNSClient, TsigAlgorithm

client = OnlyDNSClient()

# List TSIG keys
keys = client.get_tsig_keys()

# Create a new TSIG key
new_key = client.create_tsig_key(algorithm=TsigAlgorithm.HMAC_SHA256)
print(f"Created TSIG key: {new_key.name}")

# Configure domain TSIG permissions
client.update_domain_tsig(
    domain_name="example.com",
    key_name=new_key.name,
    allow_axfr=True,
    allow_dns_update=True
)

# Delete domain TSIG keys
client.delete_domain_tsig("example.com")
```

## DNSSEC & Domain Creation

```python
# Create a new domain
client.create_domain("my-new-domain.com")

# Get DNSSEC status & DS keys
dnssec = client.get_dnssec_status("my-new-domain.com")
print(f"DNSSEC Enabled: {dnssec.enabled}")
for key in dnssec.keys:
    print(f"KeyTag: {key.key_tag}, Digest: {key.digest}")

# Enable DNSSEC
client.enable_dnssec("my-new-domain.com")

# Disable DNSSEC
client.disable_dnssec("my-new-domain.com")
```

## AI Agent Integration Example

```python
# Example tool function definition for LLM tool calling (OpenAI / LangChain / CrewAI)
def set_dns_endpoint(subdomain: str, ip_address: str, domain: str = "example.com") -> str:
    """Creates or updates a DNS A record for the specified subdomain."""
    client = OnlyDNSClient()
    client.add_record(
        domain_name=domain,
        name=subdomain,
        type="A",
        records=ip_address,
        ttl=300
    )
    return f"Successfully configured {subdomain}.{domain} -> {ip_address}"
```

## License

MIT License.
