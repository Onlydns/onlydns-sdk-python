"""Command-line interface for OnlyDNS API.

Provides real-world testing capabilities and an intuitive interface for basic
domain, DNS record, DNSSEC, and TSIG management.
"""

import argparse
import json
import sys
from typing import List, Optional, Tuple

from .client import OnlyDNSClient
from .config import (
    clear_config,
    get_api_key,
    get_config_file_path,
    get_stored_api_token,
    load_config,
    set_api_key,
)
from .exceptions import (
    APIError,
    AuthenticationError,
    NotFoundError,
    OnlyDNSError,
    ValidationError,
)
from .models import RecordType, TsigAlgorithm


def _create_client(args: argparse.Namespace) -> OnlyDNSClient:
    """Create and return an OnlyDNSClient instance configured from CLI arguments."""
    api_token = getattr(args, "api_key", None) or get_api_key()
    base_url = getattr(args, "base_url", None)
    timeout = getattr(args, "timeout", 30.0)
    return OnlyDNSClient(api_token=api_token, base_url=base_url, timeout=timeout)


def _format_records_table(records: list) -> str:
    """Format a list of DNSRecord objects into a clean tabular string."""
    if not records:
        return "No records found."

    header = f"{'NAME':<28} {'TYPE':<8} {'TTL':<8} {'VALUES'}"
    separator = "-" * 80
    lines = [header, separator]

    for rec in records:
        name = rec.name
        rtype = rec.type.value if hasattr(rec.type, "value") else str(rec.type)
        ttl = str(rec.ttl)
        values_str = ", ".join(rec.records)
        lines.append(f"{name:<28} {rtype:<8} {ttl:<8} {values_str}")

    return "\n".join(lines)


# ------------------------------------------------------------------------------
# Subcommand Handlers
# ------------------------------------------------------------------------------


def cmd_config(args: argparse.Namespace) -> int:
    """Handle configuration and authentication management commands."""
    action = getattr(args, "config_action", None)

    if action in ("set-key", "set-token", "login"):
        key = getattr(args, "key", None)
        if not key:
            print("Error: API key is required. Usage: onlydns config set-key <KEY>", file=sys.stderr)
            return 2
        base_url = getattr(args, "base_url", None)
        path = set_api_key(key, base_url=base_url)
        if getattr(args, "json", False):
            print(json.dumps({"status": "ok", "message": "API key saved", "path": str(path)}))
        else:
            print(f"API key successfully saved to {path}")
        return 0

    elif action in ("get-key", "show"):
        token = get_stored_api_token()
        active_token = get_api_key()
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "stored_key_present": bool(token),
                        "active_key_present": bool(active_token),
                        "config_file": str(get_config_file_path()),
                    }
                )
            )
        else:
            if active_token:
                masked = active_token[:4] + "*" * max(0, len(active_token) - 8) + active_token[-4:] if len(active_token) >= 8 else "***"
                print(f"Active API key: {masked}")
                print(f"Config path:    {get_config_file_path()}")
            else:
                print("No API key configured in environment or config file.")
        return 0

    elif action == "path":
        path = get_config_file_path()
        if getattr(args, "json", False):
            print(json.dumps({"path": str(path), "exists": path.is_file()}))
        else:
            print(str(path))
        return 0

    elif action == "clear":
        cleared = clear_config()
        if getattr(args, "json", False):
            print(json.dumps({"status": "ok" if cleared else "not_found", "cleared": cleared}))
        else:
            if cleared:
                print("Configuration file cleared.")
            else:
                print("No configuration file found to clear.")
        return 0

    print("Error: Please specify a config action (set-key, get-key, path, clear). Usage: onlydns config <action>", file=sys.stderr)
    return 2


def cmd_domains(args: argparse.Namespace) -> int:
    """Handle domain-related commands."""
    action = getattr(args, "domains_action", None) or "list"
    client = _create_client(args)

    if action == "create":
        domain = getattr(args, "domain", None)
        if not domain:
            print("Error: Domain name is required. Usage: onlydns domains create <domain>", file=sys.stderr)
            return 2
        client.create_domain(domain)
        if getattr(args, "json", False):
            print(json.dumps({"status": "ok", "domain": domain, "action": "created"}))
        else:
            print(f"Successfully created domain '{domain}'.")
        return 0

    elif action == "list":
        offset = getattr(args, "offset", 0) or 0
        limit = getattr(args, "limit", 200) or 200
        domains = client.list_domains(offset=offset, limit=limit)
        if getattr(args, "json", False):
            print(json.dumps(domains, indent=2))
        else:
            if not domains:
                print("No domains found.")
            else:
                print(f"Domains ({len(domains)}):")
                for d in domains:
                    print(f"  - {d}")
        return 0

    print(f"Error: Unknown domains action '{action}'. Available actions: list, create", file=sys.stderr)
    return 2


def cmd_records(args: argparse.Namespace) -> int:
    """Handle DNS record management commands."""
    action = getattr(args, "records_action", None)
    if not action:
        print("Error: Please specify a records action (list, add, update, remove, find). Usage: onlydns records <action> <domain> [options]", file=sys.stderr)
        return 2

    domain = getattr(args, "domain", None)
    if not domain:
        print(f"Error: Domain name is required. Usage: onlydns records {action} <domain> [options]", file=sys.stderr)
        return 2

    if action == "find":
        name = getattr(args, "name", None)
        rtype = getattr(args, "type", None)
        raw_val = getattr(args, "value", None)
        val = raw_val[0] if isinstance(raw_val, list) and raw_val else (raw_val if isinstance(raw_val, str) else None)

        if not name and not rtype and not val:
            print(
                "Error: At least one filter option (--name, --type, or --value) is required for 'find'. "
                "Usage: onlydns records find <domain> [--name NAME] [--type TYPE] [--value VALUE]",
                file=sys.stderr,
            )
            return 2

        client = _create_client(args)
        matches = client.find_records(
            domain_name=domain,
            name=name,
            type=rtype,
            value=val,
        )
        if getattr(args, "json", False):
            print(json.dumps([m.to_dict() for m in matches], indent=2))
        else:
            print(_format_records_table(matches))
        return 0

    client = _create_client(args)

    if action == "list":
        records = client.get_records(domain)
        if getattr(args, "json", False):
            print(json.dumps([r.to_dict() for r in records], indent=2))
        else:
            print(_format_records_table(records))
        return 0

    elif action == "add":
        name = getattr(args, "name", None)
        rtype = getattr(args, "type", None)
        if not name or not rtype:
            print("Error: Record --name (-n) and --type (-t) are required.", file=sys.stderr)
            return 2

        raw_values = getattr(args, "value", None) or []
        values: List[str] = []
        for v in raw_values:
            values.extend([val.strip() for val in v.split(",") if val.strip()])
        if not values:
            print("Error: At least one --value (-v) must be provided.", file=sys.stderr)
            return 2

        ttl = getattr(args, "ttl", None)
        client.add_record(
            domain_name=domain,
            name=name,
            type=rtype,
            records=values,
            ttl=ttl,
        )
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "added",
                        "domain": domain,
                        "name": name,
                        "type": rtype,
                        "values": values,
                        "ttl": ttl,
                    }
                )
            )
        else:
            ttl_str = f" (TTL {ttl})" if ttl is not None else ""
            print(f"Added record {name} {rtype} -> {', '.join(values)}{ttl_str} in '{domain}'.")
        return 0

    elif action == "update":
        name = getattr(args, "name", None)
        rtype = getattr(args, "type", None)
        if not name or not rtype:
            print("Error: Record --name (-n) and --type (-t) are required.", file=sys.stderr)
            return 2

        raw_values = getattr(args, "value", None) or []
        values = []
        for v in raw_values:
            values.extend([val.strip() for val in v.split(",") if val.strip()])
        if not values:
            print("Error: At least one --value (-v) must be provided for update.", file=sys.stderr)
            return 2

        ttl = getattr(args, "ttl", None)
        client.update_record(
            domain_name=domain,
            name=name,
            type=rtype,
            records=values,
            ttl=ttl,
        )
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "updated",
                        "domain": domain,
                        "name": name,
                        "type": rtype,
                        "values": values,
                        "ttl": ttl,
                    }
                )
            )
        else:
            ttl_str = f" (TTL {ttl})" if ttl is not None else ""
            print(f"Updated record {name} {rtype} -> {', '.join(values)}{ttl_str} in '{domain}'.")
        return 0

    elif action == "remove":
        name = getattr(args, "name", None)
        rtype = getattr(args, "type", None)
        if not name or not rtype:
            print("Error: Record --name (-n) and --type (-t) are required.", file=sys.stderr)
            return 2

        raw_values = getattr(args, "value", None) or []
        target_value = raw_values[0] if raw_values else None
        client.remove_record(
            domain_name=domain,
            name=name,
            type=rtype,
            value=target_value,
        )
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "removed",
                        "domain": domain,
                        "name": name,
                        "type": rtype,
                        "value": target_value,
                    }
                )
            )
        else:
            if target_value:
                print(f"Removed value '{target_value}' from {name} {rtype} in '{domain}'.")
            else:
                print(f"Removed record {name} {rtype} from '{domain}'.")
        return 0

    print(f"Error: Unknown records action '{action}'. Available actions: list, add, update, remove, find", file=sys.stderr)
    return 2


def cmd_dnssec(args: argparse.Namespace) -> int:
    """Handle DNSSEC management commands."""
    action = getattr(args, "dnssec_action", None)
    if not action:
        print("Error: Please specify a dnssec action (status, enable, disable). Usage: onlydns dnssec <action> <domain>", file=sys.stderr)
        return 2

    domain = getattr(args, "domain", None)
    if not domain:
        print(f"Error: Domain name is required. Usage: onlydns dnssec {action} <domain>", file=sys.stderr)
        return 2

    client = _create_client(args)

    if action in ("status", "get"):
        status = client.get_dnssec_status(domain)
        if getattr(args, "json", False):
            print(json.dumps(status.to_dict(), indent=2))
        else:
            print(f"DNSSEC Status for {domain}:")
            print(f"  Enabled:     {status.enabled}")
            if status.nsec3param:
                print(f"  NSEC3 Param: {status.nsec3param}")
            print(f"  DS Keys ({len(status.keys)}):")
            for idx, k in enumerate(status.keys, 1):
                alg_str = k.algorithm.name if hasattr(k.algorithm, "name") else str(k.algorithm)
                dt_str = k.digest_type.name if hasattr(k.digest_type, "name") else str(k.digest_type)
                print(f"    [{idx}] KeyTag: {k.key_tag}, Algorithm: {alg_str}, DigestType: {dt_str}")
                print(f"        Digest: {k.digest}")
        return 0

    elif action == "enable":
        client.enable_dnssec(domain)
        if getattr(args, "json", False):
            print(json.dumps({"status": "ok", "domain": domain, "dnssec": "enabled"}))
        else:
            print(f"DNSSEC successfully enabled for '{domain}'.")
        return 0

    elif action == "disable":
        client.disable_dnssec(domain)
        if getattr(args, "json", False):
            print(json.dumps({"status": "ok", "domain": domain, "dnssec": "disabled"}))
        else:
            print(f"DNSSEC successfully disabled for '{domain}'.")
        return 0

    print(f"Error: Unknown dnssec action '{action}'. Available actions: status, enable, disable", file=sys.stderr)
    return 2


def cmd_tsig(args: argparse.Namespace) -> int:
    """Handle TSIG key management commands."""
    action = getattr(args, "tsig_action", None)
    if not action:
        print("Error: Please specify a tsig action (list, create, get, set-permissions, clear). Usage: onlydns tsig <action> [options]", file=sys.stderr)
        return 2

    client = _create_client(args)

    if action == "list":
        keys = client.get_tsig_keys()
        if getattr(args, "json", False):
            print(json.dumps([k.to_dict() for k in keys], indent=2))
        else:
            if not keys:
                print("No TSIG keys found.")
            else:
                print(f"TSIG Keys ({len(keys)}):")
                for k in keys:
                    algo = k.algorithm.value if hasattr(k.algorithm, "value") else str(k.algorithm)
                    print(f"  - {k.name:<30} ({algo})")
        return 0

    elif action == "create":
        algo_str = getattr(args, "algo", "hmac-sha256") or "hmac-sha256"
        try:
            algo = TsigAlgorithm(algo_str)
        except ValueError:
            print(f"Error: Invalid TSIG algorithm '{algo_str}'. Available: {', '.join(a.value for a in TsigAlgorithm)}", file=sys.stderr)
            return 2
        name = getattr(args, "name", None)
        res = client.create_tsig_key(algorithm=algo, name=name)
        if getattr(args, "json", False):
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"Created TSIG key '{res.name}':")
            print(f"  Algorithm: {res.algorithm}")
            print(f"  Secret:    {res.key}")
        return 0

    elif action == "get":
        key_name = getattr(args, "key_name", None)
        if not key_name:
            print("Error: TSIG key name is required. Usage: onlydns tsig get <key_name>", file=sys.stderr)
            return 2
        key = client.get_tsig_key(key_name)
        if getattr(args, "json", False):
            print(json.dumps(key.to_dict(), indent=2))
        else:
            algo = key.algorithm.value if hasattr(key.algorithm, "value") else str(key.algorithm)
            print(f"TSIG Key '{key.name}':")
            print(f"  Algorithm: {algo}")
            if key.key:
                print(f"  Secret:    {key.key}")
        return 0

    elif action == "set-permissions":
        domain = getattr(args, "domain", None)
        key_name = getattr(args, "key_name", None)
        if not domain or not key_name:
            print("Error: Domain name and TSIG key name are required. Usage: onlydns tsig set-permissions <domain> <key_name> [--transfer] [--update]", file=sys.stderr)
            return 2
        transfer = bool(getattr(args, "transfer", False))
        update = bool(getattr(args, "update", False))
        client.update_domain_tsig(
            domain_name=domain,
            key_name=key_name,
            allow_axfr=transfer,
            allow_dns_update=update,
        )
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "domain": domain,
                        "key_name": key_name,
                        "allow_axfr": transfer,
                        "allow_dns_update": update,
                    }
                )
            )
        else:
            print(
                f"Updated TSIG permissions for domain '{domain}' key '{key_name}': "
                f"AXFR={transfer}, DynamicUpdate={update}."
            )
        return 0

    elif action == "clear":
        domain = getattr(args, "domain", None)
        if not domain:
            print("Error: Domain name is required. Usage: onlydns tsig clear <domain>", file=sys.stderr)
            return 2
        client.delete_domain_tsig(domain)
        if getattr(args, "json", False):
            print(json.dumps({"status": "ok", "domain": domain, "action": "tsig_cleared"}))
        else:
            print(f"Cleared all TSIG keys for domain '{domain}'.")
        return 0

    print(f"Error: Unknown tsig action '{action}'. Available actions: list, create, get, set-permissions, clear", file=sys.stderr)
    return 2


# ------------------------------------------------------------------------------
# Argument Parser Construction
# ------------------------------------------------------------------------------


def _build_global_parser() -> argparse.ArgumentParser:
    """Build a helper parser for extracting global flags."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--api-key", "-k", dest="api_key", default=None)
    parser.add_argument("--base-url", dest="base_url", default=None)
    parser.add_argument("--json", action="store_true", default=False)
    parser.add_argument("--timeout", type=float, default=None)
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="onlydns",
        description="Command-line interface for OnlyDNS API (onlydns.com).",
    )
    parser.add_argument(
        "--api-key",
        "-k",
        dest="api_key",
        default=None,
        help="OnlyDNS API bearer token (overrides environment variable and stored config)",
    )
    parser.add_argument(
        "--base-url",
        dest="base_url",
        default=None,
        help="Custom base API URL (default: https://api.onlydns.com/v1)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results in JSON format",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP request timeout in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version="onlydns-sdk 1.0.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 1. Config Subcommand
    config_p = subparsers.add_parser("config", help="Manage API key and configuration settings")
    config_sub = config_p.add_subparsers(dest="config_action", help="Config actions")

    set_key_p = config_sub.add_parser("set-key", help="Save API key to ~/.config/onlydns/config.json")
    set_key_p.add_argument("key", help="API token string")

    config_sub.add_parser("get-key", help="Show currently configured API key status")
    config_sub.add_parser("path", help="Print configuration file path")
    config_sub.add_parser("clear", help="Clear saved configuration file")

    # Shortcut login
    login_p = subparsers.add_parser("login", help="Save API key to ~/.config/onlydns/config.json")
    login_p.add_argument("key", help="API token string")

    # 2. Domains Subcommand
    domains_p = subparsers.add_parser("domains", help="Manage domains")
    domains_sub = domains_p.add_subparsers(dest="domains_action", help="Domain actions")

    list_dom_p = domains_sub.add_parser("list", help="List domains in account")
    list_dom_p.add_argument("--limit", type=int, default=200, help="Max results to fetch")
    list_dom_p.add_argument("--offset", type=int, default=0, help="Pagination offset")

    create_dom_p = domains_sub.add_parser("create", help="Create a new domain")
    create_dom_p.add_argument("domain", help="Domain name (e.g. example.com)")

    # 3. Records Subcommand
    records_p = subparsers.add_parser("records", help="Manage DNS records within a domain")
    records_sub = records_p.add_subparsers(dest="records_action", help="Record actions")

    # records list
    rec_list_p = records_sub.add_parser("list", help="List all DNS records for a domain")
    rec_list_p.add_argument("domain", help="Domain name")

    # records add
    rec_add_p = records_sub.add_parser("add", help="Add or append value(s) to a DNS record")
    rec_add_p.add_argument("domain", help="Domain name")
    rec_add_p.add_argument("--name", "-n", required=True, help="Record name (e.g. 'api', '@', 'www')")
    rec_add_p.add_argument("--type", "-t", required=True, help="Record type (e.g. 'A', 'CNAME', 'TXT')")
    rec_add_p.add_argument("--value", "-v", action="append", required=True, help="Record value (can be specified multiple times or comma-separated)")
    rec_add_p.add_argument("--ttl", type=int, default=None, help="TTL in seconds")

    # records update
    rec_up_p = records_sub.add_parser("update", help="Replace all values and TTL for a DNS record")
    rec_up_p.add_argument("domain", help="Domain name")
    rec_up_p.add_argument("--name", "-n", required=True, help="Record name")
    rec_up_p.add_argument("--type", "-t", required=True, help="Record type")
    rec_up_p.add_argument("--value", "-v", action="append", required=True, help="New record value(s)")
    rec_up_p.add_argument("--ttl", type=int, default=None, help="TTL in seconds")

    # records remove
    rec_rm_p = records_sub.add_parser("remove", help="Remove an entire record or specific value")
    rec_rm_p.add_argument("domain", help="Domain name")
    rec_rm_p.add_argument("--name", "-n", required=True, help="Record name")
    rec_rm_p.add_argument("--type", "-t", required=True, help="Record type")
    rec_rm_p.add_argument("--value", "-v", action="append", help="Specific value to remove (if omitted, removes all values)")

    # records find
    rec_find_p = records_sub.add_parser("find", help="Find records matching name, type, and/or value")
    rec_find_p.add_argument("domain", help="Domain name")
    rec_find_p.add_argument("--name", "-n", default=None, help="Record name filter (e.g. 'api', 'www', '@')")
    rec_find_p.add_argument("--type", "-t", default=None, help="Record type filter (e.g. 'A', 'CNAME', 'TXT')")
    rec_find_p.add_argument("--value", "-v", default=None, help="Record value filter (e.g. '192.0.2.1')")

    # 4. DNSSEC Subcommand
    dnssec_p = subparsers.add_parser("dnssec", help="Manage DNSSEC for a domain")
    dnssec_sub = dnssec_p.add_subparsers(dest="dnssec_action", help="DNSSEC actions")

    dnssec_stat_p = dnssec_sub.add_parser("status", help="Get DNSSEC status and DS keys")
    dnssec_stat_p.add_argument("domain", help="Domain name")

    dnssec_enable_p = dnssec_sub.add_parser("enable", help="Enable DNSSEC for domain")
    dnssec_enable_p.add_argument("domain", help="Domain name")

    dnssec_disable_p = dnssec_sub.add_parser("disable", help="Disable DNSSEC for domain")
    dnssec_disable_p.add_argument("domain", help="Domain name")

    # 5. TSIG Subcommand
    tsig_p = subparsers.add_parser("tsig", help="Manage TSIG keys and domain permissions")
    tsig_sub = tsig_p.add_subparsers(dest="tsig_action", help="TSIG actions")

    tsig_sub.add_parser("list", help="List all TSIG keys")

    tsig_create_p = tsig_sub.add_parser("create", help="Create a new TSIG key")
    tsig_create_p.add_argument("--name", "-n", default=None, help="Optional key name")
    tsig_create_p.add_argument("--algo", "-a", default="hmac-sha256", choices=[a.value for a in TsigAlgorithm], help="HMAC algorithm (default: hmac-sha256)")

    tsig_get_p = tsig_sub.add_parser("get", help="Get details of a TSIG key")
    tsig_get_p.add_argument("key_name", help="TSIG key name")

    tsig_perm_p = tsig_sub.add_parser("set-permissions", help="Set domain TSIG transfer and update permissions")
    tsig_perm_p.add_argument("domain", help="Domain name")
    tsig_perm_p.add_argument("key_name", help="TSIG key name")
    tsig_perm_p.add_argument("--transfer", action="store_true", help="Allow AXFR zone transfers")
    tsig_perm_p.add_argument("--update", action="store_true", help="Allow dynamic DNS updates")

    tsig_clear_p = tsig_sub.add_parser("clear", help="Clear all TSIG keys for a domain")
    tsig_clear_p.add_argument("domain", help="Domain name")

    return parser


def parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments allowing global flags anywhere in the command."""
    if argv is None:
        argv = sys.argv[1:]

    global_p = _build_global_parser()
    global_args, rem_argv = global_p.parse_known_args(argv)

    main_p = build_parser()
    args = main_p.parse_args(rem_argv)

    if global_args.api_key is not None:
        args.api_key = global_args.api_key
    if global_args.base_url is not None:
        args.base_url = global_args.base_url
    if global_args.json:
        args.json = True
    if global_args.timeout is not None:
        args.timeout = global_args.timeout

    return args


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]

    args = parse_cli_args(argv)

    if not args.command:
        parser = build_parser()
        parser.print_help()
        return 0

    try:
        if args.command == "login":
            args.config_action = "login"
            return cmd_config(args)
        elif args.command == "config":
            return cmd_config(args)
        elif args.command == "domains":
            return cmd_domains(args)
        elif args.command == "records":
            return cmd_records(args)
        elif args.command == "dnssec":
            return cmd_dnssec(args)
        elif args.command == "tsig":
            return cmd_tsig(args)
        else:
            parser = build_parser()
            parser.print_help()
            return 2
    except AuthenticationError as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": "AuthenticationError", "message": str(e), "details": getattr(e, "details", [])}))
        else:
            print(f"Authentication Error: {e}", file=sys.stderr)
            print("Tip: Run `onlydns config set-key <YOUR_KEY>` or set ONLYDNS_API_KEY environment variable.", file=sys.stderr)
        return 1
    except NotFoundError as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": "NotFoundError", "message": str(e), "details": getattr(e, "details", [])}))
        else:
            print(f"Not Found: {e}", file=sys.stderr)
        return 1
    except ValidationError as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": "ValidationError", "message": str(e), "details": getattr(e, "details", [])}))
        else:
            print(f"Validation Error: {e}", file=sys.stderr)
            for d in getattr(e, "details", []):
                print(f"  - {d}", file=sys.stderr)
        return 1
    except APIError as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": "APIError", "status_code": getattr(e, "status_code", 0), "message": str(e), "details": getattr(e, "details", [])}))
        else:
            print(f"API Error ({getattr(e, 'status_code', 'unknown')}): {e}", file=sys.stderr)
            for d in getattr(e, "details", []):
                print(f"  - {d}", file=sys.stderr)
        return 1
    except OnlyDNSError as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": "OnlyDNSError", "message": str(e)}))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": type(e).__name__, "message": str(e)}))
        else:
            print(f"Unexpected Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
