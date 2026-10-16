"""Unit tests for OnlyDNS CLI and configuration manager."""

import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from onlydns.cli import build_parser, main
from onlydns.config import (
    clear_config,
    get_api_key,
    get_config_dir,
    get_config_file_path,
    load_config,
    save_config,
    set_api_key,
)
from onlydns.exceptions import AuthenticationError, NotFoundError
from onlydns.models import DNSRecord, DNSSECStatus, RecordType, TsigKey


class TestConfig(unittest.TestCase):
    """Test configuration storage and credential resolution."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.orig_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.test_dir
        self.orig_api_key = os.environ.pop("ONLYDNS_API_KEY", None)
        self.orig_api_token = os.environ.pop("ONLYDNS_API_TOKEN", None)

    def tearDown(self):
        if self.orig_xdg is not None:
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)

        if self.orig_api_key:
            os.environ["ONLYDNS_API_KEY"] = self.orig_api_key
        if self.orig_api_token:
            os.environ["ONLYDNS_API_TOKEN"] = self.orig_api_token

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_load_config(self):
        cfg_path = set_api_key("test_secret_key_123")
        self.assertTrue(cfg_path.is_file())
        self.assertEqual(get_api_key(), "test_secret_key_123")

        data = load_config()
        self.assertEqual(data.get("api_key"), "test_secret_key_123")

    def test_env_var_priority_over_config(self):
        set_api_key("stored_key_456")
        self.assertEqual(get_api_key(), "stored_key_456")

        os.environ["ONLYDNS_API_KEY"] = "env_key_789"
        self.assertEqual(get_api_key(), "env_key_789")

    def test_clear_config(self):
        set_api_key("key_to_clear")
        self.assertTrue(clear_config())
        self.assertIsNone(get_api_key())
        self.assertFalse(clear_config())


class TestCLI(unittest.TestCase):
    """Test CLI commands and dispatching."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.orig_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.test_dir
        self.orig_api_key = os.environ.pop("ONLYDNS_API_KEY", None)
        self.orig_api_token = os.environ.pop("ONLYDNS_API_TOKEN", None)

    def tearDown(self):
        if self.orig_xdg is not None:
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)

        if self.orig_api_key:
            os.environ["ONLYDNS_API_KEY"] = self.orig_api_key
        if self.orig_api_token:
            os.environ["ONLYDNS_API_TOKEN"] = self.orig_api_token

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cli_help_and_no_args(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main([])
            self.assertEqual(code, 0)
            self.assertIn("onlydns", fake_out.getvalue())

    def test_config_commands(self):
        # login / set-key
        code = main(["login", "my_api_token_123"])
        self.assertEqual(code, 0)
        self.assertEqual(get_api_key(), "my_api_token_123")

        # config get-key
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["config", "get-key", "--json"])
            self.assertEqual(code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertTrue(data.get("stored_key_present"))

        # config path
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["config", "path"])
            self.assertEqual(code, 0)
            self.assertIn("config.json", fake_out.getvalue())

        # config clear
        code = main(["config", "clear"])
        self.assertEqual(code, 0)
        self.assertIsNone(get_api_key())

    @patch("onlydns.cli.OnlyDNSClient")
    def test_domains_list_and_create(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.list_domains.return_value = ["example.com", "test.org"]
        mock_client_cls.return_value = mock_client

        # List domains (table / text)
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "domains", "list"])
            self.assertEqual(code, 0)
            self.assertIn("example.com", fake_out.getvalue())
            self.assertIn("test.org", fake_out.getvalue())

        # List domains (json)
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "--json", "domains", "list"])
            self.assertEqual(code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertEqual(data, ["example.com", "test.org"])

        # Create domain
        code = main(["-k", "token123", "domains", "create", "newdomain.com"])
        self.assertEqual(code, 0)
        mock_client.create_domain.assert_called_once_with("newdomain.com")

    @patch("onlydns.cli.OnlyDNSClient")
    def test_records_commands(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get_records.return_value = [
            DNSRecord(name="api", type=RecordType.A, ttl=300, records=["192.0.2.1"]),
            DNSRecord(name="www", type=RecordType.CNAME, ttl=600, records=["example.com"]),
        ]
        mock_client.find_records.return_value = [
            DNSRecord(name="api", type=RecordType.A, ttl=300, records=["192.0.2.1"]),
        ]
        mock_client_cls.return_value = mock_client

        # List records
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "records", "list", "example.com"])
            self.assertEqual(code, 0)
            out = fake_out.getvalue()
            self.assertIn("api", out)
            self.assertIn("192.0.2.1", out)

        # Add record
        code = main([
            "-k", "token123",
            "records", "add", "example.com",
            "--name", "sub",
            "--type", "A",
            "--value", "1.2.3.4",
            "--ttl", "300",
        ])
        self.assertEqual(code, 0)
        mock_client.add_record.assert_called_once_with(
            domain_name="example.com",
            name="sub",
            type="A",
            records=["1.2.3.4"],
            ttl=300,
        )

        # Update record
        code = main([
            "-k", "token123",
            "records", "update", "example.com",
            "--name", "sub",
            "--type", "A",
            "--value", "5.6.7.8",
            "--ttl", "600",
        ])
        self.assertEqual(code, 0)
        mock_client.update_record.assert_called_once_with(
            domain_name="example.com",
            name="sub",
            type="A",
            records=["5.6.7.8"],
            ttl=600,
        )

        # Remove record
        code = main([
            "-k", "token123",
            "records", "remove", "example.com",
            "--name", "sub",
            "--type", "A",
        ])
        self.assertEqual(code, 0)
        mock_client.remove_record.assert_called_once_with(
            domain_name="example.com",
            name="sub",
            type="A",
            value=None,
        )

        # Find records
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main([
                "-k", "token123",
                "--json",
                "records", "find", "example.com",
                "--name", "api",
                "--type", "A",
                "--value", "192.0.2.1",
            ])
            self.assertEqual(code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["name"], "api")
            mock_client.find_records.assert_called_with(
                domain_name="example.com",
                name="api",
                type="A",
                value="192.0.2.1",
            )

    @patch("onlydns.cli.OnlyDNSClient")
    def test_dnssec_commands(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get_dnssec_status.return_value = DNSSECStatus(
            enabled=True,
            nsec3param="1 0 10 12345678",
            keys=[],
        )
        mock_client_cls.return_value = mock_client

        # Status
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "dnssec", "status", "example.com"])
            self.assertEqual(code, 0)
            self.assertIn("Enabled:     True", fake_out.getvalue())

        # Enable
        code = main(["-k", "token123", "dnssec", "enable", "example.com"])
        self.assertEqual(code, 0)
        mock_client.enable_dnssec.assert_called_once_with("example.com")

        # Disable
        code = main(["-k", "token123", "dnssec", "disable", "example.com"])
        self.assertEqual(code, 0)
        mock_client.disable_dnssec.assert_called_once_with("example.com")

    @patch("onlydns.cli.OnlyDNSClient")
    def test_tsig_commands(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get_tsig_keys.return_value = [
            TsigKey(name="key1", algorithm="hmac-sha256"),
        ]
        mock_client_cls.return_value = mock_client

        # List TSIG
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "tsig", "list"])
            self.assertEqual(code, 0)
            self.assertIn("key1", fake_out.getvalue())

        # Set permissions
        code = main([
            "-k", "token123",
            "tsig", "set-permissions", "example.com", "key1",
            "--transfer", "--update",
        ])
        self.assertEqual(code, 0)
        mock_client.update_domain_tsig.assert_called_once_with(
            domain_name="example.com",
            key_name="key1",
            allow_axfr=True,
            allow_dns_update=True,
        )

        # Clear TSIG
        code = main(["-k", "token123", "tsig", "clear", "example.com"])
        self.assertEqual(code, 0)
        mock_client.delete_domain_tsig.assert_called_once_with("example.com")

    def test_auth_error_handling(self):
        # When no token is configured
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["domains", "list"])
            self.assertEqual(code, 1)
            self.assertIn("Authentication Error", fake_err.getvalue())

    @patch("onlydns.cli.OnlyDNSClient")
    def test_api_errors_and_json_formatting(self, mock_client_cls):
        from onlydns.exceptions import APIError, ValidationError
        mock_client = MagicMock()
        mock_client.get_records.side_effect = NotFoundError("Domain not found", status_code=404)
        mock_client.add_record.side_effect = ValidationError("Invalid IP", details=["IP format is invalid"])
        mock_client_cls.return_value = mock_client

        # Not found with --json
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "--json", "records", "list", "missing.com"])
            self.assertEqual(code, 1)
            data = json.loads(fake_out.getvalue())
            self.assertEqual(data["error"], "NotFoundError")

        # Validation error with text formatting
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["-k", "token123", "records", "add", "example.com", "-n", "test", "-t", "A", "-v", "invalid"])
            self.assertEqual(code, 1)
            self.assertIn("Validation Error", fake_err.getvalue())
            self.assertIn("IP format is invalid", fake_err.getvalue())

    @patch("onlydns.cli.OnlyDNSClient")
    def test_flag_at_end_of_command(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.list_domains.return_value = ["domain1.com"]
        mock_client_cls.return_value = mock_client

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["domains", "list", "-k", "token_at_end", "--json"])
            self.assertEqual(code, 0)
            data = json.loads(fake_out.getvalue())
            self.assertEqual(data, ["domain1.com"])

    def test_missing_subcommand_parameters(self):
        # 1. Config without action
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["config"])
            self.assertEqual(code, 2)
            self.assertIn("specify a config action", fake_err.getvalue())

        # 2. Records without action
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["records"])
            self.assertEqual(code, 2)
            self.assertIn("specify a records action", fake_err.getvalue())

        # 2b. Records find without any filter options
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["records", "find", "example.com"])
            self.assertEqual(code, 2)
            self.assertIn("At least one filter option", fake_err.getvalue())

        # 3. DNSSEC without action
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["dnssec"])
            self.assertEqual(code, 2)
            self.assertIn("specify a dnssec action", fake_err.getvalue())

        # 4. TSIG without action
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            code = main(["tsig"])
            self.assertEqual(code, 2)
            self.assertIn("specify a tsig action", fake_err.getvalue())

    @patch("onlydns.cli.OnlyDNSClient")
    def test_domains_default_action(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.list_domains.return_value = ["example.com"]
        mock_client_cls.return_value = mock_client

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            code = main(["-k", "token123", "domains"])
            self.assertEqual(code, 0)
            self.assertIn("example.com", fake_out.getvalue())


if __name__ == "__main__":
    unittest.main()
