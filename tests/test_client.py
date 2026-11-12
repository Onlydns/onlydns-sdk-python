"""Unit tests for OnlyDNS Python SDK."""

import json
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from onlydns import (
    OnlyDNSClient,
    AuthenticationError,
    NotFoundError,
    ValidationError,
    APIError,
    DNSRecord,
    RecordType,
    TsigKey,
    TsigAlgorithm,
    DNSSECStatus,
    DNSSECDsKey,
    DNSSECKeyAlgorithm,
    DNSSECKeyDigestType,
)


class TestOnlyDNSClient(unittest.TestCase):

    def setUp(self):
        self.client = OnlyDNSClient(api_token="test_token_123")

    @patch("urllib.request.urlopen")
    def test_list_domains(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(["example.com", "example.net"]).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        domains = self.client.list_domains()
        self.assertEqual(domains, ["example.com", "example.net"])
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://api.onlydns.com/v1/dns?offset=0&limit=200")

    @patch("urllib.request.urlopen")
    def test_get_records(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps([
            {"name": "@", "type": "A", "ttl": 300, "records": ["192.0.2.1"]},
            {"name": "www", "type": "CNAME", "ttl": 600, "records": ["example.com"]},
        ]).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        records = self.client.get_records("example.com")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].name, "@")
        self.assertEqual(records[0].type, RecordType.A)
        self.assertEqual(records[0].records, ["192.0.2.1"])
        self.assertEqual(records[1].type, RecordType.CNAME)

    @patch("urllib.request.urlopen")
    def test_add_record_helper_merges_existing(self, mock_urlopen):
        mock_get_resp = MagicMock()
        mock_get_resp.status = 200
        mock_get_resp.read.return_value = json.dumps([
            {"name": "mail", "type": "A", "ttl": 300, "records": ["192.0.2.10"]}
        ]).encode("utf-8")

        mock_put_resp = MagicMock()
        mock_put_resp.status = 204
        mock_put_resp.read.return_value = b""

        mock_urlopen.return_value.__enter__.side_effect = [mock_get_resp, mock_put_resp]

        updated = self.client.add_record("example.com", "mail", RecordType.A, "192.0.2.11", ttl=300)
        self.assertEqual(len(updated), 1)
        self.assertEqual(updated[0].records, ["192.0.2.10", "192.0.2.11"])

    @patch("urllib.request.urlopen")
    def test_remove_record_helper(self, mock_urlopen):
        mock_get_resp = MagicMock()
        mock_get_resp.status = 200
        mock_get_resp.read.return_value = json.dumps([
            {"name": "api", "type": "A", "ttl": 300, "records": ["1.1.1.1", "2.2.2.2"]},
            {"name": "web", "type": "A", "ttl": 300, "records": ["3.3.3.3"]}
        ]).encode("utf-8")

        mock_put_resp = MagicMock()
        mock_put_resp.status = 204
        mock_put_resp.read.return_value = b""

        mock_urlopen.return_value.__enter__.side_effect = [mock_get_resp, mock_put_resp]

        # Remove single value from 'api'
        updated = self.client.remove_record("example.com", "api", RecordType.A, value="1.1.1.1")
        self.assertEqual(len(updated), 2)
        self.assertEqual(updated[0].records, ["2.2.2.2"])

    @patch("urllib.request.urlopen")
    def test_find_records_filters(self, mock_urlopen):
        mock_get_resp = MagicMock()
        mock_get_resp.status = 200
        mock_get_resp.read.return_value = json.dumps([
            {"name": "api.example.com.", "type": "A", "ttl": 300, "records": ["192.0.2.1"]},
            {"name": "mail.example.com.", "type": "A", "ttl": 300, "records": ["192.0.2.25"]},
            {"name": "www.example.com.", "type": "CNAME", "ttl": 600, "records": ["example.com."]},
            {"name": "example.com.", "type": "TXT", "ttl": 300, "records": ["v=spf1 include:_spf.example.com ~all"]},
        ]).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_get_resp

        # Filter by name substring
        res_name = self.client.find_records("example.com", name="api")
        self.assertEqual(len(res_name), 1)
        self.assertEqual(res_name[0].name, "api.example.com.")

        # Filter by broader name substring
        res_name_all = self.client.find_records("example.com", name="example.com")
        self.assertEqual(len(res_name_all), 4)

        # Filter by type
        res_type = self.client.find_records("example.com", type=RecordType.A)
        self.assertEqual(len(res_type), 2)

        # Filter by value
        res_val = self.client.find_records("example.com", value="192.0.2.25")
        self.assertEqual(len(res_val), 1)
        self.assertEqual(res_val[0].name, "mail.example.com.")

        # Filter by value substring
        res_sub = self.client.find_records("example.com", value="spf")
        self.assertEqual(len(res_sub), 1)
        self.assertEqual(res_sub[0].type, RecordType.TXT)

        # Filter by name, type, and value combined
        res_comb = self.client.find_records("example.com", name="www", type="CNAME", value="example.com")
        self.assertEqual(len(res_comb), 1)
        self.assertEqual(res_comb[0].name, "www.example.com.")

    @patch("urllib.request.urlopen")
    def test_tsig_key_operations(self, mock_urlopen):
        # Create TSIG Key
        mock_create = MagicMock()
        mock_create.status = 200
        mock_create.read.return_value = json.dumps({
            "name": "key-test-1",
            "algorithm": "hmac-sha256",
            "key": "secretbase64=="
        }).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_create
        key = self.client.create_tsig_key(TsigAlgorithm.HMAC_SHA256)
        self.assertEqual(key.name, "key-test-1")
        self.assertEqual(key.algorithm, TsigAlgorithm.HMAC_SHA256)
        self.assertEqual(key.key, "secretbase64==")

        # Get Domain TSIG
        mock_get_domain = MagicMock()
        mock_get_domain.status = 200
        mock_get_domain.read.return_value = json.dumps({
            "key-test-1": {
                "allowAxfr": True,
                "allowDnsUpdate": True,
                "subdomains": ["_acme-challenge", "staging"],
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_get_domain

        domain_perms = self.client.get_domain_tsig("example.com")
        self.assertIn("key-test-1", domain_perms)
        self.assertTrue(domain_perms["key-test-1"].allow_axfr)
        self.assertTrue(domain_perms["key-test-1"].allow_dns_update)
        self.assertEqual(domain_perms["key-test-1"].subdomains, ["_acme-challenge", "staging"])

        # Update Domain TSIG with subdomains
        mock_patch = MagicMock()
        mock_patch.status = 200
        mock_patch.read.return_value = b"{}"
        mock_urlopen.return_value.__enter__.return_value = mock_patch

        self.client.update_domain_tsig("example.com", "key-test-1", True, True, subdomains=["_acme-challenge"])
        self.assertTrue(mock_urlopen.called)

    @patch("urllib.request.urlopen")
    def test_create_domain(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        self.client.create_domain("newdomain.com")
        self.assertTrue(mock_urlopen.called)

    @patch("urllib.request.urlopen")
    def test_dnssec_operations(self, mock_urlopen):
        # get status
        mock_get = MagicMock()
        mock_get.status = 200
        mock_get.read.return_value = json.dumps({
            "enabled": True,
            "nsec3param": "1 0 10 12345678",
            "keys": [
                {
                    "keyTag": 2371,
                    "algorithm": 13,
                    "digestType": 2,
                    "digest": "abc123def456"
                }
            ]
        }).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_get
        status = self.client.get_dnssec_status("example.com")
        self.assertTrue(status.enabled)
        self.assertEqual(status.nsec3param, "1 0 10 12345678")
        self.assertEqual(len(status.keys), 1)
        self.assertEqual(status.keys[0].key_tag, 2371)
        self.assertEqual(status.keys[0].algorithm, DNSSECKeyAlgorithm.ECDSA_P256_SHA256)
        self.assertEqual(status.keys[0].digest_type, DNSSECKeyDigestType.SHA256)
        self.assertEqual(status.keys[0].digest, "abc123def456")

        # enable DNSSEC
        mock_enable = MagicMock()
        mock_enable.status = 201
        mock_enable.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_enable
        self.client.enable_dnssec("example.com")

        # disable DNSSEC
        mock_disable = MagicMock()
        mock_disable.status = 204
        mock_disable.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_disable
        self.client.disable_dnssec("example.com")

    @patch("urllib.request.urlopen")
    def test_account_operations(self, mock_urlopen):
        # 1. get_account
        mock_get_acc = MagicMock()
        mock_get_acc.status = 200
        mock_get_acc.read.return_value = json.dumps({
            "accountId": "018f1234-5678-7000-8000-000000000001",
            "activeAt": "2024-01-01T00:00:00+00:00",
            "companyName": "Acme Corporation",
            "firstName": "Jane",
            "lastName": "Doe",
            "address": {
                "street1": "123 Innovation Way",
                "city": "Austin",
                "state": "TX",
                "countryId": "US",
                "postalCode": "78701",
            },
            "package": {
                "id": "018f1234-5678-7000-8000-000000000002",
                "description": "Enterprise Tier",
                "amount": 49.99,
                "features": {
                    "domains": 50,
                    "records": 5000,
                    "queries": 1000000,
                    "dnssec": True,
                    "tsig": True,
                    "proxy": True,
                    "customSSO": True,
                },
            },
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_get_acc

        info = self.client.get_account()
        self.assertEqual(info.account_id, "018f1234-5678-7000-8000-000000000001")
        self.assertEqual(info.company_name, "Acme Corporation")
        self.assertIsNotNone(info.package)
        self.assertTrue(info.package.features.custom_sso)

        # 2. get_account_oidc
        mock_get_oidc = MagicMock()
        mock_get_oidc.status = 200
        mock_get_oidc.read.return_value = json.dumps({
            "configured": True,
            "accountId": "018f1234-5678-7000-8000-000000000001",
            "discoveryUrl": "https://idp.example.com/.well-known/openid-configuration",
            "clientId": "client-123",
            "clientSecretMasked": "secr*****",
            "enforceSso": False,
            "breakGlassAdminsCount": 1,
            "canEnforceSso": True,
            "nonCompliantUsers": [],
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_get_oidc

        oidc = self.client.get_account_oidc()
        self.assertTrue(oidc.configured)
        self.assertEqual(oidc.client_id, "client-123")

        # 3. save_account_oidc
        mock_save_oidc = MagicMock()
        mock_save_oidc.status = 200
        mock_save_oidc.read.return_value = json.dumps({
            "configured": True,
            "discoveryUrl": "https://idp.example.com/.well-known/openid-configuration",
            "clientId": "client-123",
            "enforceSso": True,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_save_oidc

        saved = self.client.save_account_oidc(
            discovery_url="https://idp.example.com/.well-known/openid-configuration",
            client_id="client-123",
            client_secret="secret123",
            enforce_sso=True,
        )
        self.assertTrue(saved.enforce_sso)

        # 4. test_account_oidc
        mock_test_oidc = MagicMock()
        mock_test_oidc.status = 200
        mock_test_oidc.read.return_value = json.dumps({
            "success": True,
            "issuer": "https://idp.example.com",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_test_oidc

        test_res = self.client.test_account_oidc("https://idp.example.com/.well-known/openid-configuration")
        self.assertTrue(test_res.success)
        self.assertEqual(test_res.issuer, "https://idp.example.com")

        # 5. delete_account_oidc
        mock_del_oidc = MagicMock()
        mock_del_oidc.status = 200
        mock_del_oidc.read.return_value = json.dumps({
            "success": True,
            "message": "OIDC configuration removed successfully",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_del_oidc

        del_res = self.client.delete_account_oidc()
        self.assertTrue(del_res["success"])

    @patch("urllib.request.urlopen")
    def test_error_handling_401(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.onlydns.com/v1/dns",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None
        )
        with self.assertRaises(AuthenticationError):
            self.client.list_domains()


if __name__ == "__main__":
    unittest.main()
