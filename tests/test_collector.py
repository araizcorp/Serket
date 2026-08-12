import unittest
from types import SimpleNamespace
from unittest.mock import patch

from serket.collector.acl_parser import PROP_GUID
from serket.collector.ldap_collector import (
    LDAPCollector,
    UAC_DONT_REQ_PREAUTH,
    _int,
)


class FakeConnection:
    def __init__(self):
        self.response = []
        self.result = {}
        self.last_search = {}

    def search(self, **kwargs):
        self.last_search = kwargs
        self.response = [
            {
                "type": "searchResEntry",
                "dn": "CN=one,DC=lab,DC=example",
                "attributes": {"cn": "one"},
            }
        ]
        self.result = {
            "controls": {
                "1.2.840.113556.1.4.319": {"value": {"cookie": b""}}
            }
        }


class CollectorTests(unittest.TestCase):
    def collector(self):
        collector = LDAPCollector(
            dc_host="dc.lab.example",
            domain="lab.example",
            username="auditor",
            password="not-used",
            rate_limit=0,
        )
        collector.base_dn = "DC=lab,DC=example"
        return collector

    @patch("serket.collector.ldap_collector.Connection")
    @patch("serket.collector.ldap_collector.Server")
    def test_connect_allows_optional_ad_schema_attributes(
        self, server_class, connection_class
    ):
        collector = self.collector()
        server = SimpleNamespace(
            info=SimpleNamespace(
                other={
                    "defaultNamingContext": ["DC=lab,DC=example"],
                    "configurationNamingContext": [
                        "CN=Configuration,DC=lab,DC=example"
                    ],
                }
            )
        )
        server_class.return_value = server
        connection_class.return_value = SimpleNamespace(server=server)

        collector.connect()

        self.assertFalse(connection_class.call_args.kwargs["check_names"])
        self.assertTrue(connection_class.call_args.kwargs["auto_bind"])

    def test_search_records_auditable_telemetry(self):
        collector = self.collector()
        collector.conn = FakeConnection()
        collector._active_stage = "Enumerating users"

        result = collector._search(
            collector.base_dn,
            "(objectClass=user)",
            ["cn"],
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(collector._telemetry["searches"], 1)
        self.assertEqual(collector._telemetry["pages"], 1)
        self.assertEqual(collector._telemetry["entries"], 1)
        self.assertEqual(
            collector._telemetry["stages"]["Enumerating users"]["entries"],
            1,
        )

    def test_search_skips_attributes_missing_from_dc_schema(self):
        collector = self.collector()
        collector.conn = FakeConnection()
        collector.conn.server = SimpleNamespace(
            schema=SimpleNamespace(attribute_types={"cn": object()})
        )

        collector._search(
            collector.base_dn,
            "(objectClass=computer)",
            ["cn", "ms-Mcs-AdmPwd", "msLAPS-Password"],
        )

        self.assertEqual(collector.conn.last_search["attributes"], ["cn"])
        self.assertEqual(
            collector._telemetry["skipped_schema_attributes"],
            ["ms-Mcs-AdmPwd", "msLAPS-Password"],
        )

    def test_integer_attributes_accept_scalars_lists_and_invalid_values(self):
        self.assertEqual(_int(512), 512)
        self.assertEqual(_int(["4194304"]), UAC_DONT_REQ_PREAUTH)
        self.assertEqual(_int([], 10), 10)
        self.assertEqual(_int(["invalid"], 7), 7)

    def test_users_accept_list_wrapped_user_account_control(self):
        collector = self.collector()
        collector._search = lambda *args, **kwargs: [
            {
                "dn": "CN=alice,CN=Users,DC=lab,DC=example",
                "attributes": {
                    "samAccountName": ["alice"],
                    "objectSid": ["S-1-5-21-1-2-3-1100"],
                    "userAccountControl": [str(UAC_DONT_REQ_PREAUTH)],
                    "adminCount": ["1"],
                    "memberOf": [],
                    "servicePrincipalName": [],
                },
            }
        ]

        user = collector.collect_users()["S-1-5-21-1-2-3-1100"]

        self.assertEqual(user["uac"], UAC_DONT_REQ_PREAUTH)
        self.assertEqual(user["admin_count"], 1)
        self.assertTrue(user["asreproastable"])

    def test_rbcd_queries_use_canonical_ldap_attribute(self):
        collector = self.collector()
        queries = []
        collector._search = lambda _base, _filter, attributes, *args, **kwargs: (
            queries.append(attributes) or []
        )

        collector.collect_users()
        collector.collect_gmsa()
        collector.collect_computers()

        canonical = "msDS-AllowedToActOnBehalfOfOtherIdentity"
        shortened = "msDS-AllowedToActOnBehalfOf"
        self.assertEqual(len(queries), 3)
        for attributes in queries:
            self.assertIn(canonical, attributes)
            self.assertNotIn(shortened, attributes)
        self.assertEqual(
            PROP_GUID["3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"],
            canonical,
        )

    def test_gmsa_has_dedicated_model_and_never_persists_blob(self):
        collector = self.collector()
        entry = {
            "dn": "CN=svc-web,CN=Managed Service Accounts,DC=lab,DC=example",
            "attributes": {
                "samAccountName": "svc-web$",
                "objectSid": "S-1-5-21-1-2-3-1200",
                "userAccountControl": 0,
                "servicePrincipalName": ["HTTP/web.lab.example"],
                "memberOf": [],
                "msDS-ManagedPassword": b"sensitive-blob",
            },
        }
        collector._search = lambda *args, **kwargs: [entry]

        accounts = collector.collect_gmsa()
        account = accounts["S-1-5-21-1-2-3-1200"]

        self.assertTrue(account["is_gmsa"])
        self.assertTrue(account["gmsa_password_readable"])
        self.assertFalse(account["kerberoastable"])
        self.assertNotIn("managed_password", account)
        self.assertNotIn("msDS-ManagedPassword", account)

    def test_modern_windows_laps_is_classified(self):
        collector = self.collector()
        entry = {
            "dn": "CN=WS01,CN=Computers,DC=lab,DC=example",
            "attributes": {
                "samAccountName": "WS01$",
                "dNSHostName": "ws01.lab.example",
                "objectSid": "S-1-5-21-1-2-3-1300",
                "userAccountControl": 0,
                "memberOf": [],
                "msLAPS-Password": '{"n":"Administrator","p":"secret"}',
                "msLAPS-PasswordExpirationTime": "133700000000000000",
            },
        }
        collector._search = lambda *args, **kwargs: [entry]

        computers = collector.collect_computers()
        computer = computers["S-1-5-21-1-2-3-1300"]

        self.assertTrue(computer["laps_readable"])
        self.assertEqual(computer["laps_scheme"], "Windows LAPS")
        self.assertNotIn("is_gmsa", computer)


if __name__ == "__main__":
    unittest.main()
