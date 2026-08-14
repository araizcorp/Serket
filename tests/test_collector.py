import unittest
import struct
from types import SimpleNamespace
from unittest.mock import patch

from ldap3.protocol.convert import build_controls_list

from serket.collector.acl_parser import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    GENERIC_ALL,
    PROP_GUID,
    _classify_ace,
)
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
    @staticmethod
    def sid_bytes(*subauthorities: int) -> bytes:
        return (
            bytes([1, len(subauthorities)])
            + (5).to_bytes(6, "big")
            + b"".join(struct.pack("<I", value) for value in subauthorities)
        )

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

    def test_dacl_controls_are_passed_in_ldap3_native_shape(self):
        collector = self.collector()
        captured = []

        def capture_search(*args, **kwargs):
            controls = kwargs.get("controls")
            if controls is None and len(args) > 4:
                controls = args[4]
            if controls:
                captured.append(controls)
            return []

        collector._search = capture_search
        collector._acl_search(collector.base_dn, "(objectClass=domain)")
        collector.collect_acls()
        collector.config_dn = "CN=Configuration,DC=lab,DC=example"
        collector.collect_adcs()

        self.assertEqual(len(captured), 4)
        for controls in captured:
            self.assertEqual(len(controls), 1)
            self.assertNotIsInstance(controls[0], list)
            self.assertIsNotNone(build_controls_list(controls))

    def test_integer_attributes_accept_scalars_lists_and_invalid_values(self):
        self.assertEqual(_int(512), 512)
        self.assertEqual(_int(["4194304"]), UAC_DONT_REQ_PREAUTH)
        self.assertEqual(_int([], 10), 10)
        self.assertEqual(_int(["invalid"], 7), 7)

    def test_domain_policy_preserves_legacy_keys_and_minute_precision(self):
        collector = self.collector()
        collector._search = lambda *args, **kwargs: [{
            "dn": collector.base_dn,
            "attributes": {
                "objectSid": "S-1-5-21-1-2-3",
                "minPwdLength": "14",
                "minPwdAge": "-864000000000",
                "maxPwdAge": "-36288000000000",
                "pwdHistoryLength": "24",
                "lockoutThreshold": "5",
                "lockoutDuration": "-18000000000",
                "lockoutObservationWindow": "-18000000000",
                "pwdProperties": "17",
                "ms-DS-MachineAccountQuota": "10",
            },
        }]

        domain = collector.get_domain_info()

        self.assertEqual(domain["min_pwd_length"], 14)
        self.assertEqual(domain["lockout_threshold"], 5)
        self.assertEqual(domain["password_policy"]["max_age_days"], 42)
        self.assertTrue(domain["password_policy"]["complexity_required"])
        self.assertTrue(domain["password_policy"]["store_cleartext"])
        self.assertEqual(domain["lockout_policy"]["duration_minutes"], 30)

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

    def test_users_expose_password_and_activity_posture(self):
        collector = self.collector()
        old_filetime = 132537600000000000  # 2020-12-30 UTC
        collector._search = lambda *args, **kwargs: [{
            "dn": "CN=alice,CN=Users,DC=lab,DC=example",
            "attributes": {
                "samAccountName": "alice",
                "objectSid": "S-1-5-21-1-2-3-1100",
                "userAccountControl": 0x00010020,
                "adminCount": 0,
                "memberOf": [],
                "servicePrincipalName": [],
                "pwdLastSet": old_filetime,
                "lastLogonTimestamp": old_filetime,
                "accountExpires": 0x7FFFFFFFFFFFFFFF,
            },
        }]

        user = collector.collect_users()["S-1-5-21-1-2-3-1100"]

        self.assertTrue(user["pwd_never_expires"])
        self.assertTrue(user["pwd_not_required"])
        self.assertGreater(user["pwd_age_days"], 730)
        self.assertTrue(user["stale"])
        self.assertIsNone(user["account_expires"])
        self.assertTrue(user["pwd_last_set"].endswith("+00:00"))

    def test_raw_sid_wins_over_corrupt_decoded_attribute(self):
        collector = self.collector()
        sid = "S-1-5-21-1-2-3-512"
        collector._search = lambda *args, **kwargs: [{
            "dn": "CN=Domain Admins,CN=Users,DC=lab,DC=example",
            "attributes": {
                "samAccountName": "Domain Admins",
                "objectSid": "\x01\x05corrupt",
                "member": [],
                "memberOf": [],
                "adminCount": 1,
            },
            "raw_attributes": {
                "objectSid": [self.sid_bytes(21, 1, 2, 3, 512)],
            },
        }]

        groups = collector.collect_groups()

        self.assertIn(sid, groups)
        self.assertTrue(groups[sid]["high_value"])

    def test_acl_uses_raw_security_descriptor_and_target_sid(self):
        collector = self.collector()
        trustee = self.sid_bytes(21, 1, 2, 3, 1100)
        target = self.sid_bytes(21, 1, 2, 3, 2100)
        ace_body = struct.pack("<I", GENERIC_ALL) + trustee
        ace = bytes([0, 0]) + struct.pack("<H", 4 + len(ace_body)) + ace_body
        acl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
        descriptor = struct.pack("<BBHLLLL", 1, 0, 0x8004, 0, 0, 0, 20) + acl
        collector._search = lambda *args, **kwargs: [{
            "dn": "CN=Target,CN=Users,DC=lab,DC=example",
            "attributes": {
                "objectSid": "corrupt-target",
                "nTSecurityDescriptor": "corrupt-descriptor",
                "objectClass": ["top", "group"],
                "samAccountName": "Target",
            },
            "raw_attributes": {
                "objectSid": [target],
                "nTSecurityDescriptor": [descriptor],
            },
        }]

        permissions = collector.collect_acls()

        generic_all = next(item for item in permissions if item["edge_type"] == "GenericAll")
        self.assertEqual(generic_all["sid"], "S-1-5-21-1-2-3-1100")
        self.assertEqual(generic_all["target_sid"], "S-1-5-21-1-2-3-2100")
        self.assertEqual(generic_all["target_type"], "Group")

    @patch("serket.collector.ldap_collector.parse_security_descriptor")
    def test_dcsync_is_derived_from_both_replication_rights(self, parse_descriptor):
        collector = self.collector()
        trustee_sid = "S-1-5-21-1-2-3-1100"
        parse_descriptor.return_value = [
            {"sid": trustee_sid, "edge_type": "GetChanges", "object_guid": "a", "ace_flags": 0},
            {"sid": trustee_sid, "edge_type": "GetChangesAll", "object_guid": "b", "ace_flags": 0},
        ]
        collector._search = lambda *args, **kwargs: [{
            "dn": collector.base_dn,
            "attributes": {
                "objectSid": "corrupt",
                "objectClass": ["top", "domainDNS"],
                "name": "lab",
            },
            "raw_attributes": {
                "objectSid": [self.sid_bytes(21, 1, 2, 3)],
                "nTSecurityDescriptor": [b"descriptor"],
            },
        }]

        permissions = collector.collect_acls()

        dcsync = [item for item in permissions if item["edge_type"] == "DCSync"]
        self.assertEqual(len(dcsync), 1)
        self.assertEqual(dcsync[0]["sid"], trustee_sid)

    @patch("serket.collector.ldap_collector.parse_security_descriptor")
    def test_single_replication_right_is_not_promoted_to_dcsync(self, parse_descriptor):
        collector = self.collector()
        parse_descriptor.return_value = [{
            "sid": "S-1-5-21-1-2-3-1100",
            "edge_type": "GetChangesAll",
            "object_guid": "b",
            "ace_flags": 0,
        }]
        collector._search = lambda *args, **kwargs: [{
            "dn": collector.base_dn,
            "attributes": {
                "objectSid": "corrupt",
                "objectClass": ["top", "domainDNS"],
                "name": "lab",
            },
            "raw_attributes": {
                "objectSid": [self.sid_bytes(21, 1, 2, 3)],
                "nTSecurityDescriptor": [b"descriptor"],
            },
        }]

        permissions = collector.collect_acls()

        self.assertFalse(any(item["edge_type"] == "DCSync" for item in permissions))

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

    def test_computers_are_classified_by_role(self):
        collector = self.collector()
        entries = []
        fixtures = [
            (1301, "WS01$", "Windows 11 Enterprise", 0, "workstation"),
            (1302, "APP01$", "Windows Server 2022", 0, "server"),
            (1303, "DC01$", "Windows Server 2022", 0x2000, "domain_controller"),
        ]
        for rid, name, os_name, uac, _role in fixtures:
            entries.append({
                "dn": f"CN={name},CN=Computers,DC=lab,DC=example",
                "attributes": {
                    "samAccountName": name,
                    "objectSid": "corrupt",
                    "userAccountControl": uac,
                    "operatingSystem": os_name,
                    "memberOf": [],
                },
                "raw_attributes": {
                    "objectSid": [self.sid_bytes(21, 1, 2, 3, rid)],
                },
            })
        collector._search = lambda *args, **kwargs: entries

        computers = collector.collect_computers()

        for rid, _name, _os_name, _uac, role in fixtures:
            self.assertEqual(computers[f"S-1-5-21-1-2-3-{rid}"]["computer_role"], role)

    def test_gpo_ldap_metadata_and_link_options_are_normalized(self):
        collector = self.collector()
        gpo_guid = "11111111-2222-3333-4444-555555555555"

        def search(_base, ldap_filter, *_args, **_kwargs):
            if ldap_filter == "(objectClass=groupPolicyContainer)":
                return [{
                    "dn": f"CN={{{gpo_guid}}},CN=Policies,CN=System,{collector.base_dn}",
                    "attributes": {
                        "displayName": "Tier 0 Policy",
                        "objectGUID": gpo_guid,
                        "gPCFileSysPath": rf"\\lab.example\SYSVOL\lab.example\Policies\{{{gpo_guid}}}",
                        "gPCFunctionalityVersion": "2",
                        "versionNumber": "65538",
                        "flags": "1",
                        "gPCMachineExtensionNames": ["[{machine-extension}]"],
                        "gPCUserExtensionNames": [],
                    },
                }]
            return [{
                "dn": f"OU=Domain Controllers,{collector.base_dn}",
                "attributes": {
                    "gPLink": (
                        f"[LDAP://CN={{{gpo_guid}}},CN=Policies,CN=System,"
                        f"{collector.base_dn};2]"
                    ),
                    "gPOptions": "1",
                },
            }]

        collector._search = search
        gpo = collector.collect_gpos()[0]

        self.assertFalse(gpo["user_settings_enabled"])
        self.assertTrue(gpo["computer_settings_enabled"])
        self.assertEqual(gpo["functionality_version"], 2)
        self.assertEqual(gpo["version_number"], 65538)
        self.assertTrue(gpo["links"][0]["enabled"])
        self.assertTrue(gpo["links"][0]["enforced"])
        self.assertTrue(gpo["links"][0]["target_blocks_inheritance"])

    def test_apply_group_policy_extended_right_is_preserved(self):
        self.assertEqual(
            _classify_ace(
                ADS_RIGHT_DS_CONTROL_ACCESS,
                "edacfd8f-ffb3-11d1-b41d-00a0c968f939",
            ),
            "ApplyGroupPolicy",
        )


if __name__ == "__main__":
    unittest.main()
