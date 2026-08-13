import unittest

from serket.collector.ldap_collector import (
    LDAPCollector,
    UAC_NOT_DELEGATED,
    UAC_PARTIAL_SECRETS_ACCOUNT,
    UAC_SMARTCARD_REQUIRED,
    UAC_USE_DES_KEY_ONLY,
)
from serket.graph.builder import ADGraph
from serket.graph.pathfinder import get_attack_surface


DOMAIN = "S-1-5-21-1-2-3"
USER = f"{DOMAIN}-1100"


class EnterprisePostureTests(unittest.TestCase):
    def collector(self):
        collector = LDAPCollector(
            dc_host="dc.lab.example",
            domain="lab.example",
            username="auditor",
            password="unused",
            rate_limit=0,
        )
        collector.base_dn = "DC=lab,DC=example"
        collector.domain_sid = DOMAIN
        return collector

    def test_user_security_attributes_are_normalized_without_secret_material(self):
        collector = self.collector()
        collector._search = lambda *args, **kwargs: [{
            "dn": "CN=alice,CN=Users,DC=lab,DC=example",
            "attributes": {
                "samAccountName": "alice",
                "objectSid": USER,
                "userAccountControl": (
                    UAC_SMARTCARD_REQUIRED | UAC_NOT_DELEGATED | UAC_USE_DES_KEY_ONLY
                ),
                "memberOf": [],
                "servicePrincipalName": [],
                "adminCount": 1,
                "msDS-KeyCredentialLink": ["B:8:00112233:CN=alice,CN=Users,DC=lab,DC=example"],
                "msDS-User-Account-Control-Computed": 0x10,
                "logonHours": b"restricted",
                "userWorkstations": "WS01,WS02",
                "primaryGroupID": 513,
                "msDS-AssignedAuthNPolicy": "CN=Tier0,CN=AuthN Policies,DC=lab,DC=example",
            },
        }]

        user = collector.collect_users()[USER]

        self.assertTrue(user["has_key_credential_link"])
        self.assertTrue(user["smartcard_required"])
        self.assertTrue(user["not_delegated"])
        self.assertTrue(user["use_des_key_only"])
        self.assertTrue(user["locked_out"])
        self.assertTrue(user["logon_hours_restricted"])
        self.assertEqual(user["user_workstations"], ["WS01", "WS02"])
        self.assertEqual(user["primary_group_id"], 513)
        self.assertTrue(user["authn_policy_assigned"])
        self.assertNotIn("key_credential_link", user)

    def test_special_groups_and_protected_users_gap_are_classified(self):
        collector = self.collector()
        entries = []
        for rid, name in (
            (525, "Protected Users"),
            (571, "Key Admins"),
            (2200, "DnsAdmins"),
            (2201, "Exchange Windows Permissions"),
            (554, "Pre-Windows 2000 Compatible Access"),
        ):
            sid = f"{DOMAIN}-{rid}" if rid != 554 else "S-1-5-32-554"
            entries.append({
                "dn": f"CN={name},CN=Users,DC=lab,DC=example",
                "attributes": {
                    "samAccountName": name,
                    "objectSid": sid,
                    "member": [], "memberOf": [], "adminCount": 0,
                },
            })
        collector._search = lambda *args, **kwargs: entries
        groups = collector.collect_groups()

        self.assertTrue(groups[f"{DOMAIN}-525"]["is_protected_users"])
        self.assertTrue(groups[f"{DOMAIN}-571"]["is_key_admin"])
        self.assertTrue(groups[f"{DOMAIN}-2200"]["is_dns_admins"])
        self.assertTrue(groups[f"{DOMAIN}-2201"]["is_exchange_privileged"])
        self.assertTrue(groups["S-1-5-32-554"]["is_prewin2000_compatible"])

        users = {USER: {
            "name": "alice", "admin_count": 1, "enabled": True,
            "effective_member_of": [],
        }}
        groups["S-1-5-32-554"]["members"] = ["S-1-5-11"]
        collector._apply_security_posture(users, groups, {})
        self.assertTrue(users[USER]["missing_protected_users"])
        self.assertTrue(groups["S-1-5-32-554"]["prewin2000_exposure"])

    def test_rodc_and_operating_system_inventory_are_collected(self):
        collector = self.collector()
        user_dn = "CN=alice,CN=Users,DC=lab,DC=example"
        collector._search = lambda *args, **kwargs: [{
            "dn": "CN=RODC01,OU=Domain Controllers,DC=lab,DC=example",
            "attributes": {
                "samAccountName": "RODC01$",
                "dNSHostName": "rodc01.lab.example",
                "objectSid": f"{DOMAIN}-1001",
                "userAccountControl": 0x2000 | UAC_PARTIAL_SECRETS_ACCOUNT,
                "operatingSystem": "Windows Server 2025 Standard",
                "operatingSystemVersion": "10.0 (26100)",
                "operatingSystemServicePack": "",
                "memberOf": [],
                "msDS-RevealedUsers": [f"B:8:00112233:{user_dn}"],
                "msDS-RevealOnDemandGroup": ["CN=Allowed RODC Password Replication Group,CN=Users,DC=lab,DC=example"],
            },
        }]

        computer = collector.collect_computers()[f"{DOMAIN}-1001"]

        self.assertTrue(computer["is_rodc"])
        self.assertEqual(computer["rodc_revealed_user_dns"], [user_dn])
        self.assertEqual(computer["os_version"], "10.0 (26100)")
        self.assertEqual(computer["os_display"], "Windows Server 2025 Standard 10.0.26100")
        self.assertEqual(computer["os_inventory_key"], "Server 2025 Standard 10.0.26100")

    def test_trust_attributes_follow_official_ad_values(self):
        collector = self.collector()
        collector._search = lambda *args, **kwargs: [{
            "dn": "CN=partner.example,CN=System,DC=lab,DC=example",
            "attributes": {
                "trustPartner": "partner.example",
                "flatName": "PARTNER",
                "securityIdentifier": "S-1-5-21-9-8-7",
                "trustDirection": 3,
                "trustType": 2,
                "trustAttributes": 0x08 | 0x40,
            },
        }]

        trust = collector.collect_trusts()[0]

        self.assertEqual(trust["trust_type"], "Windows Active Directory")
        self.assertEqual(trust["direction"], "Bidirectional")
        self.assertTrue(trust["is_forest"])
        self.assertTrue(trust["sid_filtering_relaxed"])
        self.assertTrue(trust["sid_filtering_risk"])

    def test_graph_projects_maq_special_memberships_rodc_and_trusts(self):
        protected = f"{DOMAIN}-525"
        dns_admins = f"{DOMAIN}-2200"
        rodc = f"{DOMAIN}-1001"
        data = {
            "domain": {"sid": DOMAIN, "name": "lab.example", "maq": 10},
            "users": {USER: {
                "name": "alice", "dn": "CN=alice,DC=lab,DC=example",
                "enabled": True, "kerberoastable": False, "asreproastable": False,
                "unconstrained": False, "constrained": True,
                "delegation_targets": ["HTTP/app.lab.example"], "spns": [],
                "admin_count": 1, "effective_member_of": [dns_admins],
                "has_key_credential_link": True,
            }},
            "groups": {
                protected: {"name": "Protected Users", "dn": "CN=Protected Users,DC=lab,DC=example", "admin_count": 0, "high_value": True, "is_protected_users": True},
                dns_admins: {"name": "DnsAdmins", "dn": "CN=DnsAdmins,DC=lab,DC=example", "admin_count": 0, "high_value": True, "is_dns_admins": True},
            },
            "computers": {rodc: {
                "name": "RODC01$", "dn": "CN=RODC01,DC=lab,DC=example", "dns": "",
                "os": "Windows Server 2025", "os_version": "10.0", "computer_role": "domain_controller",
                "is_dc": True, "is_rodc": True, "unconstrained": False, "constrained": False,
                "rodc_revealed_users": [USER], "rodc_tier0_revealed_users": [USER],
                "rodc_tier0_exposure": True, "effective_member_of": [],
            }},
            "directory_objects": {}, "gpos": [], "acls": [], "adcs": {},
            "trusts": [{
                "partner": "partner.example", "partner_sid": "S-1-5-21-9-8-7",
                "direction": "Bidirectional", "trust_type": "Windows Active Directory",
                "is_forest": True, "is_transitive": True,
                "sid_filtering_status": "forest-relaxed-to-external",
                "sid_filtering_risk": True,
            }],
            "sid_name": {"S-1-5-11": "Authenticated Users"}, "dn_map": {},
        }

        attack_graph = ADGraph.build_from_data(data)
        graph = attack_graph.G

        self.assertTrue(graph.has_edge("S-1-5-11", DOMAIN, key="MAQAbuse"))
        self.assertTrue(graph.has_edge(USER, USER, key="ShadowCredentials"))
        self.assertTrue(graph.has_edge(USER, dns_admins, key="DNSAdmin"))
        self.assertTrue(graph.has_edge(rodc, USER, key="RODCCachedCredential"))
        self.assertTrue(graph.has_edge(DOMAIN, "S-1-5-21-9-8-7", key="ForestTrust"))
        self.assertTrue(graph.has_edge("S-1-5-21-9-8-7", DOMAIN, key="ForestTrust"))
        constrained = get_attack_surface(attack_graph, data)["constrained"]
        self.assertEqual(constrained[0]["targets"], ["HTTP/app.lab.example"])


if __name__ == "__main__":
    unittest.main()
