"""Tests for LAPS/gMSA ACL edges, MAQ and sAMAccountName spoofing findings."""
import unittest
from serket.collector.acl_parser import _classify_ace, MITRE
from serket.finding_engine import generate_findings
from serket.graph.builder import ADGraph, _add_edge, EDGE_OPSEC, MITRE_MAP
from serket.graph.pathfinder import SUGGESTED_COMMANDS
from serket.sensitivity import propagate_sensitivity

CONTROL_ACCESS = 0x00000100


class LapsGmsaEdgeTests(unittest.TestCase):
    def test_laps_legacy_guid_classifies_as_readlapspassword(self):
        # Legacy LAPS GUIDs are forest-specific; resolved via schema_names
        self.assertEqual(
            _classify_ace(CONTROL_ACCESS, "aaaa-bbbb", {"aaaa-bbbb": "ms-Mcs-AdmPwd"}),
            "ReadLAPSPassword",
        )

    def test_windows_laps_guid_classifies_as_readlapspassword(self):
        self.assertEqual(
            _classify_ace(CONTROL_ACCESS, "cccc-dddd", {"cccc-dddd": "ms-LAPS-Password"}),
            "ReadLAPSPassword",
        )

    def test_gmsa_guid_classifies_as_readgmsapassword(self):
        self.assertEqual(
            _classify_ace(
                CONTROL_ACCESS,
                "e362ed86-b728-0842-b27d-2dea7a9df218",
                {"e362ed86-b728-0842-b27d-2dea7a9df218": "ms-DS-ManagedPassword"},
            ),
            "ReadGMSAPassword",
        )

    def test_unknown_control_access_without_schema_falls_back(self):
        self.assertEqual(_classify_ace(CONTROL_ACCESS, "unknown-guid"), "AllExtendedRights")
        self.assertEqual(
            _classify_ace(CONTROL_ACCESS, "unknown-guid", {"unknown-guid": "someAttribute"}),
            "AllExtendedRights",
        )

    def test_mitre_entries_exist(self):
        self.assertIn("ReadLAPSPassword", MITRE)
        self.assertIn("ReadGMSAPassword", MITRE)

    def test_graph_tables_include_new_edges(self):
        for edge in ("ReadLAPSPassword", "ReadGMSAPassword"):
            self.assertIn(edge, EDGE_OPSEC)
            self.assertIn(edge, MITRE_MAP)

    def test_suggested_commands_cover_new_techniques(self):
        for key in ("ReadLAPSPassword", "ReadGMSAPassword",
                    "MachineAccountQuota", "SAMAccountNameSpoofing"):
            self.assertIn(key, SUGGESTED_COMMANDS)
            self.assertTrue(SUGGESTED_COMMANDS[key])


class MaqFindingTests(unittest.TestCase):
    def _ad_data(self, maq):
        return {
            "domain": {"name": "lab.example", "sid": "S-1-5-21-1", "maq": maq},
            "telemetry": {"started_at": "2026-08-14T09:00:00+00:00"},
            "users": {}, "computers": {},
        }

    def _graph_with_dc(self):
        ag = ADGraph()
        ag._add_node("dc1", "DC01$", "DomainController", is_dc=True)
        return ag

    def test_maq_enabled_finding_raised_when_quota_positive(self):
        ag = self._graph_with_dc()
        propagate_sensitivity(ag)
        result = generate_findings(ad_data=self._ad_data(10), ag=ag)
        badges = {f["badge"] for f in result["findings"]}
        self.assertIn("MAQ_ENABLED", badges)
        self.assertIn("SPOOFABLE_SAMNAME", badges)

    def test_no_maq_findings_when_quota_zero(self):
        ag = self._graph_with_dc()
        propagate_sensitivity(ag)
        result = generate_findings(ad_data=self._ad_data(0), ag=ag)
        badges = {f["badge"] for f in result["findings"]}
        self.assertNotIn("MAQ_ENABLED", badges)
        self.assertNotIn("SPOOFABLE_SAMNAME", badges)

    def test_spoofing_requires_a_dc(self):
        ag = ADGraph()  # no DC node
        propagate_sensitivity(ag)
        result = generate_findings(ad_data=self._ad_data(10), ag=ag)
        badges = {f["badge"] for f in result["findings"]}
        self.assertIn("MAQ_ENABLED", badges)
        self.assertNotIn("SPOOFABLE_SAMNAME", badges)


class SchemaNamesCollectionTests(unittest.TestCase):
    def _collector(self):
        from serket.collector.ldap_collector import LDAPCollector
        collector = LDAPCollector(
            dc_host="dc.lab.example",
            domain="lab.example",
            username="auditor",
            password="not-used",
            rate_limit=0,
        )
        collector.base_dn = "DC=lab,DC=example"
        return collector

    def test_schema_names_resolved_from_schema_partition(self):
        import uuid

        collector = self._collector()
        raw = uuid.UUID("4c9928d7-d725-4fa6-a109-aba3ad8790e5").bytes_le

        def fake_search(base, filt, attrs, scope, controls=None):
            self.assertIn("CN=Schema", base)
            return [{
                "dn": "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=lab,DC=example",
                "attributes": {"lDAPDisplayName": "ms-Mcs-AdmPwd", "schemaIDGUID": raw},
            }]

        collector._search = fake_search
        names = collector.collect_schema_names()
        self.assertEqual(names.get("4c9928d7-d725-4fa6-a109-aba3ad8790e5"), "ms-Mcs-AdmPwd")

    def test_schema_names_falls_back_on_ldap_error(self):
        from serket.collector.ldap_collector import LDAPException

        collector = self._collector()

        def failing(base, filt, attrs, scope, controls=None):
            raise LDAPException("denied")

        collector._search = failing
        names = collector.collect_schema_names()
        # gMSA well-known default survives
        self.assertEqual(
            names.get("e362ed86-b728-0842-b27d-2dea7a9df218"), "ms-DS-ManagedPassword"
        )


if __name__ == "__main__":
    unittest.main()
