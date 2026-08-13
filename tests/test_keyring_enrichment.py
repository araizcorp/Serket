from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from serket.collector.ldap_collector import LDAPCollector
from serket.enrichment import EnrichmentError, apply_bridge, save_enriched_package, validate_bridge
from serket.graph.builder import ADGraph
from serket.output.saver import load_results
from serket.server.api import create_app


SID = "S-1-5-21-1-2-3-1100"


def bridge():
    return {
        "bridge_version": "1.0",
        "generated": "2026-08-13T10:00:00Z",
        "domain": "corp.local",
        "enrichments": [
            {
                "identity_type": "user",
                "identity_key": SID,
                "enrichment_type": "credential_reuse",
                "severity": "high",
                "details": {
                    "shared_secret_count": 1,
                    "shared_identity_count": 3,
                    "shared_with_sids": [],
                    "shared_with_names": ["bob", "svc_backup"],
                    "cloud_linked": True,
                    "cloud_identities": ["backup@example-cloud"],
                },
            },
            {
                "identity_type": "user",
                "identity_key": SID,
                "enrichment_type": "credential_hygiene",
                "severity": "high",
                "details": {
                    "password_reused_in": 3,
                    "password_age_days": None,
                    "matches_domain_policy": None,
                    "crackability_score": None,
                },
            },
        ],
    }


def result_data():
    return {
        "meta": {},
        "domain": {"name": "corp.local", "password_policy": {"max_age_days": 42}},
        "users": {}, "groups": {}, "computers": {}, "directory_objects": {},
        "gpos": [], "trusts": [], "acls": [], "adcs": {}, "interchange": {},
        "stats": {}, "sid_name": {}, "quality": {}, "coverage": {}, "system_counts": {},
        "surface": {}, "paths": [], "high_value": [],
        "graph": {
            "directed": True,
            "multigraph": True,
            "nodes": [{"id": SID, "name": "alice", "type": "User", "pwd_age_days": 892}],
            "edges": [],
        },
    }


class KeyringEnrichmentTests(unittest.TestCase):
    def test_bridge_enriches_node_and_combines_ldap_policy_age(self):
        data = result_data()
        report = apply_bridge(data, bridge())
        node = data["graph"]["nodes"][0]
        self.assertEqual(report["matched"], 2)
        self.assertTrue(node["credential_reuse"])
        self.assertTrue(node["cloud_linked"])
        self.assertEqual(node["reuse_count"], 3)
        self.assertEqual(node["keyring_password_age_days"], 892)
        self.assertFalse(node["matches_domain_policy"])

    def test_bridge_rejects_secret_material_fields(self):
        unsafe = bridge()
        unsafe["enrichments"][0]["details"]["secret_value"] = "must-not-pass"
        with self.assertRaisesRegex(EnrichmentError, "prohibited sensitive field"):
            validate_bridge(unsafe)

    def test_name_domain_identity_falls_back_to_one_unique_serket_name(self):
        data = result_data()
        name_bridge = bridge()
        for item in name_bridge["enrichments"]:
            item["identity_key"] = "alice@CORP"
        report = apply_bridge(data, name_bridge)
        self.assertEqual(report["matched"], 2)

    def test_enriched_package_round_trip(self):
        data = result_data()
        apply_bridge(data, bridge())
        with TemporaryDirectory() as temp:
            output = save_enriched_package(data, Path(temp) / "enriched.serket")
            loaded = load_results(str(output))
        node = loaded["graph"]["nodes"][0]
        self.assertTrue(node["credential_reuse"])
        self.assertFalse(node["matches_domain_policy"])

    def test_local_api_enrich_endpoint_accepts_json_bridge(self):
        from fastapi.testclient import TestClient

        data = result_data()
        response = TestClient(create_app(data)).post("/api/enrich", json=bridge())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["matched"], 2)
        self.assertTrue(data["graph"]["nodes"][0]["credential_reuse"])

    def test_shadow_maq_and_adminsdholder_p0_findings(self):
        domain_sid = "S-1-5-21-1-2-3"
        data = {
            "domain": {"name": "corp.local", "sid": domain_sid, "maq": 10},
            "users": {
                SID: {
                    "name": "alice", "dn": "CN=alice,DC=corp,DC=local",
                    "enabled": True, "kerberoastable": False,
                    "asreproastable": False, "unconstrained": False,
                    "spns": [], "admin_count": 1,
                    "has_key_credential_link": True,
                }
            },
            "groups": {}, "computers": {}, "directory_objects": {},
            "gpos": [], "acls": [], "adcs": {},
        }
        graph = ADGraph.build_from_data(data).G
        self.assertTrue(graph.has_edge("S-1-5-11", domain_sid, key="MAQAbuse"))
        self.assertTrue(graph.has_edge(SID, SID, key="ShadowCredentials"))

        collector = object.__new__(LDAPCollector)
        collector._adminsdholder_dacl_fingerprint = "expected"
        collector._dacl_fingerprints = {SID: "different"}
        collector._apply_adminsdholder_drift(data["users"], data["groups"])
        self.assertTrue(data["users"][SID]["adminsdholder_drift"])


if __name__ == "__main__":
    unittest.main()
