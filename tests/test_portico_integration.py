from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from serket.enrichment import EnrichmentError, save_enriched_package
from serket.external_surface import apply_external_bridge, validate_external_bridge
from serket.graph.builder import ADGraph
from serket.output.saver import load_results
from serket.server.api import create_app


def bridge():
    return {
        "bridge_version": "1.0",
        "bridge_type": "external_identity_surface",
        "source": "portico",
        "generated": "2026-08-14T10:00:00Z",
        "domain": "corp.local",
        "external_exposures": [
            {
                "asset_key": "mail.corp.local",
                "match_strategy": "hostname_exact",
                "exposure_type": "external_auth_surface",
                "endpoint_kind": "owa",
                "url": "https://mail.corp.local/owa/",
                "auth_schemes": ["ntlm", "basic"],
                "product_hints": ["exchange"],
                "mfa_status": "unknown",
                "evidence_strength": "high",
                "advisory_status": "not_assessed",
            },
            {
                "asset_key": "dc.corp.local",
                "match_strategy": "hostname_exact",
                "exposure_type": "external_ldaps",
                "port": 636,
                "tls_valid": True,
                "evidence_strength": "high",
                "advisory_status": "not_assessed",
            },
        ],
    }


def result_data():
    return {
        "meta": {"snapshot_id": "snap-1"},
        "snapshot_id": "snap-1",
        "domain": {"name": "corp.local"},
        "users": {}, "groups": {}, "computers": {}, "directory_objects": {},
        "gpos": [], "trusts": [], "acls": [], "adcs": {}, "sysvol": {},
        "interchange": {}, "stats": {}, "sid_name": {}, "quality": {},
        "coverage": {}, "system_counts": {}, "surface": {}, "paths": [],
        "high_value": [], "sensitivity": {},
        "findings": [{
            "id": "old", "correlation_id": "old", "snapshot_id": "snap-1",
            "object_id": "computer-1", "category": "kerberos", "badge": "OLD",
            "severity": "low", "risk_score": 7,
        }],
        "risk_summary": {"global_score": 7},
        "posture": {"schema": "serket-posture/v1", "global_score": 7},
        "graph": {
            "directed": True, "multigraph": True, "edges": [],
            "nodes": [
                {"id": "computer-1", "name": "MAIL", "type": "Computer",
                 "dns": "wrong.corp.local", "spns": ["HTTP/mail.corp.local:443"]},
                {"id": "computer-2", "name": "DC", "type": "Computer",
                 "dns": "dc.corp.local"},
            ],
        },
    }


class PorticoIntegrationTests(unittest.TestCase):
    def test_computer_spns_are_available_for_authoritative_matching(self):
        graph = ADGraph.build_from_data({
            "domain": {}, "users": {}, "groups": {}, "directory_objects": {},
            "gpos": [], "acls": [], "adcs": {},
            "computers": {"S-1-5-21-1": {
                "name": "MAIL", "dn": "CN=MAIL,DC=corp,DC=local",
                "dns": "mail.corp.local", "spns": ["HTTP/mail.corp.local"],
                "os": "Windows Server", "computer_role": "server", "is_dc": False,
                "unconstrained": False, "constrained": False,
            }},
        }).G
        self.assertEqual(graph.nodes["S-1-5-21-1"]["spns"], ["HTTP/mail.corp.local"])

    def test_spn_precedes_dns_and_findings_are_cumulative(self):
        data = result_data()
        data["graph"]["nodes"].append({
            "id": "dns-only", "name": "duplicate", "type": "Computer",
            "dns": "mail.corp.local",
        })
        report = apply_external_bridge(data, bridge())
        self.assertEqual(report["matched_by_spn"], 1)
        self.assertEqual(report["matched_by_dns"], 1)
        badges = {item["badge"] for item in data["findings"]}
        self.assertTrue({"OLD", "EXTERNAL_OWA", "NTLM_EXPOSED_EXTERNALLY",
                         "BASIC_AUTH_EXPOSED", "MFA_UNKNOWN", "LDAPS_EXPOSED"}.issubset(badges))
        mail = data["graph"]["nodes"][0]
        self.assertEqual(mail["external_exposures"][0]["correlation_strategy"], "spn_exact")
        mfa = next(item for item in data["findings"] if item["badge"] == "MFA_UNKNOWN")
        self.assertEqual(mfa["severity"], "info")
        self.assertIn("absence is not inferred", mfa["evidence"][0]["interpretation"])

    def test_unmatched_hostname_is_retained_as_external_asset(self):
        data = result_data()
        item = bridge()
        item["external_exposures"] = [dict(item["external_exposures"][0], asset_key="vpn.corp.local", url="https://vpn.corp.local/")]
        report = apply_external_bridge(data, item)
        self.assertEqual(report["unmatched"], 1)
        self.assertTrue(any(node.get("type") == "ExternalAsset" for node in data["graph"]["nodes"]))

    def test_rejects_domain_mismatch_sensitive_fields_and_unsafe_urls(self):
        data = result_data()
        mismatch = bridge()
        mismatch["domain"] = "other.local"
        with self.assertRaisesRegex(EnrichmentError, "domains do not match"):
            apply_external_bridge(data, mismatch)
        unsafe = bridge()
        unsafe["external_exposures"][0]["authorization"] = "Basic secret"
        with self.assertRaises(EnrichmentError):
            validate_external_bridge(unsafe)
        unsafe_url = bridge()
        unsafe_url["external_exposures"][0]["url"] = "https://user:pass@mail.corp.local/owa/?token=x"
        with self.assertRaisesRegex(EnrichmentError, "unsafe URL"):
            validate_external_bridge(unsafe_url)

    def test_round_trip_preserves_pack3_posture_and_external_component(self):
        data = result_data()
        apply_external_bridge(data, bridge())
        expected_score = data["posture"]["global_score"]
        with TemporaryDirectory() as temp:
            output = save_enriched_package(data, Path(temp) / "external.serket")
            loaded = load_results(str(output))
        self.assertEqual(loaded["snapshot_id"], "snap-1")
        self.assertEqual(loaded["posture"]["global_score"], expected_score)
        self.assertEqual(loaded["external_surface_enrichment"]["source"], "portico")
        self.assertTrue(any(item["badge"] == "BASIC_AUTH_EXPOSED" for item in loaded["findings"]))

    def test_local_api_accepts_portico_bridge(self):
        from fastapi.testclient import TestClient

        data = result_data()
        response = TestClient(create_app(data)).post("/api/external-enrich", json=bridge())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["matched"], 2)
        findings = TestClient(create_app(data)).get("/api/findings?badge=BASIC_AUTH_EXPOSED")
        self.assertEqual(findings.json()["total"], 1)


if __name__ == "__main__":
    unittest.main()
