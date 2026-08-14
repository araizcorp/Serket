import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
import zipfile

import networkx as nx

from serket.collector.adcs_analysis import analyze_ca, analyze_template
from serket.detection_catalog import DETECTION_CATALOG
from serket.output.saver import load_results, save_results
from serket.server.api import create_app


class V21Tests(unittest.TestCase):
    def data(self):
        sid = "S-1-5-21-1-2-3"
        return {
            "domain": {"name": "lab.example", "sid": sid},
            "users": {f"{sid}-1100": {"name": "alice", "dn": "CN=alice,DC=lab,DC=example"}},
            "groups": {}, "computers": {}, "directory_objects": {},
            "gpos": [], "trusts": [], "acls": [], "adcs": {},
            "sid_name": {f"{sid}-1100": "alice"},
            "quality": {"status": "ok"}, "coverage": {}, "system_counts": {},
            "telemetry": {"profile": "low-impact"},
        }

    def test_portable_package_round_trip_and_reliquary_bridge(self):
        graph = nx.MultiDiGraph()
        graph.add_node("S-1-5-21-1-2-3-1100", name="alice", type="User")
        ag = SimpleNamespace(G=graph, high_value=set())
        with TemporaryDirectory() as temp:
            analysis = {
                "surface": {}, "paths": [], "snapshot_id": "snapshot-test",
                "findings": [{"id": "finding://serket/v1/snapshot-test/1", "object_id": "S-1-5-21-1-2-3-1100"}],
                "risk_summary": {"risk_model": "serket-risk/v1", "global_score": 25},
            }
            bundle = Path(save_results(self.data(), {"nodes": 1}, analysis, temp, ag))
            package = bundle.with_suffix(".serket")
            self.assertTrue(package.is_file())
            loaded = load_results(str(package))
            self.assertEqual(loaded["domain"]["name"], "lab.example")
            self.assertEqual(loaded["interchange"]["schema"], "araizcorp-identity-bridge/v1")
            self.assertFalse(loaded["interchange"]["sensitive_values_included"])
            self.assertEqual(loaded["snapshot_id"], "snapshot-test")
            self.assertEqual(loaded["risk_summary"]["global_score"], 25)
            self.assertEqual(loaded["findings"][0]["object_id"], "S-1-5-21-1-2-3-1100")
            with zipfile.ZipFile(package) as archive:
                self.assertIn("interchange.json", archive.namelist())

    def test_directory_bundle_detects_tampering(self):
        with TemporaryDirectory() as temp:
            bundle = Path(save_results(self.data(), {}, {"surface": {}, "paths": []}, temp))
            users = bundle / "users.json"
            payload = json.loads(users.read_text(encoding="utf-8"))
            payload["data"]["forged"] = {"name": "tampered"}
            users.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity check failed"):
                load_results(str(bundle))

    def test_adcs_esc1_to_esc4_and_explicit_esc6_to_esc8_unknowns(self):
        sid = "S-1-5-21-1-2-3-513"
        result = analyze_template(
            name_flag=1,
            enrollment_flag=0,
            ekus=["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.1", "2.5.29.37.0"],
            ra_signatures=0,
            enroll_sids=[sid],
            acl_aces=[{"sid": sid, "edge_type": "WriteDACL"}],
            published=True,
        )
        self.assertEqual({item["id"] for item in result["findings"]}, {"ESC1", "ESC2", "ESC3", "ESC4"})
        ca = analyze_ca([], ["User"])
        unknown = {item["id"] for item in ca["findings"] if item["status"] == "not_assessed"}
        self.assertEqual(unknown, {"ESC6", "ESC7", "ESC8"})

    def test_detection_catalog_covers_extended_read_only_relationships(self):
        self.assertGreaterEqual(len(DETECTION_CATALOG), 20)
        self.assertTrue({
            "ShadowCredentials", "MAQAbuse", "DNSAdmin", "ExchangePermissions",
            "RODCCachedCredential", "PreWindows2000Access", "ForestTrust",
        }.issubset(DETECTION_CATALOG))
        self.assertTrue(all(not item["remote_execution"] for item in DETECTION_CATALOG.values()))
        app = create_app({"graph": {}})
        route = next(route for route in app.routes if getattr(route, "path", "") == "/api/detection-catalog")
        payload = __import__("asyncio").run(route.endpoint())
        self.assertEqual(payload["documented_relationships"], len(DETECTION_CATALOG))


if __name__ == "__main__":
    unittest.main()
