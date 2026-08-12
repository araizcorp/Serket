import json
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import unittest

import networkx as nx

from serket.output.saver import load_results, reconstruct_graph, save_results


class SaverBundleTests(unittest.TestCase):
    def synthetic_data(self):
        domain_sid = "S-1-5-21-100-200-300"
        return {
            "domain": {"name": "lab.example", "sid": domain_sid},
            "users": {f"{domain_sid}-1100": {"name": "alice"}},
            "groups": {},
            "computers": {},
            "directory_objects": {},
            "gpos": [],
            "trusts": [],
            "acls": [],
            "adcs": {},
            "sid_name": {f"{domain_sid}-1100": "alice"},
            "quality": {"status": "ok"},
            "coverage": {"directory": {"status": "collected"}},
            "system_counts": {
                "workstation": 0,
                "server": 0,
                "domain_controller": 0,
            },
            "telemetry": {"queries": 3},
        }

    def test_bundle_round_trip_composes_all_json_components(self):
        graph = nx.MultiDiGraph()
        graph.add_node("S-1-5-21-100-200-300-1100", name="alice", type="User")
        ag = SimpleNamespace(G=graph, high_value=set())

        with TemporaryDirectory() as temp_dir:
            bundle = Path(save_results(
                self.synthetic_data(),
                {"nodes": 1, "edges": 0},
                {"surface": {}, "paths": []},
                temp_dir,
                ag=ag,
            ))

            self.assertTrue((bundle / "manifest.json").is_file())
            self.assertTrue((bundle / "permissions.json").is_file())
            self.assertTrue((bundle / "graph.json").is_file())
            self.assertFalse((Path(temp_dir) / f"{bundle.name}.json").exists())

            loaded = load_results(str(bundle))
            self.assertEqual(loaded["domain"]["name"], "lab.example")
            self.assertEqual(loaded["users"]["S-1-5-21-100-200-300-1100"]["name"], "alice")
            self.assertEqual(loaded["stats"]["nodes"], 1)
            self.assertIsNotNone(reconstruct_graph(loaded))

            from_manifest = load_results(str(bundle / "manifest.json"))
            self.assertEqual(from_manifest["meta"]["collection"]["queries"], 3)

    def test_bundle_rejects_component_outside_collection_directory(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "format": "serket-collection-bundle",
                "schema_version": 1,
                "files": {"domain": "../outside.json"},
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "escapes"):
                load_results(str(manifest))

    def test_domain_name_cannot_escape_output_directory(self):
        ad_data = self.synthetic_data()
        ad_data["domain"]["name"] = "../../lab.example"

        with TemporaryDirectory() as temp_dir:
            bundle = Path(save_results(
                ad_data,
                {"nodes": 0, "edges": 0},
                {"surface": {}, "paths": []},
                temp_dir,
            ))

            self.assertEqual(bundle.parent.resolve(), Path(temp_dir).resolve())
            self.assertTrue(bundle.name.startswith("serket_lab_example_"))

    def test_legacy_single_json_remains_loadable(self):
        with TemporaryDirectory() as temp_dir:
            legacy = Path(temp_dir) / "legacy.json"
            legacy.write_text(json.dumps({
                "meta": {"tool": "Serket"},
                "domain": {"name": "lab.example"},
            }), encoding="utf-8")

            self.assertEqual(load_results(str(legacy))["domain"]["name"], "lab.example")


if __name__ == "__main__":
    unittest.main()
