import unittest

from serket.graph.builder import ADGraph
from serket.graph.pathfinder import Pathfinder
from serket.output.saver import _repair_legacy_binary_sids


class GraphCoverageTests(unittest.TestCase):
    def data(self):
        domain = "S-1-5-21-1-2-3"
        user = f"{domain}-1100"
        domain_admins = f"{domain}-512"
        target_group = f"{domain}-2100"
        dc = f"{domain}-1000"
        server = f"{domain}-1001"
        workstation = f"{domain}-1002"
        return {
            "domain": {"sid": domain, "name": "lab.example", "dn": "DC=lab,DC=example"},
            "users": {
                user: {
                    "name": "alice", "dn": "CN=alice,DC=lab,DC=example",
                    "enabled": True, "kerberoastable": False,
                    "asreproastable": False, "unconstrained": False,
                    "constrained": False, "spns": [], "admin_count": 0,
                    "effective_member_of": [domain_admins],
                }
            },
            "groups": {
                domain_admins: {
                    "name": "Admins. del dominio", "dn": "CN=DA,DC=lab,DC=example",
                    "admin_count": 1, "effective_member_of": [],
                },
                target_group: {
                    "name": "Operators", "dn": "CN=Operators,DC=lab,DC=example",
                    "admin_count": 0, "effective_member_of": [],
                },
            },
            "computers": {
                dc: self.computer("DC01$", "domain_controller", True),
                server: self.computer("APP01$", "server", False),
                workstation: self.computer("WS01$", "workstation", False),
            },
            "directory_objects": {}, "gpos": [], "adcs": {"cas": [], "templates": []},
            "acls": [
                {"sid": user, "target_sid": target_group, "edge_type": "GenericAll"},
                {"sid": user, "target_sid": target_group, "edge_type": "WriteDACL"},
            ],
            "trusts": [], "sid_name": {}, "dn_map": {},
        }

    @staticmethod
    def computer(name, role, is_dc):
        return {
            "name": name, "dn": f"CN={name},DC=lab,DC=example", "dns": "",
            "os": "Windows Server" if role != "workstation" else "Windows 11",
            "computer_role": role, "is_dc": is_dc, "unconstrained": False,
            "constrained": False, "effective_member_of": [],
        }

    def test_roles_parallel_permissions_and_path_to_dc(self):
        data = self.data()
        graph = ADGraph.build_from_data(data)
        domain = data["domain"]["sid"]
        user = f"{domain}-1100"
        target_group = f"{domain}-2100"
        dc = f"{domain}-1000"

        self.assertEqual(graph.G.nodes[dc]["type"], "DomainController")
        self.assertEqual(graph.G.nodes[f"{domain}-1001"]["type"], "Server")
        self.assertEqual(graph.G.nodes[f"{domain}-1002"]["type"], "Workstation")
        self.assertTrue(graph.G.nodes[dc]["high_value"])
        self.assertEqual(graph.G.number_of_edges(user, target_group), 2)

        analysis = Pathfinder.find_all(graph, data, max_paths=100)
        route = next(
            path for path in analysis["paths"]
            if path["src"] == user and path["target"] == dc
        )
        self.assertEqual([step["edge_type"] for step in route["steps"]], ["MemberOf", "AdminTo"])

    def test_legacy_binary_sid_graph_is_repaired_in_memory(self):
        def binary_text(*parts):
            raw = bytes([1, len(parts)]) + (5).to_bytes(6, "big")
            raw += b"".join(int(part).to_bytes(4, "little") for part in parts)
            return raw.decode("latin-1")

        user = binary_text(21, 1, 2, 3, 1100)
        admins = binary_text(21, 1, 2, 3, 512)
        dc = binary_text(21, 1, 2, 3, 1000)
        domain = binary_text(21, 1, 2, 3)
        data = {
            "domain": {"sid": domain},
            "graph": {
                "nodes": [
                    {"id": user, "type": "User", "name": "alice"},
                    {"id": admins, "type": "Group", "name": "Admins"},
                    {"id": dc, "type": "Computer", "name": "DC01$", "is_dc": True, "os": "Windows Server"},
                    {"id": domain, "type": "Domain", "name": "lab.example"},
                ],
                "links": [{"source": user, "target": admins, "type": "MemberOf"}],
            },
            "sid_name": {},
        }

        self.assertTrue(_repair_legacy_binary_sids(data))
        self.assertEqual(data["domain"]["sid"], "S-1-5-21-1-2-3")
        self.assertEqual(data["system_counts"]["domain_controller"], 1)
        self.assertIn("S-1-5-21-1-2-3-1000", data["high_value"])
        self.assertTrue(any(edge["type"] == "AdminTo" for edge in data["graph"]["links"]))


if __name__ == "__main__":
    unittest.main()
