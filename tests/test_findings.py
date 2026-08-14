import unittest

from serket.finding_engine import generate_findings
from serket.graph.builder import ADGraph, _add_edge
from serket.graph.pathfinder import get_all_paths, get_cheapest_path
from serket.sensitivity import propagate_sensitivity


class FindingEngineTests(unittest.TestCase):
    def graph(self):
        ag = ADGraph()
        ag._add_node("u1", "operator", "User")
        ag._add_node("g1", "Helpdesk A", "Group")
        ag._add_node("g2", "Helpdesk B", "Group")
        ag._add_node("da", "Domain Admins", "Group", high_value=True)
        _add_edge(ag.G, "u1", "g1", "GenericAll")
        _add_edge(ag.G, "g1", "da", "MemberOf")
        _add_edge(ag.G, "u1", "g2", "WriteDACL")
        _add_edge(ag.G, "g2", "da", "AddMember")
        _add_edge(ag.G, "u1", "da", "WriteDACL")
        return ag

    def test_multiple_paths_are_deduplicated_by_technique_chain(self):
        paths = get_all_paths(self.graph(), "u1", {"da"}, max_depth=4, max_paths=10)
        chains = {tuple(path.technique_chain) for path in paths}

        self.assertIn(("GenericAll", "MemberOf"), chains)
        self.assertIn(("WriteDACL", "AddMember"), chains)
        self.assertIn(("WriteDACL",), chains)
        self.assertEqual(sum(path.is_cheapest for path in paths), 1)
        self.assertTrue(all(path.path_id and path.edges[0].id for path in paths))
        cheapest = get_cheapest_path(self.graph(), "u1", "da")
        self.assertEqual(cheapest.technique_chain, ["WriteDACL"])
        self.assertEqual(cheapest.cost, 4)

    def test_sensitivity_propagates_through_containment_and_gpo_links(self):
        ag = ADGraph()
        ag._add_node("parent", "Servers", "OU")
        ag._add_node("dc-ou", "Domain Controllers", "OU")
        ag._add_node("dc1", "DC01$", "DomainController", is_dc=True)
        ag._add_node("gpo", "DC Policy", "GPO")
        _add_edge(ag.G, "parent", "dc-ou", "Contains")
        _add_edge(ag.G, "dc-ou", "dc1", "Contains")
        _add_edge(ag.G, "gpo", "dc-ou", "GPOLink")

        sensitivity = propagate_sensitivity(ag)

        self.assertEqual(sensitivity["dc1"], "critical")
        self.assertEqual(sensitivity["dc-ou"], "critical")
        self.assertEqual(sensitivity["parent"], "high")
        self.assertEqual(sensitivity["gpo"], "high")

    def test_acl_finding_contains_evidence_paths_and_explainable_risk(self):
        ag = self.graph()
        propagate_sensitivity(ag)
        ad_data = {
            "domain": {"name": "lab.example", "sid": "domain"},
            "telemetry": {"started_at": "2026-08-14T09:00:00+00:00"},
            "users": {"u1": {}}, "computers": {},
        }

        first = generate_findings(ad_data=ad_data, ag=ag)
        second = generate_findings(ad_data=ad_data, ag=ag)
        finding = next(
            item for item in first["findings"]
            if item["badge"] == "WRITE_DACL_TIER0"
        )

        self.assertEqual(finding["certainty"], "direct")
        self.assertTrue(finding["tier0_reachable"])
        self.assertEqual(finding["evidence"][0]["type"], "ace")
        self.assertTrue(finding["paths"])
        self.assertEqual(
            finding["risk_score"],
            min(100, sum(finding["risk_components"].values())),
        )
        self.assertEqual(
            [item["id"] for item in first["findings"]],
            [item["id"] for item in second["findings"]],
        )
        other_snapshot = generate_findings(
            ad_data={**ad_data, "telemetry": {"started_at": "2026-08-15T09:00:00+00:00"}},
            ag=ag,
        )
        first_by_key = {item["correlation_id"] for item in first["findings"]}
        other_by_key = {item["correlation_id"] for item in other_snapshot["findings"]}
        self.assertEqual(first_by_key, other_by_key)
        self.assertNotEqual(first["snapshot_id"], other_snapshot["snapshot_id"])
        self.assertEqual(ag.G.nodes["u1"]["findings"][0]["object_id"], "u1")

    def test_enabled_gpo_link_to_tier0_is_a_metadata_only_finding(self):
        ag = ADGraph()
        ag._add_node("gpo", "DC Security", "GPO", guid="gpo-guid", coverage="ldap_only")
        ag._add_node("dc-ou", "Domain Controllers", "OU")
        ag._add_node("dc", "DC01$", "DomainController", is_dc=True)
        _add_edge(ag.G, "gpo", "dc-ou", "GPOLink", enabled=True, enforced=True, link_order=1)
        _add_edge(ag.G, "dc-ou", "dc", "Contains")
        propagate_sensitivity(ag)

        result = generate_findings(
            ad_data={
                "domain": {"name": "lab.example"},
                "telemetry": {"started_at": "2026-08-14T09:00:00+00:00"},
            },
            ag=ag,
        )
        finding = next(item for item in result["findings"] if item["badge"] == "GPO_TIER0_LINK")

        self.assertEqual(finding["coverage"], "ldap_only")
        self.assertEqual(finding["certainty"], "conditional")
        self.assertEqual(finding["confidence"], "medium")
        self.assertTrue(finding["tier0_reachable"])
        self.assertTrue(finding["evidence"][0]["value"]["enforced"])

    def test_adcs_candidates_and_observed_maq_are_explicit_findings(self):
        ag = ADGraph()
        ag._add_node(
            "template", "UserAuth", "CertTemplate", guid="template-guid",
            published=False, coverage="ldap_only",
            adcs_findings=[
                {
                    "id": esc, "status": "candidate", "confidence": "low",
                    "reasons": [f"{esc} LDAP evidence"], "principals": ["u1"],
                }
                for esc in ("ESC1", "ESC2", "ESC3", "ESC4")
            ],
        )
        ag._add_node(
            "computer", "WS01$", "Workstation", guid="computer-guid",
            maq_abuse_suspected=True, creator_sid="u1",
            created="2026-08-13T09:00:00+00:00", created_age_days=1,
            maq_creator_volume=3,
        )

        result = generate_findings(
            ad_data={
                "domain": {"name": "lab.example"},
                "telemetry": {"started_at": "2026-08-14T09:00:00+00:00"},
            },
            ag=ag,
        )
        by_badge = {item["badge"]: item for item in result["findings"]}

        self.assertTrue({
            "ESC1_CANDIDATE", "ESC2_CANDIDATE", "ESC3_CANDIDATE",
            "ESC4_CANDIDATE", "MAQ_ABUSE_OBSERVED",
        }.issubset(by_badge))
        self.assertEqual(by_badge["ESC1_CANDIDATE"]["coverage"], "ldap_only")
        self.assertEqual(by_badge["ESC1_CANDIDATE"]["confidence"], "low")
        self.assertFalse(by_badge["ESC1_CANDIDATE"]["evidence"][0]["value"]["published"])
        self.assertEqual(
            by_badge["MAQ_ABUSE_OBSERVED"]["evidence"][0]["value"]["creator_volume"],
            3,
        )

    def test_sysvol_issue_emits_confirmed_gpo_abuse_and_posture(self):
        ag = ADGraph()
        ag._add_node(
            "gpo", "Weak Domain Policy", "GPO", guid="gpo-guid",
            sysvol={
                "coverage": "sysvol_offline",
                "issues": [{
                    "kind": "ntlm_compatibility", "severity": "high",
                    "description": "LmCompatibilityLevel permits legacy NTLM responses",
                    "configured_value": 1,
                }],
            },
        )
        result = generate_findings(
            ad_data={
                "domain": {"name": "lab.example"},
                "telemetry": {"started_at": "2026-08-14T09:00:00+00:00"},
            },
            ag=ag,
        )
        finding = next(item for item in result["findings"] if item["badge"] == "GPO_ABUSE")

        self.assertEqual(finding["certainty"], "direct")
        self.assertEqual(finding["coverage"], "sysvol_offline")
        self.assertEqual(result["posture"]["global_score"], result["risk_summary"]["global_score"])
        self.assertEqual(result["posture"]["schema"], "serket-posture/v1")


if __name__ == "__main__":
    unittest.main()
