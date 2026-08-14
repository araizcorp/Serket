import asyncio
import json
import unittest

from serket.server.api import _normalise_graph, create_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "domain": {"name": "lab.example"},
            "stats": {"nodes": 2, "edges": 1},
            "paths": [],
            "surface": {},
            "findings": [{"id": "finding://serket/v1/test/1", "object_id": "u1"}],
            "risk_summary": {"risk_model": "serket-risk/v1", "global_score": 42},
            "snapshot_id": "test-snapshot",
            "coverage": {"directory": {"status": "collected"}},
            "system_counts": {"workstation": 1, "server": 0, "domain_controller": 0},
            "quality": {"status": "ok", "acl_relationships": 2},
            "graph": {
                "directed": True,
                "nodes": [
                    {"id": "u1", "name": "auditor", "type": "User"},
                    {"id": "g1", "name": "Domain Admins", "type": "Group"},
                ],
                "links": [
                    {
                        "source": "u1",
                        "target": "g1",
                        "type": "MemberOf",
                        "opsec_score": 1,
                    }
                ],
            },
            "meta": {
                "collection": {
                    "profile": "low-impact",
                    "searches": 1,
                    "pages": 1,
                    "entries": 2,
                }
            },
        }
        self.app = create_app(self.data)

    def request(self, path):
        messages = []
        request_sent = False

        async def receive():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 8080),
            "root_path": "",
        }
        asyncio.run(self.app(scope, receive, send))
        start = next(m for m in messages if m["type"] == "http.response.start")
        body = b"".join(
            m.get("body", b"")
            for m in messages
            if m["type"] == "http.response.body"
        )
        headers = {
            key.decode("latin-1"): value.decode("latin-1")
            for key, value in start["headers"]
        }
        return start["status"], headers, body

    def test_graph_normalises_networkx_links(self):
        graph = _normalise_graph(self.data)
        self.assertTrue(graph["available"])
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(graph["edges"][0]["type"], "MemberOf")

    def test_api_and_security_headers(self):
        status, headers, body = self.request("/api/graph")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["edges"][0]["source"], "u1")
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertIn("base-uri 'none'", headers["content-security-policy"])

    def test_ui_brand_and_local_assets_are_served(self):
        page_status, _, page_body = self.request("/")
        self.assertEqual(page_status, 200)
        page = page_body.decode("utf-8")
        self.assertIn('id="legal-modal"', page)
        self.assertIn("AraizCorp LLC", page)
        self.assertIn("serket-logo-primary-red-v3.png", page)
        self.assertIn("favicon.ico", page)

        css_status, _, _ = self.request("/assets/workbench.css")
        script_status, _, script_body = self.request("/assets/workbench.js")
        logo_status, _, _ = self.request("/assets/assets/brand/serket-logo-primary-red-v3.png")
        favicon_status, _, _ = self.request("/assets/assets/brand/favicon.ico")
        self.assertEqual(css_status, 200)
        self.assertEqual(script_status, 200)
        self.assertEqual(logo_status, 200)
        self.assertEqual(favicon_status, 200)
        self.assertIn("renderDetection", script_body.decode("utf-8"))

    def test_health_endpoint(self):
        status, _, body = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok", "product": "serket"})

    def test_stats_and_coverage_report_collection_scope(self):
        stats_status, _, stats_body = self.request("/api/stats")
        coverage_status, _, coverage_body = self.request("/api/coverage")

        self.assertEqual(stats_status, 200)
        self.assertEqual(coverage_status, 200)
        self.assertEqual(json.loads(stats_body)["systems"]["workstation"], 1)
        self.assertEqual(json.loads(stats_body)["quality"]["status"], "ok")
        self.assertEqual(json.loads(coverage_body)["directory"]["status"], "collected")

    def test_findings_endpoint_exposes_versioned_risk_context(self):
        status, _, body = self.request("/api/findings")
        payload = json.loads(body)

        self.assertEqual(status, 200)
        self.assertEqual(payload["snapshot_id"], "test-snapshot")
        self.assertEqual(payload["risk_summary"]["risk_model"], "serket-risk/v1")
        self.assertEqual(payload["findings"][0]["object_id"], "u1")


if __name__ == "__main__":
    unittest.main()
