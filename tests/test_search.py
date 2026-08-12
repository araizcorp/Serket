import asyncio
import json
import unittest
from pathlib import Path

from serket.server.api import create_app


class SearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = Path(__file__).resolve().parents[1]
        data = json.loads((project_root / "demo" / "serket-demo.json").read_text(encoding="utf-8"))
        app = create_app(data)
        cls.search = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/search")
        cls.details = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/nodes/{node_id:path}")

    def test_searches_name_and_upn(self):
        body = asyncio.run(type(self).search(q="aria", limit=20))
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["results"][0]["name"], "aria.rios")

    def test_node_details_include_relationship_directions(self):
        body = asyncio.run(type(self).details("S-1-5-21-42424242-51515151-61616161-1101"))
        self.assertTrue(body["controls"])
        self.assertTrue(body["memberships"])


if __name__ == "__main__":
    unittest.main()
