import asyncio
import json
import unittest
from pathlib import Path

from fastapi import HTTPException

from serket.server.api import create_app


class QueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = Path(__file__).resolve().parents[1]
        data = json.loads((project_root / "demo" / "serket-demo.json").read_text(encoding="utf-8"))
        app = create_app(data)
        cls.endpoint = next(
            route.endpoint
            for route in app.routes
            if getattr(route, "path", None) == "/api/query-paths"
        )

    def test_computes_path_from_arbitrary_loaded_identity(self):
        body = asyncio.run(
            type(self).endpoint(
                {
                    "source": "S-1-5-21-42424242-51515151-61616161-1101",
                    "target": "S-1-5-21-42424242-51515151-61616161-1000",
                    "max_hops": 6,
                }
            )
        )
        self.assertFalse(body["queried_directory"])
        self.assertEqual(body["paths"][0]["hops"], 3)
        self.assertEqual(body["paths"][0]["steps"][0]["edge_type"], "MemberOf")

    def test_rejects_unknown_source(self):
        with self.assertRaises(HTTPException) as context:
            asyncio.run(type(self).endpoint({"source": "missing"}))
        self.assertEqual(context.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
