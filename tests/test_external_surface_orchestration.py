import json
from pathlib import Path
from unittest import mock
import unittest

from serket.collector.external_surface import collect_external_surface_bridge


class ExternalSurfaceOrchestrationTests(unittest.TestCase):
    @mock.patch("serket.collector.external_surface.shutil.which", return_value=None)
    def test_missing_portico_is_optional(self, _which):
        bridge, coverage = collect_external_surface_bridge("corp.local")
        self.assertIsNone(bridge)
        self.assertEqual(coverage["status"], "unavailable")

    @mock.patch("serket.collector.external_surface.shutil.which", return_value="portico")
    @mock.patch("serket.collector.external_surface.subprocess.run")
    def test_runs_standalone_scan_then_sanitized_export(self, run, _which):
        def execute(command, **kwargs):
            output = Path(command[command.index("--output") + 1])
            if command[1] == "scan":
                output.write_text("{}", encoding="utf-8")
            else:
                output.write_text(json.dumps({
                    "bridge_version": "1.0",
                    "bridge_type": "external_identity_surface",
                    "source": "portico",
                    "generated": "2026-08-14T10:00:00Z",
                    "domain": "corp.local",
                    "external_exposures": [],
                }), encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        run.side_effect = execute
        bridge, coverage = collect_external_surface_bridge("corp.local")
        self.assertEqual(coverage["status"], "collected")
        self.assertEqual(bridge["source"], "portico")
        scan = run.call_args_list[0].args[0]
        export = run.call_args_list[1].args[0]
        self.assertIn("--probe-ldaps", scan)
        self.assertEqual(export[1], "export")
        self.assertFalse(run.call_args_list[0].kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
