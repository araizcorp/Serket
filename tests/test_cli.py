from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from serket.cli import _build_parser, _find_latest_result


class CliTests(unittest.TestCase):
    def test_parser_uses_installed_command_name(self):
        parser = _build_parser()

        self.assertEqual(parser.prog, "serket")

    def test_server_command_accepts_optional_domain_selector(self):
        args = _build_parser().parse_args(["server", "-d", "corp.local"])

        self.assertEqual(args.command, "server")
        self.assertEqual(args.domain, "corp.local")

    def test_server_selects_latest_result_for_requested_domain(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corp_old = root / "serket_corp_local_20260101_100000.json"
            other = root / "serket_other_local_20260101_120000.json"
            corp_new = root / "serket_corp_local_20260101_130000.json"
            for path in (corp_old, other, corp_new):
                path.write_text("{}", encoding="utf-8")

            self.assertEqual(
                _find_latest_result(temp_dir, "corp.local"),
                str(corp_new),
            )
            self.assertEqual(_find_latest_result(temp_dir), str(corp_new))

    def test_server_returns_none_when_domain_has_no_results(self):
        with TemporaryDirectory() as temp_dir:
            self.assertIsNone(_find_latest_result(temp_dir, "missing.local"))


if __name__ == "__main__":
    unittest.main()
