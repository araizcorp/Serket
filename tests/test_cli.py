import unittest

from serket.cli import _build_parser


class CliTests(unittest.TestCase):
    def test_parser_uses_installed_command_name(self):
        parser = _build_parser()

        self.assertEqual(parser.prog, "serket")


if __name__ == "__main__":
    unittest.main()
