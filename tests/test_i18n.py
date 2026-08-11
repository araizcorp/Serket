import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InternationalizationTests(unittest.TestCase):
    def test_english_is_default_and_spanish_is_optional(self):
        html = (ROOT / "serket" / "ui" / "workbench.html").read_text(encoding="utf-8")
        script = (ROOT / "serket" / "ui" / "i18n.js").read_text(encoding="utf-8")
        self.assertIn('<html lang="en">', html)
        self.assertIn('/assets/i18n.js', html)
        self.assertIn('value="en"', script)
        self.assertIn('value="es"', script)
        self.assertIn('localStorage.setItem(STORAGE_KEY', script)

    def test_modern_path_styles_are_loaded(self):
        html = (ROOT / "serket" / "ui" / "workbench.html").read_text(encoding="utf-8")
        css = (ROOT / "serket" / "ui" / "route-modern.css").read_text(encoding="utf-8")
        self.assertIn('/assets/route-modern.css', html)
        self.assertIn('.flow-track::before', css)
        self.assertIn('.flow-edge.selected', css)


if __name__ == "__main__":
    unittest.main()
