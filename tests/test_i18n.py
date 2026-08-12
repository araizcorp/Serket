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

    def test_explorer_supports_progressive_focus_and_collapsed_details(self):
        html = (ROOT / "serket" / "ui" / "workbench.html").read_text(encoding="utf-8")
        script = (ROOT / "serket" / "ui" / "workbench.js").read_text(encoding="utf-8")
        inspector = (ROOT / "serket" / "ui" / "inspector-controls.js").read_text(encoding="utf-8")
        layout_css = (ROOT / "serket" / "ui" / "workbench.css").read_text(encoding="utf-8")
        inspector_css = (ROOT / "serket" / "ui" / "inspector-controls.css").read_text(encoding="utf-8")

        self.assertIn('id="graph-back"', html)
        self.assertIn('id="graph-details"', html)
        self.assertIn("function focusExplorerNode", script)
        self.assertIn("function explorerBack", script)
        self.assertIn('state.graphOptions.scope = "outgoing"', script)
        self.assertIn('scope === "incoming"', script)
        self.assertIn('class="graph-edge-label"', script)
        self.assertIn("parallelEdges", script)
        self.assertIn('classList.toggle("explorer-mode"', script)
        self.assertIn("explorerSelection && explorerActive", inspector)
        self.assertIn('.app-shell.explorer-mode .context-panel', layout_css)
        self.assertIn('"nav context inspector" auto', layout_css)
        self.assertIn('.app-shell.explorer-mode .graph-filter-controls', layout_css)
        self.assertIn('.app-shell.explorer-mode .inspector', inspector_css)
        self.assertIn('width: min(480px, calc(100vw - 92px))', inspector_css)
        self.assertIn('.app-shell.explorer-mode:not(.inspector-collapsed)', inspector_css)


if __name__ == "__main__":
    unittest.main()
