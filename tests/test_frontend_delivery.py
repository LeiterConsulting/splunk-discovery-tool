import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


import frontend_delivery


class FrontendDeliveryTests(unittest.TestCase):
    def test_static_bundle_matches_legacy_frontend_source(self):
        status = frontend_delivery.get_frontend_sync_status()
        self.assertTrue(status["ok"], "\n".join(status["issues"]))

    def test_build_manifest_matches_current_artifacts(self):
        manifest = frontend_delivery.load_build_manifest()
        self.assertEqual(
            manifest.get("source"),
            frontend_delivery.compute_source_fingerprint(),
            "Legacy frontend source fingerprint drifted from the recorded build manifest.",
        )
        self.assertEqual(
            manifest.get("artifacts"),
            frontend_delivery.compute_artifact_fingerprint(),
            "Generated frontend artifacts drifted from the recorded build manifest.",
        )

    def test_summary_verification_state_wiring_is_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const [showHistory, setShowHistory] = useState(null);", template_source)
        self.assertIn("setShowHistory(showHistory === taskIndex ? null : taskIndex);", template_source)
        self.assertIn("{showHistory === taskIndex && (() => {", template_source)

    def test_summary_action_handlers_are_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const launchChatInvestigation = async (prompt, options = {}) => {", template_source)
        self.assertIn("const buildRiskInvestigationPrompt = (risk) => [", template_source)
        self.assertIn("const buildUnknownEntityValidationChatPrompt = (item) => {", template_source)
        self.assertIn("const focusRiskControlPath = (risk) => {", template_source)
        self.assertIn("const focusQueriesForRisk = (risk) => {", template_source)
        self.assertIn("const focusQueriesForTask = (task) => {", template_source)
        self.assertIn("onClick={() => focusRiskControlPath(risk)}", template_source)
        self.assertIn("onClick={() => focusQueriesForRisk(risk)}", template_source)
        self.assertIn("onClick={() => focusQueriesForTask(task)}", template_source)
        self.assertIn("buildUnknownEntityValidationChatPrompt(item)", template_source)