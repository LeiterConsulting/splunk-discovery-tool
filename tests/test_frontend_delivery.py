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