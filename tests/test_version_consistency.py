"""The release version is the same everywhere it is shown."""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from app_version import APP_VERSION  # noqa: E402


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else ""


class VersionConsistencyTests(unittest.TestCase):
    def test_version_is_semantic(self):
        self.assertRegex(APP_VERSION, r"^\d+\.\d+\.\d+$")

    def test_installers_match(self):
        self.assertEqual(_first_match(r'^VERSION="([^"]+)"', _read("install.sh")), APP_VERSION)
        self.assertEqual(_first_match(r'^\$VERSION = "([^"]+)"', _read("install.ps1")), APP_VERSION)

    def test_readme_badge_matches(self):
        badge = _first_match(r"img\.shields\.io/badge/version-([0-9][^-]*(?:--[a-z]+)?)-", _read("README.md"))
        self.assertEqual(badge, APP_VERSION)

    def test_latest_changelog_release_matches(self):
        changelog = _read("CHANGELOG.md")
        self.assertEqual(_first_match(r"^## \[(\d+\.\d+\.\d+)\]", changelog), APP_VERSION)
        self.assertIn(f"[{APP_VERSION}]: https://github.com/LeiterConsulting/splunk-discovery-tool/releases/tag/v{APP_VERSION}", changelog)

    def test_new_configs_record_the_app_version(self):
        from config_manager import AppConfig

        self.assertEqual(AppConfig.__dataclass_fields__["version"].default, APP_VERSION)


if __name__ == "__main__":
    unittest.main()
