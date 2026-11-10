"""Wording rules for text the browser app shows."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "frontend_legacy_template.html"

# Retired names, broken plurals, and internal jargon that should not reach the page.
BANNED_PATTERNS = [
    ("old product name", re.compile(r"\bDT4SMS\b|Splunk MCP Discovery Tool")),
    ("old theme name", re.compile(r"\bConstruct\b")),
    ('"(s)" plural; use countLabel()', re.compile(r"[a-z]\((?:s|es)\)", re.IGNORECASE)),
    ("doubled word", re.compile(r"\b(the|a|an|to|of|and|is|in|for|on|with)\s+\1\b", re.IGNORECASE)),
    (
        "jargon",
        re.compile(
            r"header monitor|control surface|asset plane|exec-control|operator-ready|non-authoritative"
            r"|deterministic|\(demo\)|demo mode|lorem ipsum",
            re.IGNORECASE,
        ),
    ),
    ("jargon", re.compile(r"(?<!\w)recursive(?!\w)", re.IGNORECASE)),
    (
        "unformatted date; use formatMissionDateTime()",
        re.compile(r"new Date\([^()]*\)\.toLocale(?:String|DateString|TimeString)\(\)"),
    ),
]

# Kept so summaries saved before the heading was renamed still show their next check.
ALLOWED_LITERALS = ["getSummarySection(summarySections, 'Recursive Next Loop')"]


class UiCopyTests(unittest.TestCase):
    def test_template_has_no_banned_wording(self):
        source = TEMPLATE.read_text(encoding="utf-8")
        for literal in ALLOWED_LITERALS:
            source = source.replace(literal, "")
        problems = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            for label, pattern in BANNED_PATTERNS:
                match = pattern.search(line)
                if match:
                    problems.append(f"line {line_number}: {label}: {match.group(0)!r} in {line.strip()[:120]!r}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_product_name_is_used_in_title_and_header(self):
        source = TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("<title>Splunk Discovery Tool</title>", source)
        self.assertIn("Splunk Discovery Tool", source)


if __name__ == "__main__":
    unittest.main()
