import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


import web_app


class ChatFollowOnActionTests(unittest.TestCase):
    def test_build_follow_on_actions_prefers_assistant_suggested_prompt(self):
        actions = web_app.build_follow_on_actions(
            "What should I ask next?",
            {"entities": {}, "last_result": {}},
            assistant_response="If you'd like, I can list all currently available indexes.",
        )

        self.assertGreaterEqual(len(actions), 1)
        self.assertEqual(actions[0]["prompt"], "List all currently available indexes")
        self.assertEqual(actions[0]["kind"], "assistant_response_follow_up")

    def test_build_report_follow_on_actions_includes_response_follow_up(self):
        actions = web_app.build_report_follow_on_actions(
            "readiness",
            {},
            assistant_response="A good follow-up would be to compare the busiest hosts over the last 24 hours.",
        )

        self.assertGreaterEqual(len(actions), 1)
        self.assertEqual(actions[0]["prompt"], "Compare the busiest hosts over the last 24 hours")
        self.assertEqual(actions[0]["kind"], "assistant_response_follow_up")

    def test_build_follow_on_actions_extracts_or_i_can_suggestions(self):
        actions = web_app.build_follow_on_actions(
            "I need help with an index",
            {"entities": {}, "last_result": {}},
            assistant_response="If you want, I can check a likely index such as _internal, or I can list the indexes you have access to.",
        )

        prompts = [action["prompt"] for action in actions]
        self.assertIn("List the indexes you have access to", prompts)

    def test_build_follow_on_actions_extracts_conditional_i_can_suggestion(self):
        actions = web_app.build_follow_on_actions(
            "what is the total disk size of wmata",
            {"entities": {}, "last_result": {}},
            assistant_response=(
                "The wmata index is ingesting about 6,639 MB/day based on the latest 24-hour discovery snapshot. "
                "If you want the exact current on-disk size for the `wmata` index, I can query Splunk for the index's actual stored size and retention details."
            ),
        )

        prompts = [action["prompt"] for action in actions]
        self.assertIn("Query Splunk for the index's actual stored size and retention details", prompts)
        self.assertEqual(actions[0]["kind"], "assistant_response_follow_up")


if __name__ == "__main__":
    unittest.main()