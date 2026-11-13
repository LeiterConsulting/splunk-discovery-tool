import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import chat_agent  # noqa: E402
import chat_goals  # noqa: E402
import web_app  # noqa: E402
from capabilities import CapabilityManager, CapabilityRegistry  # noqa: E402
from capabilities.rag import indexer as indexer_module  # noqa: E402
from capabilities.rag.indexer import ArtifactSourceIndexer  # noqa: E402
from chat_goals import ChatGoalStore, GoalLimitError, GoalNotFoundError  # noqa: E402
from config_manager import ConfigManager  # noqa: E402
from security_manager import SecurityManager  # noqa: E402


class ChatGoalStoreTests(unittest.TestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.root = Path(temp_dir.name)
        self.store = ChatGoalStore(self.root)

    def test_goals_can_be_created_listed_updated_and_deleted(self):
        goal = self.store.create_goal("local", "  Find out why\tfreezer sensors stopped reporting. Then fix alerts. ", items=["Which hosts stopped?", "Which hosts stopped?"], questions=["When did data stop?"])

        self.assertEqual(goal["goal"], "Find out why freezer sensors stopped reporting. Then fix alerts.")
        self.assertEqual(goal["title"], "Find out why freezer sensors stopped reporting.")
        self.assertEqual([item["text"] for item in goal["items"]], ["Which hosts stopped?"])
        self.assertEqual(goal["progress"], {"answered": 0, "open": 1, "total": 1})
        self.assertEqual(goal["suggested_questions"], ["When did data stop?"])
        self.assertEqual([entry["id"] for entry in self.store.list_goals("local")], [goal["id"]])

        updated = self.store.update_goal("local", goal["id"], title="Freezer sensors", status="done")
        self.assertEqual((updated["title"], updated["status"]), ("Freezer sensors", "done"))
        with self.assertRaises(GoalLimitError):
            self.store.update_goal("local", goal["id"], status="paused")
        with self.assertRaises(GoalLimitError):
            self.store.update_goal("local", goal["id"], goal="   ")

        self.store.delete_goal("local", goal["id"])
        self.assertEqual(self.store.list_goals("local"), [])
        with self.assertRaises(GoalNotFoundError):
            self.store.get_goal("local", goal["id"])

    def test_each_owner_has_a_separate_library(self):
        goal = self.store.create_goal("user_1", "Reduce noisy alerts")
        self.assertEqual(self.store.list_goals("user_2"), [])
        with self.assertRaises(GoalNotFoundError):
            self.store.get_goal("user_2", goal["id"])
        self.assertTrue((self.root / "goals" / "user_1.json").exists())
        self.assertEqual(chat_goals.owner_key(None), "local")
        self.assertEqual(chat_goals.owner_key({"id": 7, "username": "ana"}), "user_7")
        self.assertEqual(chat_goals.owner_key({"id": "../x"}), "user____x")

    def test_library_limits(self):
        with self.assertRaises(GoalLimitError):
            self.store.create_goal("local", "   ")
        with mock.patch.object(chat_goals, "MAX_GOALS", 1):
            self.store.create_goal("local", "First")
            with self.assertRaises(GoalLimitError):
                self.store.create_goal("local", "Second")

    def test_progress_items_crud_and_replanning_keeps_answered_items(self):
        goal = self.store.create_goal("local", "Check firewall coverage", items=["Which firewalls send logs?", "Are any silent?"])
        first, second = (item["id"] for item in goal["items"])

        goal = self.store.update_item("local", goal["id"], first, status="answered", note="Two firewalls send logs.")
        goal = self.store.add_item("local", goal["id"], "What retention applies?")
        goal = self.store.update_item("local", goal["id"], second, text="Are any firewalls silent this week?")
        self.assertEqual(goal["progress"], {"answered": 1, "open": 2, "total": 3})
        self.assertEqual(goal["items"][1]["text"], "Are any firewalls silent this week?")

        goal = self.store.delete_item("local", goal["id"], second)
        self.assertEqual(len(goal["items"]), 2)
        with self.assertRaises(GoalNotFoundError):
            self.store.delete_item("local", goal["id"], second)
        with self.assertRaises(GoalLimitError):
            self.store.update_item("local", goal["id"], first, status="maybe")

        goal = self.store.replace_plan("local", goal["id"], ["Which firewalls send logs?", "Is parsing correct?"], ["Show firewall sourcetypes"], "model")
        self.assertEqual([(item["text"], item["status"]) for item in goal["items"]], [
            ("Which firewalls send logs?", "answered"),
            ("Is parsing correct?", "open"),
        ])
        self.assertEqual(goal["suggested_questions"], ["Show firewall sourcetypes"])

        # Reopening an item clears its note.
        goal = self.store.update_item("local", goal["id"], first, status="open")
        self.assertEqual(goal["items"][0]["note"], "")

    def test_turns_and_progress_evaluation(self):
        goal = self.store.create_goal("local", "Find silent hosts", items=["Which hosts are silent?", "Since when?"])
        item_ids = [item["id"] for item in goal["items"]]
        self.assertTrue(self.store.record_turn("local", goal["id"], "Which hosts are silent?", "web01 and web02 sent nothing for 3 days.", "chat_a"))
        self.assertFalse(self.store.record_turn("local", "goal_missing", "q", "a"))
        self.assertFalse(self.store.record_turn("local", goal["id"], "q", "   "))

        raw = self.store.get_raw_goal("local", goal["id"])
        turns = chat_goals.pending_turns(raw)
        self.assertEqual(len(turns), 1)
        self.assertEqual(self.store.get_goal("local", goal["id"])["pending_turns"], 1)

        evaluation = chat_goals.parse_progress({
            "updates": [
                {"id": item_ids[0], "status": "answered", "note": "web01 and web02 are silent."},
                {"id": "item_unknown", "status": "answered"},
                {"id": item_ids[1], "status": "maybe", "note": ""},
            ],
            "new_items": ["Did a change window start 3 days ago?", "Did a change window start 3 days ago?", "Is the forwarder running?", "Third"],
            "summary": "Silent hosts are known; the cause is still open.",
            "questions": ["When did web01 last send data?"],
        }, raw)
        self.assertNotIn("item_unknown", evaluation["updates"])
        self.assertEqual(len(evaluation["new_items"]), 2)

        updated = self.store.apply_progress("local", goal["id"], evaluation, [turn["id"] for turn in turns])
        self.assertEqual(updated["items"][0]["status"], "answered")
        self.assertEqual(updated["items"][0]["note"], "web01 and web02 are silent.")
        self.assertEqual(updated["items"][1]["status"], "open")
        self.assertEqual([item["source"] for item in updated["items"][2:]], ["answer", "answer"])
        self.assertEqual(updated["summary"], "Silent hosts are known; the cause is still open.")
        self.assertEqual(updated["suggested_questions"], ["When did web01 last send data?"])
        self.assertEqual(updated["pending_turns"], 0)
        self.assertIsNotNone(updated["progress_checked_at"])

    def test_saved_chats_crud(self):
        goal = self.store.create_goal("local", "Map data sources")
        messages = [
            {"id": 1, "type": "user", "content": "Which indexes have the most data?"},
            {"id": 2, "type": "assistant", "content": "main and security."},
        ]
        meta = self.store.save_chat("local", goal["id"], "chat_one", messages)
        self.assertEqual((meta["title"], meta["message_count"]), ("Which indexes have the most data?", 2))

        meta = self.store.save_chat("local", goal["id"], "chat_one", messages + [{"id": 3, "type": "user", "content": "And hosts?"}])
        self.assertEqual(meta["message_count"], 3)
        self.assertEqual(len(self.store.get_goal("local", goal["id"])["chats"]), 1)

        renamed = self.store.rename_chat("local", goal["id"], "chat_one", "Index sizes")
        self.assertEqual(renamed["title"], "Index sizes")
        # Saving again keeps a title the user chose.
        self.assertEqual(self.store.save_chat("local", goal["id"], "chat_one", messages)["title"], "Index sizes")
        self.assertEqual(self.store.get_chat("local", goal["id"], "chat_one")["messages"], messages)

        with self.assertRaises(GoalLimitError):
            self.store.rename_chat("local", goal["id"], "chat_one", "  ")
        with self.assertRaises(GoalLimitError):
            self.store.save_chat("local", goal["id"], "chat_two", "not a list")
        self.store.delete_chat("local", goal["id"], "chat_one")
        with self.assertRaises(GoalNotFoundError):
            self.store.get_chat("local", goal["id"], "chat_one")

    def test_saved_chats_keep_the_newest_messages_within_the_size_limit(self):
        goal = self.store.create_goal("local", "Long chat")
        messages = [{"id": index, "type": "user", "content": "x" * 400} for index in range(50)]
        with mock.patch.object(chat_goals, "MAX_CHAT_BYTES", 5000), mock.patch.object(chat_goals, "MAX_CHAT_MESSAGES", 40):
            meta = self.store.save_chat("local", goal["id"], "chat_long", messages)
            saved = self.store.get_chat("local", goal["id"], "chat_long")["messages"]
            self.assertLess(meta["message_count"], 40)
            self.assertEqual(saved[-1]["id"], 49)
            with self.assertRaises(GoalLimitError):
                self.store.save_chat("local", goal["id"], "chat_huge", [{"type": "user", "content": "y" * 6000}])


class GoalPromptTests(unittest.TestCase):
    def test_plan_parsing_and_starter_plan(self):
        plan = chat_goals.parse_plan({"title": "Silent sensors", "items": ["Which sensors stopped?", ""], "questions": []}, "Find silent sensors")
        self.assertEqual(plan["title"], "Silent sensors")
        self.assertEqual(plan["items"], ["Which sensors stopped?"])
        self.assertEqual(plan["questions"], ["Which sensors stopped?"])
        self.assertIsNone(chat_goals.parse_plan({"items": []}, "x"))
        self.assertIsNone(chat_goals.parse_plan("text", "x"))

        starter = chat_goals.fallback_plan("Find silent sensors")
        self.assertEqual(starter["items"], ["Find silent sensors"])
        self.assertEqual(len(starter["questions"]), 3)

    def test_plan_and_progress_prompts_carry_the_goal(self):
        plan_messages = chat_goals.build_plan_messages("Find silent sensors", "Indexes: iot, main")
        self.assertIn("Find silent sensors", plan_messages[1]["content"])
        self.assertIn("Indexes: iot, main", plan_messages[1]["content"])
        goal = {"goal": "Find silent sensors", "items": [{"id": "item_1", "status": "open", "text": "Which sensors?"}]}
        progress_messages = chat_goals.build_progress_messages(goal, [{"question": "Which sensors?", "answer": "s1 and s2"}])
        self.assertIn("id=item_1 status=open: Which sensors?", progress_messages[1]["content"])
        self.assertIn("Answer: s1 and s2", progress_messages[1]["content"])

    def test_chat_prompt_lists_settled_and_open_questions(self):
        goal = {"items": [
            {"text": "Which sensors stopped?", "status": "answered", "note": "s1 and s2"},
            {"text": "Why did they stop?", "status": "open"},
        ]}
        context = chat_agent.format_mission_context("Find silent sensors", chat_goals.progress_brief(goal))
        self.assertIn("USER GOAL", context)
        self.assertIn("Settled so far:\n  * Which sensors stopped? (s1 and s2)", context)
        self.assertIn("Still open:\n  * Why did they stop?", context)
        self.assertIn("work on the first open question", context)
        plain = chat_agent.format_mission_context("Find silent sensors")
        self.assertNotIn("Still open", plain)


class ChatDataIndexerTests(unittest.TestCase):
    def test_chat_data_is_not_indexed_as_discovery_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_dir = temp_path / "output"
            (output_dir / "chat_data" / "goals").mkdir(parents=True)
            (output_dir / "chat_data" / "goals" / "local.json").write_text(json.dumps({"marker": "saved-goal-marker"}), encoding="utf-8")
            (output_dir / "v2_operator_runbook_test.md").write_text(
                "## Queue Pressure\n\nOperators should validate queue pressure and ingestion delays in _internal before escalating.",
                encoding="utf-8",
            )
            original_cwd = Path.cwd()
            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(temp_path / "config.encrypted")), registry=CapabilityRegistry())
                manager.update_capability_config("rag_chromadb", {"source_dir": str(output_dir), "storage_dir": str(output_dir / "rag" / "chromadb")})
                indexer = ArtifactSourceIndexer(
                    config=manager.config_manager.get_capability("rag_chromadb"),
                    definition=manager.registry.get_definition("rag_chromadb"),
                )
                documents = indexer.collect_documents()
                with mock.patch.object(indexer_module, "CHAT_DATA_DIR_NAME", "not-the-chat-data-folder"):
                    unfiltered = indexer.collect_documents()
            finally:
                os.chdir(original_cwd)
        self.assertTrue(documents)
        self.assertFalse(any("saved-goal-marker" in document.content for document in documents))
        self.assertTrue(any("saved-goal-marker" in document.content for document in unfiltered))


class ChatGoalApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.temp_path = Path(self.temp_dir.name)
        self.original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.security_manager = SecurityManager(str(self.temp_path / "security.db"))
        self.originals = (web_app.config_manager, web_app.capability_manager, web_app.security_manager)
        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = self.security_manager
        self.store = ChatGoalStore(self.temp_path / "chat_data")
        self.llm_replies = []
        self.llm_prompts = []

        async def fake_llm(messages, fraction, ceiling):
            self.llm_prompts.append(messages)
            if not self.llm_replies:
                return None, "No AI model is set up. Add one in Settings to get an AI review."
            return self.llm_replies.pop(0), ""

        for patcher in (
            mock.patch.object(web_app, "chat_goal_store", self.store),
            mock.patch.object(web_app, "_ask_llm_for_goal_json", side_effect=fake_llm),
            mock.patch.object(web_app, "load_latest_report_knowledge", return_value={"prompt_context_compact": "Indexes: iot"}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(web_app.app)

    def tearDown(self):
        self.client.close()
        web_app.config_manager, web_app.capability_manager, web_app.security_manager = self.originals
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def _create(self, text="Find silent sensors"):
        response = self.client.post("/api/chat/goals", json={"goal": text})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_creating_a_goal_uses_the_model_plan(self):
        self.llm_replies.append({"title": "Silent sensors", "items": ["Which sensors stopped?", "Since when?"], "questions": ["Which iot hosts stopped sending data?"]})

        body = self._create()

        goal = body["goal"]
        self.assertEqual(body["message"], "")
        self.assertEqual(goal["title"], "Silent sensors")
        self.assertEqual(goal["planned_by"], "model")
        self.assertEqual([item["text"] for item in goal["items"]], ["Which sensors stopped?", "Since when?"])
        self.assertEqual(goal["suggested_questions"], ["Which iot hosts stopped sending data?"])
        self.assertIn("Indexes: iot", self.llm_prompts[0][1]["content"])
        self.assertEqual(self.client.get("/api/chat/goals").json()["goals"][0]["id"], goal["id"])

    def test_creating_a_goal_without_a_model_uses_starter_questions(self):
        body = self._create()
        self.assertEqual(body["goal"]["planned_by"], "starter")
        self.assertEqual(body["goal"]["items"][0]["text"], "Find silent sensors")
        self.assertIn("Starter questions are shown instead.", body["message"])
        self.assertEqual(self.client.post("/api/chat/goals", json={"goal": "  "}).status_code, 400)

    def test_goal_items_and_chats_crud_over_http(self):
        goal = self._create()["goal"]
        goal_id = goal["id"]

        renamed = self.client.patch(f"/api/chat/goals/{goal_id}", json={"title": "Sensors", "status": "done"}).json()["goal"]
        self.assertEqual((renamed["title"], renamed["status"]), ("Sensors", "done"))
        self.assertEqual(self.client.patch(f"/api/chat/goals/{goal_id}", json={"status": "later"}).status_code, 400)

        added = self.client.post(f"/api/chat/goals/{goal_id}/items", json={"text": "Since when?"}).json()["goal"]
        item_id = added["items"][-1]["id"]
        answered = self.client.patch(f"/api/chat/goals/{goal_id}/items/{item_id}", json={"status": "answered", "note": "Since Monday."}).json()["goal"]
        self.assertEqual(answered["progress"]["answered"], 1)
        removed = self.client.delete(f"/api/chat/goals/{goal_id}/items/{item_id}").json()["goal"]
        self.assertEqual(removed["progress"]["answered"], 0)

        messages = [{"id": 1, "type": "user", "content": "Which sensors stopped?"}]
        saved = self.client.put(f"/api/chat/goals/{goal_id}/chats/chat_123", json={"messages": messages}).json()["chat"]
        self.assertEqual(saved["title"], "Which sensors stopped?")
        self.assertEqual(self.client.get(f"/api/chat/goals/{goal_id}/chats/chat_123").json()["chat"]["messages"], messages)
        self.assertEqual(self.client.patch(f"/api/chat/goals/{goal_id}/chats/chat_123", json={"title": "First look"}).json()["chat"]["title"], "First look")
        self.assertEqual(self.client.get(f"/api/chat/goals/{goal_id}").json()["goal"]["chats"][0]["title"], "First look")
        self.assertEqual(self.client.delete(f"/api/chat/goals/{goal_id}/chats/chat_123").status_code, 200)
        self.assertEqual(self.client.get(f"/api/chat/goals/{goal_id}/chats/chat_123").status_code, 404)

        self.assertEqual(self.client.delete(f"/api/chat/goals/{goal_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/api/chat/goals/{goal_id}").status_code, 404)

    def test_replanning_replaces_open_items_and_keeps_answered_ones(self):
        goal = self._create()["goal"]
        item_id = goal["items"][0]["id"]
        self.client.patch(f"/api/chat/goals/{goal['id']}/items/{item_id}", json={"status": "answered"})
        self.llm_replies.append({"title": "x", "items": ["Which hosts?", "Why?"], "questions": ["Show hosts"]})

        replanned = self.client.post(f"/api/chat/goals/{goal['id']}/plan").json()["goal"]

        self.assertEqual([(item["text"], item["status"]) for item in replanned["items"]], [
            ("Find silent sensors", "answered"), ("Which hosts?", "open"), ("Why?", "open"),
        ])
        self.assertEqual(replanned["planned_by"], "model")

    def test_chat_answers_with_a_goal_are_recorded_and_progress_is_checked(self):
        self.llm_replies.append({"title": "Silent sensors", "items": ["Which sensors stopped?", "Since when?"], "questions": ["q"]})
        goal = self._create()["goal"]
        first_item = goal["items"][0]["id"]

        async def fake_chat(request, status_callback=None, runtime_config=None, goal_owner=None):
            return {"response": "Sensors s1 and s2 stopped on Monday.", "chat_session_id": request.get("chat_session_id")}

        with mock.patch.object(web_app, "chat_with_splunk_logic", side_effect=fake_chat):
            result = self.client.post("/chat", json={"message": "Which sensors stopped?", "chat_session_id": "chat_9", "goal_id": goal["id"]}).json()
            no_goal = self.client.post("/chat", json={"message": "Hello", "chat_session_id": "chat_9"}).json()
        self.assertTrue(result["goal_turn_recorded"])
        self.assertNotIn("goal_turn_recorded", no_goal)
        self.assertEqual(self.client.get(f"/api/chat/goals/{goal['id']}").json()["goal"]["pending_turns"], 1)

        # Without a model reply the turn stays pending and the reason is returned.
        failed = self.client.post(f"/api/chat/goals/{goal['id']}/progress").json()
        self.assertFalse(failed["updated"])
        self.assertIn("No AI model", failed["message"])
        self.assertEqual(failed["goal"]["pending_turns"], 1)

        self.llm_replies.append({
            "updates": [{"id": first_item, "status": "answered", "note": "s1 and s2 stopped."}],
            "new_items": ["Why did they stop?"],
            "summary": "The silent sensors are known.",
            "questions": ["Why did s1 stop sending data on Monday?"],
        })
        checked = self.client.post(f"/api/chat/goals/{goal['id']}/progress").json()
        self.assertTrue(checked["updated"])
        self.assertEqual(checked["goal"]["progress"], {"answered": 1, "open": 2, "total": 3})
        self.assertEqual(checked["goal"]["summary"], "The silent sensors are known.")
        self.assertEqual(checked["goal"]["pending_turns"], 0)
        self.assertIn("Sensors s1 and s2 stopped on Monday.", self.llm_prompts[-1][1]["content"])

        # Nothing new to judge: no model call.
        prompts_before = len(self.llm_prompts)
        unchanged = self.client.post(f"/api/chat/goals/{goal['id']}/progress").json()
        self.assertFalse(unchanged["updated"])
        self.assertEqual(len(self.llm_prompts), prompts_before)

    def test_goal_libraries_are_per_user_when_sign_in_is_on(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))
        admin_password = "".join(["Goal", "Admin", "Pass", "123!"])
        self.assertEqual(self.client.post("/api/auth/login", json={"username": "admin", "password": "password"}).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/reset-password", json={
            "current_password": "password", "new_password": admin_password, "confirm_password": admin_password,
        }).status_code, 200)
        admin_goal = self._create("Admin goal")["goal"]

        analyst_password = "".join(["Goal", "Analyst", "Pass", "123!"])
        created = self.client.post("/api/security/users", json={
            "username": "analyst1", "password": analyst_password, "role": "analyst", "require_password_reset": False,
        })
        self.assertEqual(created.status_code, 200, created.text)

        with TestClient(web_app.app) as analyst:
            self.assertEqual(analyst.get("/api/chat/goals").status_code, 401)
            self.assertEqual(analyst.post("/api/auth/login", json={"username": "analyst1", "password": analyst_password}).status_code, 200)
            self.assertEqual(analyst.get("/api/chat/goals").json()["goals"], [])
            self.assertEqual(analyst.get(f"/api/chat/goals/{admin_goal['id']}").status_code, 404)
            analyst_goal = analyst.post("/api/chat/goals", json={"goal": "Analyst goal"}).json()["goal"]

        self.assertEqual([goal["id"] for goal in self.client.get("/api/chat/goals").json()["goals"]], [admin_goal["id"]])
        self.assertNotEqual(analyst_goal["id"], admin_goal["id"])


class GoalAwareChatTests(unittest.TestCase):
    def test_record_chat_goal_turn_ignores_errors_and_missing_goals(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ChatGoalStore(Path(temp_dir))
            goal = store.create_goal("local", "Find silent sensors")
            with mock.patch.object(web_app, "chat_goal_store", store):
                error_result = {"error": "boom"}
                web_app.record_chat_goal_turn("local", {"goal_id": goal["id"], "message": "q"}, error_result)
                missing = {"response": "a"}
                web_app.record_chat_goal_turn("local", {"goal_id": "goal_missing", "message": "q"}, missing)
                other_owner = {"response": "a"}
                web_app.record_chat_goal_turn("user_2", {"goal_id": goal["id"], "message": "q"}, other_owner)
                recorded = {"response": "a"}
                web_app.record_chat_goal_turn("local", {"goal_id": goal["id"], "message": "q"}, recorded)
            self.assertNotIn("goal_turn_recorded", error_result)
            self.assertNotIn("goal_turn_recorded", missing)
            self.assertNotIn("goal_turn_recorded", other_owner)
            self.assertTrue(recorded["goal_turn_recorded"])
            self.assertEqual(store.get_goal("local", goal["id"])["turn_count"], 1)


if __name__ == "__main__":
    unittest.main()
