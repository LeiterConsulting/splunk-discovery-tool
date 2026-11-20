import asyncio
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import web_app  # noqa: E402
from capabilities import CapabilityManager  # noqa: E402
from config_manager import ConfigManager  # noqa: E402
from incognito import IncognitoLLMClient, IncognitoSession, IncognitoState, IncognitoStore  # noqa: E402
from security_manager import SecurityManager  # noqa: E402

# Real names in the synthetic deployment. None of them may reach the model in incognito mode.
REAL_NAMES = ("web01", "contoso", "jdoe", "Jane Doe", "10.20.30.40", "branch-fw-02")

BLUEPRINT = {
    "discovered_inventory": {
        "hosts": ["web01.contoso.local", "branch-fw-02"],
        "indexes": ["contoso_prod", "main"],
    },
    "finding_ledger": [
        {"kind": "user", "data": {"username": "jdoe", "realname": "Jane Doe", "email": "jdoe@contoso.com"}},
    ],
}


def rows_result(rows):
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": {"results": rows}}}


def tool_call(query):
    payload = {"tool": "splunk_run_query", "args": {"query": query, "earliest_time": "-24h", "latest_time": "now"}}
    return f"<TOOL_CALL>{json.dumps(payload)}</TOOL_CALL>"


def find(pattern, text):
    match = re.search(pattern, text)
    if match is None:
        raise AssertionError(f"{pattern} not found in: {text[:400]}")
    return match.group(0)


class ScriptedModel:
    """Replies in order; a callable reply is given the messages it was sent, like a real model reading them."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    async def generate_response(self, messages=None, max_tokens=None, temperature=None, prompt=None):
        sent = [dict(message) for message in messages] if messages is not None else prompt
        self.calls.append(sent)
        if not self.replies:
            raise AssertionError("Unexpected extra model call")
        reply = self.replies.pop(0)
        return reply(sent) if callable(reply) else reply


class RecordingMCP:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def __call__(self, call, _config):
        self.calls.append(call)
        return self.handler(call)


def assert_no_real_names(case, sent):
    text = json.dumps(sent, default=str).lower()
    for real in REAL_NAMES:
        case.assertNotIn(real.lower(), text, f"{real} reached the model")


class IncognitoAppCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)
        original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.addCleanup(os.chdir, original_cwd)
        output = Path("output")
        output.mkdir()
        (output / "v2_intelligence_blueprint_20260101_000000.json").write_text(json.dumps(BLUEPRINT), encoding="utf-8")
        self.store = IncognitoStore(output / "incognito", Fernet(Fernet.generate_key()))
        patcher = mock.patch.object(web_app, "incognito_store", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    @contextmanager
    def chat(self, llm, mcp, owner="local"):
        async def discover(_config):
            return {"splunk_run_query", "splunk_get_indexes"}

        client = IncognitoLLMClient(llm, web_app.current_incognito_session)
        with mock.patch.object(web_app, "get_or_create_llm_client", lambda _config: client), \
                mock.patch.object(web_app, "load_latest_report_knowledge", lambda *_: None), \
                mock.patch.object(web_app, "discover_mcp_tools", discover), \
                mock.patch.object(web_app, "execute_mcp_tool_call", mcp), \
                mock.patch.object(web_app, "_get_memory_store_path", lambda session_id, owner=None: self.temp_path / f"{session_id}.json"), \
                mock.patch.object(web_app, "sync_chat_settings_for_request", lambda *_args, **_kwargs: dict(web_app.chat_session_settings)), \
                mock.patch.dict(web_app.chat_session_settings, {"enable_splunk_augmentation": True, "enable_rag_context": False}), \
                mock.patch.dict(web_app.chat_agent_memory, {}, clear=True):
            yield lambda request: asyncio.run(web_app.run_chat_turn(request, goal_owner=owner))


class IncognitoChatTests(IncognitoAppCase):
    def test_chat_masks_names_runs_the_real_search_and_restores_the_answer(self):
        self.store.set_preference("local", True)

        def first(messages):
            question = messages[-1]["content"]
            host = find(r"host_\d{4}", question)
            index = find(r"idx_\d{4}", question)
            address = find(r"198\.18\.\d+\.\d+", question)
            return tool_call(f"search index={index} host={host} src={address} | stats count by host, src, user")

        def second(messages):
            feedback = messages[-1]["content"]
            host = find(r"host_\d{4}", feedback)
            address = find(r"198\.18\.\d+\.\d+", feedback)
            user = find(r"user_\d{4}", feedback)
            return f"{host} dropped 3 events from {address} for {user} in the last 24 hours."

        llm = ScriptedModel([first, second])
        mcp = RecordingMCP(lambda _call: rows_result([{
            "host": "web01.contoso.local", "src": "10.20.30.40", "user": "jdoe", "count": "3",
            "_raw": "Jan 1 web01 sshd: failed password for jdoe from 10.20.30.40",
        }]))
        with self.chat(llm, mcp) as run:
            result = run({
                "message": "Why is web01.contoso.local dropping events from 10.20.30.40 in index=contoso_prod?",
                "history": [], "chat_session_id": "incognito_chat",
            })

        self.assertNotIn("error", result, result.get("error"))
        query = mcp.calls[0]["params"]["arguments"]["query"]
        self.assertIn("index=contoso_prod host=web01.contoso.local src=10.20.30.40", query)
        self.assertIn("web01.contoso.local", result["tool_calls"][0]["args"]["query"])
        self.assertIn("web01.contoso.local dropped 3 events from 10.20.30.40 for jdoe", result["response"])
        assert_no_real_names(self, llm.calls)
        self.assertNotIn("failed password", json.dumps(llm.calls))
        self.assertIn("Privacy note", llm.calls[0][0]["content"])

        summary = result["incognito"]
        self.assertTrue(summary["active"])
        self.assertEqual(summary["reason"], "user_choice")
        self.assertEqual(summary["calls"], 2)
        self.assertGreaterEqual(summary["masked"]["host"], 1)
        record = self.store.load_ledger("local", summary["ledger_id"])
        self.assertEqual(len(record["calls"]), 2)
        assert_no_real_names(self, record)
        self.assertIsNone(self.store.load_ledger("user_someone_else", summary["ledger_id"]))

    def test_tool_calls_with_invented_stand_ins_are_not_run(self):
        self.store.set_preference("local", True)
        llm = ScriptedModel([
            tool_call("search index=main host=host_0999 | stats count"),
            "I could not find that host in the data I was given.",
        ])
        mcp = RecordingMCP(lambda _call: rows_result([]))
        with self.chat(llm, mcp) as run:
            result = run({"message": "How many events did web01 send to index=main in the last 24 hours?",
                          "history": [], "chat_session_id": "incognito_unknown"})

        self.assertEqual(mcp.calls, [])
        feedback = llm.calls[1][-1]["content"]
        self.assertIn("host_0999", feedback)
        self.assertIn("do not appear in this conversation", feedback)
        self.assertIn("could not find that host", result["response"])
        self.assertIn("host_0999", result["incognito"]["unknown_stand_ins"])

    def test_unreadable_stand_ins_block_the_request_before_the_model(self):
        other_key = IncognitoStore(self.store.root, Fernet(Fernet.generate_key()))
        other_key.vault(web_app.INCOGNITO_VAULT_SCOPE).ensure_one("host", "web01")
        self.store.set_preference("local", True)
        llm = ScriptedModel(["never sent"])
        with self.chat(llm, RecordingMCP(lambda _call: rows_result([]))) as run:
            result = run({"message": "Why would tstats be faster than a raw search on web01?", "history": [],
                          "chat_session_id": "incognito_blocked"})

        self.assertTrue(result.get("incognito_blocked"))
        self.assertIn("nothing was sent", result["error"].lower())
        self.assertEqual(llm.calls, [])
        self.assertTrue(result["incognito"]["blocked"])

    def test_chat_is_unchanged_when_incognito_is_off(self):
        self.store.set_preference("local", False)
        llm = ScriptedModel(["tstats reads indexed fields, so it is faster than a raw search on web01.contoso.local."])
        with self.chat(llm, RecordingMCP(lambda _call: rows_result([]))) as run:
            result = run({"message": "Why would tstats be faster than a raw search on web01.contoso.local?",
                          "history": [], "chat_session_id": "incognito_off"})

        sent = json.dumps(llm.calls)
        self.assertIn("web01.contoso.local", sent)
        self.assertNotIn("Privacy note", sent)
        self.assertNotIn("incognito", result)
        self.assertFalse((self.store.root / "ledger").exists())

    def test_earlier_turns_are_masked_too(self):
        self.store.set_preference("local", True)
        llm = ScriptedModel(["tstats reads indexed fields, so it is faster."])
        history = [
            {"role": "user", "content": "What does branch-fw-02 forward?"},
            {"role": "assistant", "content": "branch-fw-02 forwards firewall logs for jdoe@contoso.com's team."},
        ]
        with self.chat(llm, RecordingMCP(lambda _call: rows_result([]))) as run:
            result = run({"message": "Why would tstats be faster than a raw search there?", "history": history,
                          "chat_session_id": "incognito_history"})

        self.assertNotIn("error", result, result.get("error"))
        assert_no_real_names(self, llm.calls)


class IncognitoApiTests(IncognitoAppCase):
    def setUp(self):
        super().setUp()
        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.security_manager = SecurityManager(str(self.temp_path / "security.db"))
        originals = (web_app.config_manager, web_app.capability_manager, web_app.security_manager)

        def restore():
            web_app.config_manager, web_app.capability_manager, web_app.security_manager = originals

        self.addCleanup(restore)
        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = self.security_manager
        self.provider_kind = "local"
        patcher = mock.patch.object(web_app, "llm_provider_kind", lambda _config=None: self.provider_kind)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(web_app.app)
        self.addCleanup(self.client.close)

    def test_status_and_personal_choice(self):
        status = self.client.get("/api/incognito/status").json()
        self.assertEqual((status["state"]["active"], status["state"]["reason"]), (False, "off"))
        self.assertIsNone(status["preference"])
        self.assertTrue(status["can_manage"])

        turned_on = self.client.post("/api/incognito/preference", json={"enabled": True}).json()
        self.assertEqual((turned_on["state"]["active"], turned_on["state"]["reason"]), (True, "user_choice"))
        self.assertTrue(turned_on["preference"])
        self.assertEqual(self.client.post("/api/incognito/preference", json={"enabled": "yes"}).status_code, 400)
        reset = self.client.post("/api/incognito/preference", json={"enabled": None}).json()
        self.assertIsNone(reset["preference"])
        self.assertFalse(reset["state"]["active"])

    def test_admin_can_require_incognito_for_cloud_models(self):
        saved = self.client.post("/api/incognito/policy", json={
            "force_for_cloud": True, "always_mask_terms": "Contoso\nFabrikam\nx", "keep_visible_terms": ["web01"],
        })
        self.assertEqual(saved.status_code, 200, saved.text)
        policy = saved.json()["policy"]
        self.assertEqual(policy["always_mask_terms"], ["Contoso", "Fabrikam"])
        self.assertEqual(policy["keep_visible_terms"], ["web01"])
        self.assertNotIn(b"Fabrikam", (self.store.root / "policy.enc").read_bytes())
        self.assertEqual(self.client.post("/api/incognito/policy", json={"force_for_cloud": "yes"}).status_code, 400)
        self.assertEqual(self.client.post("/api/incognito/policy", json={"always_mask_terms": 5}).status_code, 400)

        self.provider_kind = "cloud"
        status = self.client.get("/api/incognito/status").json()
        self.assertEqual((status["state"]["active"], status["state"]["locked"]), (True, True))
        self.assertEqual(status["state"]["reason"], "required_for_cloud")
        refused = self.client.post("/api/incognito/preference", json={"enabled": False})
        self.assertEqual(refused.status_code, 409)

        self.provider_kind = "local"
        self.assertFalse(self.client.get("/api/incognito/status").json()["state"]["active"])

    def test_preview_and_rotate(self):
        preview = self.client.post("/api/incognito/preview", json={"text": "Is web01.contoso.local ok? index=contoso_prod"})
        self.assertEqual(preview.status_code, 200, preview.text)
        body = preview.json()
        self.assertIsNone(body["blocked"])
        self.assertNotIn("web01", body["masked"])
        self.assertNotIn("contoso", body["masked"])
        self.assertIn("host", body["masked_counts"])
        self.assertEqual(self.client.post("/api/incognito/preview", json={"text": " "}).status_code, 400)
        self.assertEqual(self.client.post("/api/incognito/preview", json={"text": "a" * 20001}).status_code, 400)

        counts = self.client.get("/api/incognito/policy").json()["policy"]["stand_in_counts"]
        self.assertGreater(counts.get("host", 0), 0)
        rotated = self.client.post("/api/incognito/rotate").json()
        self.assertEqual(rotated["status"], "rotated")
        self.assertEqual(sum(rotated["policy"]["stand_in_counts"].values()), 0)
        again = self.client.post("/api/incognito/preview", json={"text": "web01.contoso.local"}).json()
        self.assertNotIn("web01", again["masked"])

    def test_shareable_exports_replace_names_with_the_same_stand_ins(self):
        transcript = (
            "# Chat\n\n**You:** Why is web01.contoso.local dropping events from 10.20.30.40?\n\n"
            "**Assistant:** jdoe changed the forwarder on web01.contoso.local. Check index=contoso_prod and index=main.\n"
        )
        exported = self.client.post("/api/incognito/export", json={"text": transcript, "filename": "chat-2026-01-01.md"})
        self.assertEqual(exported.status_code, 200, exported.text)
        body = exported.json()
        self.assertEqual(body["filename"], "chat-2026-01-01-stand-ins.md")
        for real in REAL_NAMES:
            self.assertNotIn(real.lower(), body["content"].lower())
        self.assertIn("index=main", body["content"])
        self.assertIn("host", body["masked_counts"])
        host = find(r"host_\d{4}", body["content"])
        preview = self.client.post("/api/incognito/preview", json={"text": "web01.contoso.local"}).json()
        self.assertEqual(preview["masked"], host)
        self.assertFalse((self.store.root / "ledger").exists())

        self.assertEqual(self.client.post("/api/incognito/export", json={"text": "  "}).status_code, 400)
        renamed = self.client.post("/api/incognito/export", json={"text": "web01", "filename": "../bad name"}).json()
        self.assertEqual(renamed["filename"], "export-stand-ins.md")

        report_json = self.temp_path / "output" / "discovery_report_20260101_000000.json"
        report_json.write_text(json.dumps({
            "hosts": ["web01.contoso.local"], "index": "contoso_prod", "owner": "jdoe", "events": 3,
        }), encoding="utf-8")
        report_md = self.temp_path / "output" / "v2_ai_summary_20260101_000000.md"
        report_md.write_text("Host web01.contoso.local sends 10.20.30.40 traffic for Jane Doe.", encoding="utf-8")
        picture = self.temp_path / "output" / "summary_infographic_20260101_000000.png"
        picture.write_bytes(b"\x89PNG")
        paths = {path.name: path for path in (report_json, report_md, picture)}

        def resolve(filename, _scope_key=None):
            if filename not in paths:
                raise web_app.HTTPException(status_code=404, detail="Report not found")
            return paths[filename]

        with mock.patch.object(web_app, "_resolve_accessible_output_artifact_path", side_effect=resolve):
            shared_json = self.client.get(f"/api/incognito/export/report/{report_json.name}")
            shared_md = self.client.get(f"/api/incognito/export/report/{report_md.name}")
            shared_picture = self.client.get(f"/api/incognito/export/report/{picture.name}")
            missing = self.client.get("/api/incognito/export/report/other_20260101_000000.json")

        self.assertEqual(shared_json.status_code, 200, shared_json.text)
        self.assertEqual(shared_json.json()["filename"], "discovery_report_20260101_000000-stand-ins.json")
        data = json.loads(shared_json.json()["content"])
        self.assertEqual(data["hosts"], [host])
        self.assertEqual(data["events"], 3)
        self.assertNotIn("incognito_note", data)
        self.assertNotIn("contoso", shared_json.json()["content"].lower())
        self.assertNotIn("jdoe", shared_json.json()["content"])
        self.assertEqual(shared_md.status_code, 200, shared_md.text)
        for real in REAL_NAMES:
            self.assertNotIn(real.lower(), shared_md.json()["content"].lower())
        self.assertIn(host, shared_md.json()["content"])
        self.assertEqual(shared_picture.status_code, 400)
        self.assertEqual(missing.status_code, 404)

    def test_ledger_is_only_shown_to_its_owner(self):
        session = IncognitoSession(IncognitoState(True, owner="local"), self.store.masker("installation"))
        session.record(prompt="masked prompt about host_0001", reply="host_0001 is fine")
        ledger_id = self.store.save_ledger(session)
        record = self.client.get(f"/api/incognito/ledger/{ledger_id}")
        self.assertEqual(record.status_code, 200)
        self.assertEqual(record.json()["record"]["calls"][0]["reply"], "host_0001 is fine")
        self.assertNotIn("owner", record.json()["record"])
        self.assertEqual(self.client.get("/api/incognito/ledger/not-a-real-record").status_code, 404)

        other = IncognitoSession(IncognitoState(True, owner="user_7"), None)
        other.record(prompt="x")
        other_id = self.store.save_ledger(other)
        self.assertEqual(self.client.get(f"/api/incognito/ledger/{other_id}").status_code, 404)

    def test_sign_in_keeps_policy_admin_only_and_choices_per_user(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))
        admin_password = "".join(["Incog", "Admin", "Pass", "123!"])
        self.assertEqual(self.client.post("/api/auth/login", json={"username": "admin", "password": "password"}).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/reset-password", json={
            "current_password": "password", "new_password": admin_password, "confirm_password": admin_password,
        }).status_code, 200)
        self.assertTrue(self.client.post("/api/incognito/preference", json={"enabled": True}).json()["state"]["active"])
        admin_owner = next(iter(self.store._load_preferences()))
        admin_session = IncognitoSession(IncognitoState(True, owner=admin_owner), None)
        admin_session.record(prompt="admin question")
        admin_ledger = self.store.save_ledger(admin_session)
        self.assertEqual(self.client.get(f"/api/incognito/ledger/{admin_ledger}").status_code, 200)

        analyst_password = "".join(["Incog", "Analyst", "Pass", "123!"])
        created = self.client.post("/api/security/users", json={
            "username": "analyst1", "password": analyst_password, "role": "analyst", "require_password_reset": False,
        })
        self.assertEqual(created.status_code, 200, created.text)
        with TestClient(web_app.app) as analyst:
            self.assertEqual(analyst.get("/api/incognito/status").status_code, 401)
            self.assertEqual(analyst.post("/api/incognito/export", json={"text": "web01"}).status_code, 401)
            self.assertEqual(analyst.post("/api/auth/login", json={"username": "analyst1", "password": analyst_password}).status_code, 200)
            status = analyst.get("/api/incognito/status").json()
            self.assertFalse(status["can_manage"])
            self.assertFalse(status["state"]["active"])
            self.assertEqual(analyst.get("/api/incognito/policy").status_code, 403)
            self.assertEqual(analyst.post("/api/incognito/policy", json={"default_on": True}).status_code, 403)
            self.assertEqual(analyst.post("/api/incognito/rotate").status_code, 403)
            self.assertEqual(analyst.post("/api/incognito/preview", json={"text": "web01"}).status_code, 403)
            self.assertEqual(analyst.get(f"/api/incognito/ledger/{admin_ledger}").status_code, 404)
            shared = analyst.post("/api/incognito/export", json={"text": "web01.contoso.local is slow"})
            self.assertEqual(shared.status_code, 200, shared.text)
            self.assertNotIn("web01", shared.json()["content"])
            self.assertFalse(analyst.post("/api/incognito/preference", json={"enabled": False}).json()["state"]["active"])
        self.assertEqual(len(self.store._load_preferences()), 2)
        self.assertTrue(self.client.get("/api/incognito/status").json()["state"]["active"])


class IncognitoJobTests(IncognitoAppCase):
    def test_jobs_keep_the_state_they_started_with(self):
        self.store.set_preference("local", True)
        self.assertEqual(web_app.incognito_job_payload("local"), {"owner": "local", "active": True})
        self.store.set_preference("local", False)
        self.assertEqual(web_app.incognito_job_payload("local"), {"owner": "local", "active": False})

        started_on = web_app.open_incognito_session_for_job({"incognito": {"owner": "local", "active": True}}, "AI summary")
        self.assertTrue(started_on.active)
        self.assertEqual(started_on.state.reason, "job_started_incognito")
        self.assertIsNotNone(started_on.state.owner)
        self.assertFalse(web_app.open_incognito_session_for_job({}, "AI summary").active)
        self.assertFalse(web_app.open_incognito_session_for_job({"incognito": "bad"}, "AI summary").active)

    def test_summary_request_passes_the_state_to_the_worker(self):
        self.store.set_preference("local", True)
        launched = []

        async def finished(*_args, **_kwargs):
            return {"status": "done"}

        def launch(job_type, payload):
            launched.append((job_type, payload))
            return SimpleNamespace(pid=None)

        with mock.patch.object(web_app, "_require_accessible_discovery_session", return_value={}), \
                mock.patch.object(web_app, "_get_discovery_session_scope_key", return_value=None), \
                mock.patch.object(web_app, "_sync_runtime_state_from_disk"), \
                mock.patch.object(web_app, "_load_cached_summary_if_available", return_value=None), \
                mock.patch.object(web_app, "_get_summarization_progress", return_value={}), \
                mock.patch.object(web_app, "_set_summarization_progress"), \
                mock.patch.object(web_app, "_launch_runtime_job_worker", side_effect=launch), \
                mock.patch.object(web_app, "_wait_for_summary_result", side_effect=finished):
            result = asyncio.run(web_app._handle_summary_background_request(
                {"timestamp": "20260101_000000"}, incognito_owner_key="local"
            ))

        self.assertEqual(result, {"status": "done"})
        self.assertEqual(launched[0][0], "summary")
        self.assertEqual(launched[0][1]["incognito"], {"owner": "local", "active": True})

    def test_summary_worker_applies_the_requester_state(self):
        with mock.patch.dict(os.environ):
            import runtime_job_worker
        seen = []

        async def summarize(_request):
            session = web_app.current_incognito_session()
            seen.append((session.active, session.state.reason, session.state.owner))
            return {"status": "ok"}

        with mock.patch.object(web_app, "_sync_runtime_state_from_disk"), \
                mock.patch.object(web_app, "_get_summarization_progress", return_value={}), \
                mock.patch.object(web_app, "_set_summarization_progress"), \
                mock.patch.object(web_app, "_summarize_session_impl", side_effect=summarize):
            asyncio.run(runtime_job_worker._run_summary_job({
                "timestamp": "20260101_000000", "scope_key": None, "incognito": {"owner": "local", "active": True},
            }))

        self.assertEqual(seen, [(True, "job_started_incognito", "local")])
        self.assertIsNone(web_app.current_incognito_session())


if __name__ == "__main__":
    unittest.main()
