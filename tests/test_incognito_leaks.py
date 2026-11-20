"""Incognito leak suite.

A synthetic deployment is driven through every feature that calls the AI model while the admin
policy requires incognito mode for cloud models. A recording model plays the provider: nothing it
receives may contain the deployment's own names, and what the user gets back has the real names.
"""

import asyncio
import base64
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
for folder in (ROOT / "src", ROOT / "tests"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import web_app  # noqa: E402
from capabilities import CapabilityManager  # noqa: E402
from config_manager import ConfigManager  # noqa: E402
from incognito import IncognitoLLMClient, IncognitoPolicy, IncognitoStore  # noqa: E402
from security_manager import SecurityManager  # noqa: E402
from test_discovery_pipeline import APPS, INDEXES, TOOL_NAMES, FakeSplunkMCP, make_engine, text_content  # noqa: E402

# Importing the worker marks the whole process as a worker; keep that out of the other tests.
with mock.patch.dict(os.environ):
    import runtime_job_worker  # noqa: E402

HOSTS = [
    {"host": "web-01.contoso.local", "totalCount": "100"},
    {"host": "dc-01", "totalCount": "200"},
    {"host": "fw-edge-02", "totalCount": "2000"},
    {"host": "10.20.30.40", "totalCount": "50"},
]
CONTOSO_INDEX = {"title": "contoso_prod", "totalEventCount": "4000", "currentDBSizeMB": "80", "datatype": "event"}
CONTOSO_APP = {"name": "contoso_soc", "label": "Contoso SOC Toolkit", "version": "2.1", "disabled": "0"}

# The deployment's own names. None of them may reach the model.
REAL_NAMES = (
    "contoso", "web-01", "dc-01", "fw-edge-02", "10.20.30.40", "legacy_app", "empty_idx", "svc_analytics",
    "jdoe", "TA-legacy",
)
# Everything incognito mode should replace here. A stand-in for anything else means an ordinary
# word or a field name was mistaken for a name.
EXPECTED_MASKED = frozenset(name.lower() for name in (
    "web-01.contoso.local", "dc-01", "fw-edge-02", "10.20.30.40", "10.20.30.41", "firewall", "legacy_app",
    "empty_idx", "contoso_prod", "svc_analytics", "jdoe", "contoso_soc", "Contoso SOC Toolkit",
    "Contoso VPN failures", "contoso_assets", "contoso_soc_analyst",
))
STAND_IN = re.compile(r"\b(?:host|idx|user|app|search|kv|role|object|term|secret)_\d{4}\b|\b198\.18\.\d{1,3}\.\d{1,3}\b")
ROWS = [
    {"index": "contoso_prod", "host": "web-01.contoso.local", "src": "10.20.30.40", "user": "jdoe", "count": "7",
     "_raw": "Jan 1 web-01 sshd: failed password for jdoe from 10.20.30.40"},
    {"index": "legacy_app", "host": "dc-01", "src": "10.20.30.41", "user": "svc_analytics", "count": "2",
     "_raw": "Jan 1 dc-01 audit: svc_analytics logon"},
]


class ContosoMCP(FakeSplunkMCP):
    """The discovery pipeline's fake Splunk server, filled with names that identify the organization."""

    def __init__(self):
        super().__init__(hosts=HOSTS, apps=APPS + [CONTOSO_APP])

    def tool_result(self, name, args):
        if name == "splunk_get_indexes":
            return {"structuredContent": {"results": [dict(row) for row in INDEXES + [CONTOSO_INDEX]]}, "content": []}
        if name == "splunk_get_index_info" and args.get("index_name") == CONTOSO_INDEX["title"]:
            return text_content({"name": CONTOSO_INDEX["title"], "frozenTimePeriodInSecs": "31536000",
                                 "currentDBSizeMB": "80", "totalEventCount": "4000"})
        if name == "splunk_get_knowledge_objects" and args.get("type") == "saved_searches":
            return text_content({"results": [{
                "name": "Contoso VPN failures", "is_scheduled": "1",
                "search": "index=contoso_prod sourcetype=vpn action=failure user=jdoe | stats count by src",
            }]})
        if name == "splunk_get_user_info":
            return text_content({"name": "svc_analytics", "roles": ["power", "contoso_soc_analyst"]})
        if name == "splunk_get_kv_store_collections":
            return text_content({"results": [{"name": "contoso_assets", "app": "contoso_soc"}]})
        return super().tool_result(name, args)


def stand_ins(text):
    found = []
    for match in STAND_IN.finditer(text):
        if match.group(0) not in found:
            found.append(match.group(0))
    return found


def pick(names, prefix, default):
    return next((name for name in names if name.startswith(prefix)), default)


class RecordingModel:
    """Plays the AI provider: keeps every request and answers with the stand-ins it was shown."""

    def __init__(self):
        self.requests = []
        self.scripted = []

    async def analyze_data(self, data, analysis_type):
        self.requests.append(data)
        names = stand_ins(json.dumps(data))
        phrase = ", ".join(names[:4]) or "no named items"
        if analysis_type == "patterns":
            return {"patterns": [f"{pick(names, 'idx_', 'main')} holds the fewest events"]}
        if analysis_type == "recommendations":
            return {"recommendations": [{
                "title": f"Review {pick(names, 'idx_', 'main')}", "priority": "high", "category": "Data Quality",
                "description": f"Discovery named {phrase}.", "suggested_actions": f"Check {phrase}.",
            }]}
        return {"use_cases": [{"title": f"Correlate {phrase}", "description": f"Join {phrase}.",
                               "data_sources": names[:2]}]}

    async def generate_response(self, prompt=None, messages=None, max_tokens=None, temperature=None):
        sent = prompt if messages is None else json.dumps(messages)
        self.requests.append(sent)
        if self.scripted:
            return self.scripted.pop(0)(sent)
        return self.answer(sent)

    @staticmethod
    def answer(sent):
        names = stand_ins(sent)
        phrase = ", ".join(names[:4]) or "no named items"
        host = pick(names, "host_", "the host")
        index = pick(names, "idx_", "main")
        spl = f"index={index} host={host} earliest=-24h | stats count by host"
        if "extract specific, actionable findings" in sent:
            return json.dumps({"security_findings": [{
                "type": "Forwarding gap", "severity": "high", "description": f"Gaps on {phrase}.",
                "affected_resources": names[:3], "metric": "1", "recommendation": f"Check {host}.",
            }]})
        if "Generate 8 SPL queries" in sent:
            return json.dumps([{
                "title": f"Events from {host}", "description": f"Counts events from {host} in {index}.",
                "use_case": "Data Quality", "category": "Data Quality", "spl": spl, "finding_reference": "Gap",
                "execution_time": "< 30s", "business_value": "Finds gaps", "priority": "HIGH",
                "difficulty": "Beginner", "environment_evidence": [index, host],
            }])
        if "implementation tasks for the Splunk administrator" in sent:
            return json.dumps([{
                "title": f"Restore forwarding on {host}", "priority": "HIGH", "category": "Data Quality",
                "description": f"{host} stopped sending to {index}.", "prerequisites": [],
                "steps": [{"number": 1, "action": f"Check the forwarder on {host}", "spl": spl}],
                "verification_spl": spl, "expected_outcome": f"{host} sends events to {index}",
                "impact": "Complete data", "estimated_time": "30 minutes", "rollback": "None",
            }])
        if "Splunk admin task verification" in sent:
            return json.dumps({"status": "partial", "message": f"{phrase} still show failures.",
                               "metrics": {"current_value": phrase, "expected_value": "0", "gap": host},
                               "recommendations": [f"Check {host}"]})
        if "troubleshoot a failed task" in sent:
            return json.dumps({"root_cause": f"{host} stopped forwarding to {index}.", "remediation_steps": [
                {"number": 1, "action": f"Restart the forwarder on {host}", "spl": spl, "explanation": "Resumes data",
                 "risk": "low"}], "estimated_time": "1 hour", "success_probability": "high"})
        if "M-26-14 advisor" in sent:
            return json.dumps({"summary": f"Retention evidence covers {phrase}.", "environment_relevance": index,
                               "recommended_adjustments": [f"Extend retention for {index}"],
                               "suggested_follow_ups": [f"Recheck {host}"], "evidence_gaps": [], "confidence_notes": []})
        if "plan an investigation" in sent:
            return json.dumps({"title": "Forwarding check", "items": [f"Is {host} sending to {index}?",
                                                                       f"Which users does {host} log?"],
                               "questions": [f"How many events did {host} send to {index} today?"]})
        if "track a Splunk user's progress" in sent:
            item_id = re.search(r"id=(\S+) status=", sent).group(1)
            return json.dumps({"updates": [{"id": item_id, "status": "answered", "note": f"{host} sent to {index}."}],
                               "new_items": [], "summary": f"{host} is confirmed.", "questions": []})
        return f"Named in this request: {phrase}."


class FakeImageAPI:
    def __init__(self):
        self.prompts = []

    def __call__(self, *_args, **_kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, _url, headers=None, json=None):
        self.prompts.append(json["prompt"])
        image = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode("ascii")
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"data": [{"b64_json": image}]})


class IncognitoLeakSuite(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.temp_path = Path(temp.name)
        original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.addCleanup(os.chdir, original_cwd)
        Path("output").mkdir()

        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.config_manager.update_llm(provider="openai", model="gpt-test", api_key="test-" + "key")
        self.config_manager.update_mcp(url="https://splunk.example.test:8089/services/mcp", token="test-token")
        originals = (web_app.config_manager, web_app.capability_manager, web_app.security_manager)

        def restore():
            web_app.config_manager, web_app.capability_manager, web_app.security_manager = originals

        self.addCleanup(restore)
        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = SecurityManager(str(self.temp_path / "security.db"))

        self.store = IncognitoStore(Path("output") / "incognito", Fernet(Fernet.generate_key()))
        self.store.save_policy(IncognitoPolicy(force_for_cloud=True))
        self.model = RecordingModel()
        self.client = IncognitoLLMClient(self.model, web_app.current_incognito_session)
        for target, value in (("incognito_store", self.store), ("get_or_create_llm_client", lambda *_a, **_k: self.client)):
            patcher = mock.patch.object(web_app, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.http = TestClient(web_app.app)
        self.addCleanup(self.http.close)

    # ----- checks ---------------------------------------------------------------------------

    def assert_nothing_identifying_sent(self, requests=None, *, with_note=True):
        requests = self.model.requests if requests is None else requests
        self.assertTrue(requests, "the model was never called")
        for request in requests:
            text = request if isinstance(request, str) else json.dumps(request, default=str)
            lowered = text.lower()
            for real in REAL_NAMES:
                self.assertNotIn(real.lower(), lowered, f"{real} reached the model in: {text[:300]}")
            self.assertNotIn("failed password", lowered)
            if with_note:
                self.assertIn("Privacy note", text)

    def assert_clean_afterwards(self):
        records = sorted((self.store.root / "ledger").glob("*.rec"))
        self.assertTrue(records, "no record of what the AI saw was saved")
        for path in records:
            text = json.dumps(self.store._read(path)).lower()
            for real in REAL_NAMES:
                self.assertNotIn(real.lower(), text, f"{real} is in the record of what the AI saw")
        masked = {real.lower() for values in self.store.vault(web_app.INCOGNITO_VAULT_SCOPE).entries().values()
                  for real, _stand_in in values.values()}
        self.assertEqual(masked - EXPECTED_MASKED, set(), "stand-ins were made for things that are not names")

    def assert_real_names_restored(self, value, label):
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        self.assertIsNone(STAND_IN.search(text), f"{label} still shows a stand-in: {text[:400]}")
        self.assertTrue(any(real.lower() in text.lower() for real in REAL_NAMES), f"{label} has no real names: {text[:400]}")

    # ----- features -------------------------------------------------------------------------

    def run_discovery(self):
        mcp = ContosoMCP()

        async def tools_list(_config):
            return list(TOOL_NAMES)

        def engine(**kwargs):
            return make_engine(mcp, llm=kwargs["llm_client"])

        payload = {"scope": {}, "runtime_binding": {}, "incognito": web_app.incognito_job_payload("local")}
        self.assertTrue(payload["incognito"]["active"])
        with mock.patch.object(web_app, "_is_runtime_worker_process", return_value=True), \
                mock.patch.object(web_app, "DISCOVERY_PIPELINE_VERSION", "v2"), \
                mock.patch.object(web_app, "discover_mcp_tools", tools_list), \
                mock.patch.object(web_app, "DiscoveryEngine", engine), \
                mock.patch.object(web_app, "discovery_runtime_state", web_app._build_discovery_runtime_state()), \
                mock.patch.dict(web_app.discovery_runtime_states, {}, clear=True):
            asyncio.run(runtime_job_worker._run_discovery_job(payload))
        sessions = web_app.load_discovery_sessions()
        self.assertEqual(len(sessions), 1)
        return sessions[0]["timestamp"]

    def run_summary(self, timestamp):
        with mock.patch.object(web_app, "_is_runtime_worker_process", return_value=True), \
                mock.patch.dict(web_app.summarization_progress, {}, clear=True):
            asyncio.run(runtime_job_worker._run_summary_job({
                "timestamp": timestamp, "scope_key": None, "incognito": web_app.incognito_job_payload("local"),
            }))
        return json.loads((Path("output") / f"v2_ai_summary_{timestamp}.json").read_text(encoding="utf-8"))

    def test_discovery_reports_keep_real_names_while_the_model_sees_stand_ins(self):
        timestamp = self.run_discovery()
        self.assert_nothing_identifying_sent()
        self.assertEqual(len(self.model.requests), 3)
        blueprint = json.loads((Path("output") / f"v2_intelligence_blueprint_{timestamp}.json").read_text("utf-8"))
        self.assertEqual(blueprint["llm_status"]["recommendations"]["status"], "ok")
        self.assert_real_names_restored(blueprint["recommendations"][0]["description"], "recommendation")
        for report in Path("output").glob(f"v2_*_{timestamp}.*"):
            self.assertIsNone(STAND_IN.search(report.read_text("utf-8")), f"{report.name} shows a stand-in")
        self.assert_clean_afterwards()

    def test_ai_summary_and_infographic(self):
        timestamp = self.run_discovery()
        self.model.requests.clear()
        summary = self.run_summary(timestamp)
        self.assertEqual(len(self.model.requests), 4)
        self.assert_nothing_identifying_sent()
        self.assert_real_names_restored(summary["ai_summary"], "AI summary")
        self.assert_real_names_restored(summary.get("admin_tasks") or [], "admin tasks")

        images = FakeImageAPI()
        with mock.patch.object(web_app.httpx, "AsyncClient", images):
            response = self.http.post("/api/summary/generate-infographic",
                                      json={"timestamp": timestamp, "summary_data": summary})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("stand-ins", response.json()["incognito_note"])
        self.assertEqual(len(images.prompts), 1)
        self.assertRegex(images.prompts[0], r"host_\d{4}")
        self.assert_nothing_identifying_sent(images.prompts, with_note=False)
        self.assert_clean_afterwards()

    def test_task_verification_and_remediation(self):
        timestamp = self.run_discovery()
        self.model.requests.clear()

        async def splunk(_call, _config):
            return {"result": {"structuredContent": {"results": [dict(row) for row in ROWS]}}}

        spl = "index=contoso_prod host=web-01.contoso.local | stats count by host, src, user"
        with mock.patch.object(web_app, "execute_mcp_tool_call", splunk):
            verified = self.http.post("/verify-task", json={
                "session_id": timestamp, "task_index": 0, "verification_spl": spl,
                "expected_outcome": "web-01.contoso.local has no failed logons for jdoe",
            }).json()
        self.assertEqual(verified["status"], "partial", verified)
        self.assert_real_names_restored(verified["message"], "verification message")
        self.assertEqual(verified["verification_spl"], spl)
        self.assertTrue(verified["incognito"]["ledger_id"])

        remediation = self.http.post("/get-remediation", json={
            "session_id": timestamp, "task_index": 0, "verification_result": verified,
            "task_details": {"title": "Stop failed logons on web-01.contoso.local", "priority": "HIGH",
                             "steps": [{"number": 1, "action": "Reset jdoe", "spl": spl}]},
        }).json()
        self.assert_real_names_restored(remediation["root_cause"], "root cause")
        self.assert_real_names_restored(remediation["remediation_steps"][0]["spl"], "remediation SPL")
        self.assertEqual(len(self.model.requests), 2)
        self.assert_nothing_identifying_sent()
        self.assert_clean_afterwards()

    def test_m26_14_advisory(self):
        self.run_discovery()
        self.model.requests.clear()
        self.assertTrue(web_app.capability_manager.install_capability("m26_14_advisor").ok)
        self.assertTrue(web_app.capability_manager.enable_capability("m26_14_advisor").ok)

        async def splunk(_call, _config):
            rows = [{"index": "contoso_prod", "host": "web-01.contoso.local", "retention_days": 30,
                     "retention_status": "below_floor"}]
            return {"result": {"structuredContent": {"status_code": 200, "results": rows}}}

        with mock.patch.object(web_app, "execute_mcp_tool_call", splunk):
            response = self.http.post("/api/discovery/m26-14/validate", json={
                "pack_id": "retention_and_searchability", "timestamp": "latest", "earliest": "-14d", "latest": "now",
            })
        self.assertEqual(response.status_code, 200, response.text)
        analysis = response.json()["advisory"]["llm_analysis"]
        self.assertEqual(analysis["status"], "ready", analysis)
        self.assert_real_names_restored(analysis["recommended_adjustments"], "M-26-14 advice")
        self.assertEqual(len(self.model.requests), 1)
        self.assert_nothing_identifying_sent()
        self.assert_clean_afterwards()

    def test_goal_planning_and_progress(self):
        self.run_discovery()
        self.model.requests.clear()
        created = self.http.post("/api/chat/goals", json={
            "goal": "Find out why web-01.contoso.local stopped sending to contoso_prod",
        })
        self.assertEqual(created.status_code, 200, created.text)
        goal = created.json()["goal"]
        self.assertEqual(goal["planned_by"], "model", created.json())
        self.assert_real_names_restored([item["text"] for item in goal["items"]], "goal questions")

        web_app.chat_goal_store.record_turn(
            "local", goal["id"], "Did web-01.contoso.local send to contoso_prod today?",
            "Yes: web-01.contoso.local sent 7 events to contoso_prod; jdoe failed to log on from 10.20.30.40.",
        )
        progress = self.http.post(f"/api/chat/goals/{goal['id']}/progress").json()
        self.assertTrue(progress["updated"], progress)
        self.assert_real_names_restored(progress["goal"]["summary"], "goal progress")
        self.assertEqual(len(self.model.requests), 2)
        self.assert_nothing_identifying_sent()
        self.assert_clean_afterwards()

    def test_chat_with_discovery_context_and_search_rows(self):
        self.run_discovery()
        self.model.requests.clear()

        def tool_call(sent):
            names = stand_ins(sent.split("Privacy note")[-1])
            payload = {"tool": "splunk_run_query", "args": {
                "query": f"search index={pick(names, 'idx_', 'main')} host={pick(names, 'host_', '*')} | stats count by host, src, user",
                "earliest_time": "-24h", "latest_time": "now"}}
            return f"<TOOL_CALL>{json.dumps(payload)}</TOOL_CALL>"

        self.model.scripted = [tool_call, RecordingModel.answer]
        searches = []

        async def splunk(call, _config):
            searches.append(call["params"]["arguments"]["query"])
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": {"results": [dict(row) for row in ROWS]}}}

        async def tools_list(_config):
            return {"splunk_run_query", "splunk_get_indexes"}

        with mock.patch.object(web_app, "discover_mcp_tools", tools_list), \
                mock.patch.object(web_app, "execute_mcp_tool_call", splunk), \
                mock.patch.object(web_app, "_get_memory_store_path", lambda session_id, owner=None: self.temp_path / f"{session_id}.json"), \
                mock.patch.object(web_app, "sync_chat_settings_for_request", lambda *_args, **_kwargs: dict(web_app.chat_session_settings)), \
                mock.patch.dict(web_app.chat_session_settings, {"enable_splunk_augmentation": True, "enable_rag_context": False}), \
                mock.patch.dict(web_app.chat_agent_memory, {}, clear=True):
            result = asyncio.run(web_app.run_chat_turn({
                "message": "What is web-01.contoso.local sending to contoso_prod, and is jdoe involved?",
                "history": [], "chat_session_id": "leak_suite_chat",
            }, goal_owner="local"))

        self.assertNotIn("error", result, result.get("error"))
        self.assertIn("contoso_prod", searches[0])
        self.assertIn("web-01.contoso.local", searches[0])
        self.assert_real_names_restored(result["response"], "chat answer")
        self.assertEqual(len(self.model.requests), 2)
        self.assert_nothing_identifying_sent()
        self.assert_clean_afterwards()


if __name__ == "__main__":
    unittest.main()
