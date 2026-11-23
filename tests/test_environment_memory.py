import asyncio
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for path in (SRC_DIR, Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import web_app  # noqa: E402
from capabilities import CapabilityManager  # noqa: E402
from config_manager import ConfigManager  # noqa: E402
from environment_memory import (  # noqa: E402
    CHECK_QUERIES,
    EnvironmentMemory,
    EnvironmentMemorySettings,
    EnvironmentSettingsStore,
    apply_settings_updates,
    busiest_index,
    check_rows_complete,
    known_environment_block,
    merge_observation,
    observation_from_blueprint,
    observation_from_check,
    observation_from_rows,
)
from environment_memory import record as record_module  # noqa: E402
from environment_memory.record import empty_record  # noqa: E402
from security_manager import SecurityManager  # noqa: E402
from test_incognito_app import IncognitoAppCase, RecordingMCP, ScriptedModel, rows_result, tool_call  # noqa: E402

# Recent enough that the second run's changes fall within the chat block's 7-day window.
BASE = (datetime.now(timezone.utc) - timedelta(days=4)).replace(microsecond=0)
T1, T2, T3 = BASE, BASE + timedelta(days=2), BASE + timedelta(days=3)
HOUR = timedelta(hours=1)


def iso(moment):
    return moment.isoformat().replace("+00:00", "Z")


def epoch(moment):
    return int(moment.timestamp())


def blueprint(at, *, indexes, sourcetypes=None, hosts=None, recent=None, idle=()):
    ledger = [{"kind": "index", "data": {"name": name, "totalEventCount": 1000, "currentDBSizeMB": 12.5}} for name in indexes]
    for name, last in (sourcetypes or {}).items():
        ledger.append({"kind": "sourcetype", "data": {"sourcetype": name, "lastTime": epoch(last), "totalCount": 40}})
    for name, last in (hosts or {}).items():
        ledger.append({"kind": "host", "data": {"host": name, "lastTime": epoch(last), "totalCount": 25}})
    ledger.append({"kind": "analytics", "data": {"analytics_id": "recent_index_activity", "data": {
        "recent_event_counts": dict(recent or {}), "indexes_without_recent_events": list(idle),
    }}})
    return {
        "generated_at": iso(at),
        "finding_ledger": ledger,
        "discovery_step_status": {name: {"status": "ok"} for name in ("indexes", "sourcetypes", "hosts", "sources")},
        "discovered_inventory": {"indexes": list(indexes)},
    }


RUN1 = blueprint(
    T1,
    indexes=["contoso_web", "contoso_fw", "contoso_old", "_internal"],
    sourcetypes={"contoso:web": T1 - HOUR, "contoso:fw": T1 - 2 * HOUR},
    hosts={"web01": T1 - HOUR, "fw01": T1 - HOUR},
    recent={"contoso_web": 5000, "contoso_fw": 300, "_internal": 90000},
    idle=["contoso_old"],
)
RUN2 = blueprint(
    T2,
    indexes=["contoso_web", "contoso_fw", "contoso_new", "_internal"],
    sourcetypes={"contoso:web": T2 - HOUR, "contoso:new": T2 - HOUR / 2},
    hosts={"web01": T2 - HOUR},
    recent={"contoso_web": 5200, "contoso_new": 150, "_internal": 91000},
    idle=["contoso_fw"],
)
RUN3 = blueprint(
    T3,
    indexes=["contoso_web", "contoso_fw", "contoso_new", "_internal"],
    sourcetypes={"contoso:web": T3 - HOUR, "contoso:new": T3 - HOUR, "contoso:fw": T3 - HOUR},
    hosts={"web01": T3 - HOUR, "fw01": T3 - HOUR},
    recent={"contoso_web": 5100, "contoso_new": 140, "contoso_fw": 200, "_internal": 90500},
)
REFS = ("20260101_000000", "20260103_000000", "20260104_000000")


def summary(changes):
    return sorted((change["change"], change["kind"], change["name"]) for change in changes)


def merged(*runs):
    record = empty_record()
    for ref, run in zip(REFS, runs):
        merge_observation(record, observation_from_blueprint(run, ref), quiet_hours=24)
    return record


def check(at, rows, hosts):
    return observation_from_check(rows, hosts, at=at, sourcetype_complete=True, host_complete=True)


class MergeTests(unittest.TestCase):
    def test_first_run_records_what_exists_without_calling_it_new(self):
        record = empty_record()
        changes = merge_observation(record, observation_from_blueprint(RUN1, REFS[0]), quiet_hours=24)

        self.assertEqual(changes, [])
        self.assertEqual(set(record["baseline"]), {"index", "sourcetype", "host", "source", "index_listing"})
        self.assertEqual(len(record["entities"]["index"]), 4)
        self.assertEqual(record["entities"]["index"]["contoso_web"]["status"], "active")
        self.assertEqual(record["entities"]["index"]["contoso_old"]["status"], "idle")

    def test_later_runs_report_new_quiet_gone_and_back(self):
        record = merged(RUN1)
        second = merge_observation(record, observation_from_blueprint(RUN2, REFS[1]), quiet_hours=24)
        self.assertEqual(summary(second), [
            ("gone", "index", "contoso_old"),
            ("new", "index", "contoso_new"),
            ("new", "sourcetype", "contoso:new"),
            ("went_quiet", "host", "fw01"),
            ("went_quiet", "index", "contoso_fw"),
            ("went_quiet", "sourcetype", "contoso:fw"),
        ])
        quiet = next(change for change in second if change["name"] == "contoso:fw")
        self.assertTrue(quiet["detail"].startswith("No events since "))
        self.assertTrue(all(change["origin"] == "discovery" for change in second))

        third = merge_observation(record, observation_from_blueprint(RUN3, REFS[2]), quiet_hours=24)
        self.assertEqual(summary(third), [
            ("back", "host", "fw01"),
            ("back", "index", "contoso_fw"),
            ("back", "sourcetype", "contoso:fw"),
        ])
        self.assertEqual([change["id"] for change in record["changes"]], list(range(1, 10)))

    def test_a_longer_quiet_threshold_waits_before_calling_something_quiet(self):
        record = empty_record()
        merge_observation(record, observation_from_blueprint(RUN1, REFS[0]), quiet_hours=24 * 7)
        changes = merge_observation(record, observation_from_blueprint(RUN2, REFS[1]), quiet_hours=24 * 7)
        self.assertNotIn("went_quiet", {change["change"] for change in changes})

    def test_checks_report_volume_shifts_of_more_than_half(self):
        record = empty_record()
        first = check(T1, [{"index": "contoso_web", "sourcetype": "contoso:web", "count": "1000", "lastTime": epoch(T1 - HOUR)}],
                      [{"host": "web01", "count": "1000", "lastTime": epoch(T1 - HOUR)}, {"host": "web02", "count": "40"}])
        self.assertEqual(merge_observation(record, first, quiet_hours=24), [])

        later = T1 + 6 * HOUR
        second = check(later, [{"index": "contoso_web", "sourcetype": "contoso:web", "count": "3500", "lastTime": epoch(later)}],
                       [{"host": "web01", "count": "1400", "lastTime": epoch(later)}, {"host": "web02", "count": "95"}])
        changes = merge_observation(record, second, quiet_hours=24)
        self.assertEqual(summary(changes), [
            ("volume_shift", "index", "contoso_web"),
            ("volume_shift", "sourcetype", "contoso:web"),
        ])
        self.assertEqual(changes[0]["detail"], "Events in 24 hours went from 1,000 to 3,500 (up 250%)")
        self.assertEqual((changes[0]["previous"], changes[0]["current"]), (1000, 3500))

    def test_discovery_metadata_counts_are_never_compared_as_volume(self):
        record = merged(RUN1)
        busier = blueprint(T2, indexes=["contoso_web"], sourcetypes={"contoso:web": T2 - HOUR}, recent={"contoso_web": 5000})
        busier["finding_ledger"][1]["data"]["totalCount"] = 4000
        changes = merge_observation(record, observation_from_blueprint(busier, REFS[1]), quiet_hours=24)
        self.assertNotIn("volume_shift", {change["change"] for change in changes})

    def test_chat_searches_add_new_names_but_never_call_anything_quiet(self):
        record = empty_record()
        early = observation_from_rows([("splunk_run_query", [{"index": "contoso_web", "sourcetype": "contoso:web", "count": "5"}])], T1)
        self.assertEqual(merge_observation(record, early, quiet_hours=24), [])
        self.assertIn("chat", record["entities"]["sourcetype"]["contoso:web"]["origins"])

        record = merged(RUN1)
        rows = [{"index": "contoso_web", "sourcetype": "contoso:dns", "count": "12"}]
        changes = merge_observation(record, observation_from_rows([("splunk_run_query", rows)], T2), quiet_hours=24)
        self.assertEqual(summary(changes), [("new", "sourcetype", "contoso:dns")])
        self.assertEqual(changes[0]["origin"], "chat")
        self.assertEqual(record["entities"]["sourcetype"]["contoso:dns"]["indexes"], ["contoso_web"])
        self.assertEqual(record["entities"]["host"]["fw01"]["status"], "active")

    def test_the_change_log_and_each_kind_are_capped(self):
        record = merged(RUN1)
        record["changes"] = [{"id": number, "at": iso(BASE), "kind": "index", "name": f"x{number}", "change": "new"} for number in range(1, 501)]
        record["next_change_id"] = 501
        merge_observation(record, observation_from_blueprint(RUN2, REFS[1]), quiet_hours=24)
        self.assertEqual(len(record["changes"]), record_module.MAX_CHANGES)
        self.assertEqual(record["changes"][-1]["id"], 506)

        record = empty_record()
        with mock.patch.dict(record_module.ENTITY_CAPS, {"host": 3}):
            for number in range(5):
                rows = [{"host": f"web{number:02d}", "count": "1"}]
                merge_observation(record, observation_from_rows([("splunk_run_query", rows)], T1 + number * HOUR), quiet_hours=24)
        self.assertEqual(sorted(record["entities"]["host"]), ["web02", "web03", "web04"])


class ObservationTests(unittest.TestCase):
    def test_chat_rows_only_count_real_names_from_search_results(self):
        rows = [
            {"index": "contoso_web", "sourcetype": "contoso:web", "host": "web01", "count": "3"},
            {"index": "_internal", "sourcetype": "splunkd", "host": "idx01", "count": "9"},
            {"index": "contoso_web", "host": "*", "sourcetype": "null", "count": "2"},
            {"index": "bad index!", "count": "1"},
            {"index": "contoso_zero", "count": "0"},
            {"title": "contoso_listed", "totalEventCount": "12"},
        ]
        observation = observation_from_rows(
            [("splunk_run_query", rows), ("splunk_get_knowledge_objects", [{"index": "contoso_ko"}])], T1
        )
        names = {kind: sorted(item["name"] for item in observation["items"][kind].values()) for kind in observation["items"]}
        self.assertEqual(names["index"], ["_internal", "contoso_listed", "contoso_web"])
        self.assertEqual(names["sourcetype"], ["contoso:web"])
        self.assertEqual(names["host"], ["web01"])
        self.assertEqual(observation["complete"], {})
        self.assertIsNone(observation_from_rows([("splunk_run_query", [{"count": "4"}])], T1))

    def test_check_results_count_as_complete_only_when_nothing_was_cut(self):
        self.assertTrue(check_rows_complete(10))
        self.assertTrue(check_rows_complete(999))
        self.assertFalse(check_rows_complete(0))
        self.assertFalse(check_rows_complete(10, truncated=True))
        self.assertFalse(check_rows_complete(10, total_rows=20))
        self.assertFalse(check_rows_complete(1000))
        self.assertFalse(check_rows_complete(5000))


class RecordFileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def write_run(self, ref, payload):
        path = self.folder / f"v2_intelligence_blueprint_{ref}.json"
        path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
        return path

    def test_a_new_record_starts_from_the_last_two_runs_and_merges_each_run_once(self):
        for ref, run in zip(REFS, (RUN1, RUN2, RUN3)):
            self.write_run(ref, run)
        memory = EnvironmentMemory(self.folder)
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 2)
        record = memory.load()
        self.assertEqual(record["discovery_refs"], list(REFS[1:]))
        self.assertTrue(record["changes"])
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 0)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(memory.path.stat().st_mode), 0o600)

        self.write_run("20260105_000000", blueprint(T3 + HOUR, indexes=["contoso_web"], recent={"contoso_web": 10}))
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 1)

    def test_a_report_still_being_written_is_read_on_a_later_pass(self):
        self.write_run(REFS[0], RUN1)
        self.write_run(REFS[1], RUN2)
        unfinished = self.write_run(REFS[2], "{")
        memory = EnvironmentMemory(self.folder)
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 1)
        self.assertEqual(memory.load()["discovery_refs"], [REFS[1]])
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 0)
        self.assertEqual(memory.load()["discovery_refs"], [REFS[1]])

        old = time.time() - 3600
        os.utime(unfinished, (old, old))
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 0)
        self.assertEqual(memory.load()["discovery_refs"], [REFS[1], REFS[2]])

    def test_clearing_starts_over_instead_of_rebuilding_from_old_runs(self):
        self.write_run(REFS[0], RUN1)
        self.write_run(REFS[1], RUN2)
        memory = EnvironmentMemory(self.folder)
        memory.sync_discovery(quiet_hours=24)
        memory.clear()
        record = memory.load()
        self.assertFalse(any(record["entities"].values()))
        self.assertEqual(record["changes"], [])
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 0)
        self.write_run(REFS[2], RUN3)
        self.assertEqual(memory.sync_discovery(quiet_hours=24), 1)

    def test_an_unreadable_record_starts_over(self):
        memory = EnvironmentMemory(self.folder)
        memory.path.parent.mkdir(parents=True)
        memory.path.write_text("not json", encoding="utf-8")
        self.assertEqual(memory.load()["entities"]["index"], {})


class ContextTests(unittest.TestCase):
    def test_known_environment_block_lists_names_quiet_items_and_recent_changes(self):
        record = merged(RUN1, RUN2)
        block = known_environment_block(record, now=T2 + HOUR)
        self.assertTrue(block.startswith("KNOWN ENVIRONMENT"))
        self.assertIn("contoso_web (5,200 in 24h)", block)
        self.assertLess(block.index("contoso_web"), block.index("_internal"))
        self.assertIn("Quiet now:", block)
        self.assertIn("index contoso_fw", block)
        self.assertIn("new index contoso_new", block)
        self.assertNotIn("contoso_old", block.split("Changes in the last")[0])
        self.assertEqual(known_environment_block(empty_record(), now=T2), "")
        self.assertNotIn("Changes in the last", known_environment_block(record, now=T2 + timedelta(days=30)))

    def test_compact_block_lists_fewer_names(self):
        record = empty_record()
        rows = [{"host": f"web{number:02d}", "count": "1"} for number in range(10)]
        merge_observation(record, observation_from_rows([("splunk_run_query", rows)], T1), quiet_hours=24)
        self.assertIn("and 4 more", known_environment_block(record, now=T1, compact=True))
        self.assertNotIn("more", known_environment_block(record, now=T1))

    def test_busiest_index_skips_internal_and_quiet_indexes(self):
        self.assertEqual(busiest_index(merged(RUN1)), "contoso_web")
        internal_only = empty_record()
        merge_observation(internal_only, observation_from_rows([("splunk_run_query", [{"index": "_internal", "count": "9"}])], T1), quiet_hours=24)
        self.assertEqual(busiest_index(internal_only), "")


class SettingsTests(unittest.TestCase):
    def test_updates_are_validated(self):
        updated = apply_settings_updates(EnvironmentMemorySettings(), {"scheduled_check": True, "check_interval_hours": 12})
        self.assertTrue(updated.scheduled_check)
        self.assertEqual(updated.check_interval_hours, 12)
        self.assertTrue(updated.learn_from_chat)
        self.assertEqual(updated.quiet_hours, 24)
        for bad in ({"scheduled_check": "yes"}, {"check_interval_hours": 0}, {"check_interval_hours": True},
                    {"quiet_hours": 721}, {"quiet_hours": 2.5}):
            with self.assertRaises(ValueError):
                apply_settings_updates(EnvironmentMemorySettings(), bad)

    def test_store_round_trip_and_unreadable_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EnvironmentSettingsStore(Path(temp_dir) / "settings.json")
            self.assertFalse(store.load().scheduled_check)
            saved = store.save(EnvironmentMemorySettings(scheduled_check=True, quiet_hours=48), updated_by="admin")
            loaded = store.load()
            self.assertEqual((loaded.scheduled_check, loaded.quiet_hours, loaded.updated_by), (True, 48, "admin"))
            self.assertEqual(loaded.updated_at, saved.updated_at)
            self.assertNotIn("unreadable", json.loads(store.path.read_text(encoding="utf-8")))
            store.path.write_text("{", encoding="utf-8")
            broken = store.load()
            self.assertTrue(broken.unreadable)
            self.assertFalse(broken.scheduled_check)


def search_result(rows):
    return {"tool_calls": [{"tool": "splunk_run_query", "args": {}, "result": rows_result(rows)}]}


class EnvironmentAppCase(IncognitoAppCase):
    """A temporary output folder whose global scope holds RUN1 and RUN2."""

    def setUp(self):
        super().setUp()
        (Path("output") / "v2_intelligence_blueprint_20260101_000000.json").unlink()
        for ref, run in zip(REFS, (RUN1, RUN2)):
            (Path("output") / f"v2_intelligence_blueprint_{ref}.json").write_text(json.dumps(run), encoding="utf-8")

    def global_record(self):
        return EnvironmentMemory(Path("output")).load()


class ChatLearningTests(EnvironmentAppCase):
    def test_chat_results_add_names_to_the_askers_scope_only(self):
        changes = web_app.learn_environment_from_chat(Path("output"), search_result([
            {"index": "contoso_web", "sourcetype": "contoso:dns", "host": "dns01", "count": "7"},
        ]))
        self.assertEqual(changes, 2)
        record = self.global_record()
        self.assertIn("contoso:dns", record["entities"]["sourcetype"])
        self.assertIn("chat", record["entities"]["host"]["dns01"]["origins"])

        scoped = web_app._discovery_scope_output_dir("mcp:contoso-lab")
        web_app.learn_environment_from_chat(scoped, search_result([{"index": "contoso_lab", "count": "3"}]))
        self.assertIn("contoso_lab", EnvironmentMemory(scoped).load()["entities"]["index"])
        self.assertNotIn("contoso_lab", self.global_record()["entities"]["index"])

    def test_failed_searches_and_turned_off_learning_teach_nothing(self):
        self.assertEqual(web_app.learn_environment_from_chat(Path("output"), {"error": "boom"}), 0)
        failed = {"tool_calls": [{"tool": "splunk_run_query", "result": {"error": "Search failed", "status_code": 400}}]}
        self.assertEqual(web_app.learn_environment_from_chat(Path("output"), failed), 0)
        self.assertFalse(EnvironmentMemory(Path("output")).exists())

        web_app.environment_settings_store.save(EnvironmentMemorySettings(learn_from_chat=False))
        rows = search_result([{"index": "contoso_web", "sourcetype": "contoso:dns", "count": "7"}])
        self.assertEqual(web_app.learn_environment_from_chat(Path("output"), rows), 0)
        self.assertFalse(EnvironmentMemory(Path("output")).exists())

    def test_follow_on_suggestions_use_a_real_index_or_none(self):
        actions = web_app.build_follow_on_actions("hello", {}, known_index="contoso_web")
        self.assertEqual(len(actions), 1)
        self.assertIn("index=contoso_web", actions[0]["prompt"])
        self.assertEqual(web_app.build_follow_on_actions("hello", {}), [])
        self.assertEqual(web_app.environment_scope_folders(), [(web_app.DISCOVERY_SCOPE_GLOBAL, Path("output"))])

    def test_chat_instructions_list_the_known_environment(self):
        self.store.set_preference("local", False)
        llm = ScriptedModel(["tstats reads indexed fields, so it is faster than a raw search."])
        with self.chat(llm, RecordingMCP(lambda _call: rows_result([]))) as run:
            result = run({"message": "Why would tstats be faster than a raw search?", "history": [], "chat_session_id": "env_known"})
        self.assertNotIn("error", result, result.get("error"))
        system = llm.calls[0][0]["content"]
        self.assertIn("KNOWN ENVIRONMENT", system)
        self.assertIn("contoso_web (5,200 in 24h)", system)
        self.assertIn("new index contoso_new", system)

    def test_incognito_masks_names_that_only_chat_has_seen(self):
        self.store.set_preference("local", False)
        llm = ScriptedModel([
            tool_call("search index=contoso_web | stats count by host, sourcetype"),
            "dbhost07 sent 4 events.",
        ])
        mcp = RecordingMCP(lambda _call: rows_result([{"host": "dbhost07", "sourcetype": "db:audit", "index": "contoso_web", "count": "4"}]))
        with self.chat(llm, mcp) as run:
            run({"message": "Which hosts send to contoso_web?", "history": [], "chat_session_id": "env_learn"})
        self.assertIn("dbhost07", self.global_record()["entities"]["host"])

        self.store.set_preference("local", True)
        private = ScriptedModel(["tstats reads indexed fields, so it is faster."])
        with self.chat(private, RecordingMCP(lambda _call: rows_result([]))) as run:
            result = run({"message": "Why would tstats be faster than a raw search?", "history": [], "chat_session_id": "env_private"})
        self.assertNotIn("error", result, result.get("error"))
        sent = json.dumps(private.calls)
        self.assertIn("KNOWN ENVIRONMENT", sent)
        # Sourcetypes stay visible in incognito mode; indexes and hosts must not.
        self.assertIn("db:audit", sent)
        for real in ("dbhost07", "contoso_web", "contoso_fw", "web01", "fw01"):
            self.assertNotIn(real, sent)


class EnvironmentApiTests(EnvironmentAppCase):
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
        self.client = TestClient(web_app.app)
        self.addCleanup(self.client.close)

    def check_mcp(self, sourcetype_rows, host_rows):
        def handler(call):
            query = call["params"]["arguments"]["query"]
            return rows_result(sourcetype_rows if "by index sourcetype" in query else host_rows)
        return RecordingMCP(handler)

    def test_reading_settings_and_clearing_without_sign_in(self):
        data = self.client.get("/api/environment-memory").json()
        self.assertTrue(data["can_manage"])
        self.assertEqual(data["scope"]["scope_key"], web_app.DISCOVERY_SCOPE_GLOBAL)
        self.assertTrue(data["memory"]["has_data"])
        self.assertEqual(data["memory"]["counts"]["index"]["gone"], 1)
        self.assertEqual(data["memory"]["change_counts"]["went_quiet"], 3)
        self.assertFalse(data["settings"]["scheduled_check"])

        quiet = self.client.get("/api/environment-memory/changes", params={"change": "went_quiet", "kind": "host"}).json()
        self.assertEqual([change["name"] for change in quiet["changes"]], ["fw01"])
        self.assertEqual(self.client.get("/api/environment-memory/changes", params={"change": "bogus"}).status_code, 400)
        self.assertEqual(self.client.get("/api/environment-memory/changes", params={"kind": "source"}).status_code, 400)

        self.assertEqual(self.client.post("/api/environment-memory/settings", json={"check_interval_hours": 0}).status_code, 400)
        saved = self.client.post("/api/environment-memory/settings", json={"scheduled_check": True, "check_interval_hours": 12})
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual((saved.json()["settings"]["scheduled_check"], saved.json()["settings"]["check_interval_hours"]), (True, 12))
        self.assertTrue(self.client.get("/api/environment-memory/settings").json()["settings"]["scheduled_check"])

        cleared = self.client.post("/api/environment-memory/clear").json()
        self.assertFalse(cleared["memory"]["has_data"])
        self.assertFalse(self.client.get("/api/environment-memory").json()["memory"]["has_data"])

    def test_check_now_runs_the_light_check_and_records_failures(self):
        now = datetime.now(timezone.utc)
        mcp = self.check_mcp(
            [{"index": "contoso_web", "sourcetype": "contoso:web", "count": "4200", "lastTime": epoch(now)},
             {"index": "contoso_web", "sourcetype": "contoso:mail", "count": "300", "lastTime": epoch(now)}],
            [{"host": "web01", "count": "4500", "lastTime": epoch(now)}],
        )
        with mock.patch.object(web_app, "environment_check_config", lambda _key: object()), \
                mock.patch.object(web_app, "execute_mcp_tool_call", mcp):
            response = self.client.post("/api/environment-memory/check")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["check"]["status"], "ok")
        self.assertEqual([call["params"]["arguments"]["query"] for call in mcp.calls], [query for _name, query in CHECK_QUERIES])
        self.assertEqual({call["params"]["arguments"]["earliest_time"] for call in mcp.calls}, {"-24h"})
        self.assertIn(("new", "sourcetype", "contoso:mail"), summary(data["memory"]["changes"]))
        self.assertEqual(data["memory"]["last_check"]["status"], "ok")

        failing = RecordingMCP(lambda _call: {"error": "Search failed", "detail": "tstats is not allowed", "status_code": 400})
        with mock.patch.object(web_app, "environment_check_config", lambda _key: object()), \
                mock.patch.object(web_app, "execute_mcp_tool_call", failing):
            data = self.client.post("/api/environment-memory/check").json()
        self.assertEqual(data["check"]["status"], "error")
        self.assertIn("tstats is not allowed", data["memory"]["last_check"]["error"])

        with mock.patch.object(web_app, "environment_check_config", lambda _key: None):
            self.assertEqual(self.client.post("/api/environment-memory/check").status_code, 400)

    def test_checks_need_the_url_and_token_that_discovery_needs(self):
        global_scope = web_app.DISCOVERY_SCOPE_GLOBAL
        self.assertTrue(self.config_manager.get().mcp.url)
        self.assertIsNone(web_app.environment_check_config(global_scope))
        self.assertFalse(self.client.get("/api/environment-memory").json()["can_check"])

        self.assertTrue(self.config_manager.update_mcp(token="contoso-token"))
        self.assertEqual(web_app.environment_check_config(web_app._mcp_workspace(self.config_manager.get())["scope_key"]).mcp.token, "contoso-token")
        self.assertTrue(self.client.get("/api/environment-memory").json()["can_check"])
        self.assertIsNone(web_app.environment_check_config(web_app.DISCOVERY_SCOPE_NO_MCP))
        self.assertIsNone(web_app.environment_check_config("mcp:contoso-missing"))

        lab_url = "https://splunk.example.test:8089/services/mcp"
        self.assertTrue(self.config_manager.save_mcp_config("contoso-lab", lab_url, "lab-token", activate=True))
        lab_scope = self.client.get("/connection-info").json()["workspace"]["scope_key"]
        lab = web_app.environment_check_config(lab_scope)
        self.assertEqual((lab.mcp.url, lab.mcp.token, lab.active_mcp_config_name), (lab_url, "lab-token", "contoso-lab"))

    def test_scheduled_checks_wait_for_the_setting_and_the_interval(self):
        mcp = self.check_mcp([{"index": "contoso_web", "sourcetype": "contoso:web", "count": "10"}], [{"host": "web01", "count": "10"}])
        with mock.patch.object(web_app, "environment_check_config", lambda _key: object()), \
                mock.patch.object(web_app, "execute_mcp_tool_call", mcp):
            self.assertEqual(asyncio.run(web_app.run_due_environment_checks()), [])
            self.assertEqual(mcp.calls, [])
            web_app.environment_settings_store.save(EnvironmentMemorySettings(scheduled_check=True, check_interval_hours=6))
            self.assertEqual(asyncio.run(web_app.run_due_environment_checks()), [web_app.DISCOVERY_SCOPE_GLOBAL])
            self.assertEqual(asyncio.run(web_app.run_due_environment_checks()), [])
            later = datetime.now(timezone.utc) + timedelta(hours=7)
            self.assertEqual(asyncio.run(web_app.run_due_environment_checks(later)), [web_app.DISCOVERY_SCOPE_GLOBAL])
        self.assertEqual(len(mcp.calls), 4)

    def test_signed_in_users_read_their_own_scope_and_only_admins_change_it(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))
        self.assertEqual(self.client.get("/api/environment-memory").status_code, 401)
        admin_password = "".join(["Environ", "Admin", "Pass", "123!"])
        self.assertEqual(self.client.post("/api/auth/login", json={"username": "admin", "password": "password"}).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/reset-password", json={
            "current_password": "password", "new_password": admin_password, "confirm_password": admin_password,
        }).status_code, 200)
        self.assertEqual(self.client.post("/api/environment-memory/settings", json={"quiet_hours": 48}).status_code, 200)
        admin_view = self.client.get("/api/environment-memory").json()
        self.assertTrue(admin_view["can_manage"])
        self.assertEqual(admin_view["settings"]["updated_by"], "admin")

        analyst_password = "".join(["Environ", "Analyst", "Pass", "123!"])
        created = self.client.post("/api/security/users", json={
            "username": "analyst1", "password": analyst_password, "role": "analyst", "require_password_reset": False,
        })
        self.assertEqual(created.status_code, 200, created.text)
        with TestClient(web_app.app) as analyst:
            self.assertEqual(analyst.post("/api/auth/login", json={"username": "analyst1", "password": analyst_password}).status_code, 200)
            view = analyst.get("/api/environment-memory").json()
            self.assertFalse(view["can_manage"])
            self.assertFalse(view["can_check"])
            self.assertEqual(view["scope"]["scope_key"], web_app.DISCOVERY_SCOPE_NO_MCP)
            self.assertFalse(view["memory"]["has_data"])
            self.assertEqual(view["settings"]["quiet_hours"], 48)
            self.assertNotIn("updated_by", view["settings"])
            for method, path in (("get", "/api/environment-memory/settings"), ("post", "/api/environment-memory/settings"),
                                 ("post", "/api/environment-memory/check"), ("post", "/api/environment-memory/clear")):
                self.assertEqual(getattr(analyst, method)(path).status_code, 403, path)


if __name__ == "__main__":
    unittest.main()
