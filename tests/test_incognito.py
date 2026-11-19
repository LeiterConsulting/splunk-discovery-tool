import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.fernet import Fernet  # noqa: E402

from incognito import (  # noqa: E402
    INCOGNITO_NOTICE,
    IncognitoBlocked,
    IncognitoLLMClient,
    IncognitoPolicy,
    IncognitoSession,
    IncognitoState,
    IncognitoStore,
    MaskSettings,
    Masker,
    StandInVault,
    clean_terms,
    provider_kind,
    resolve_state,
    session_scope,
)
from incognito.masker import spl_field_values  # noqa: E402
from incognito.seeding import blueprint_files, inventory_from_blueprint, seed_from_outputs  # noqa: E402
from incognito.vocabulary import is_free_text_term, is_public_domain, is_public_value  # noqa: E402


class _TempStore:
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.fernet = Fernet(Fernet.generate_key())
        self.store = IncognitoStore(self.root, self.fernet)

    def tearDown(self):
        self._temp.cleanup()

    def masker(self, **policy):
        if policy:
            self.store.save_policy(IncognitoPolicy(**policy))
        return self.store.masker("global")


class VocabularyTests(unittest.TestCase):
    def test_splunk_and_vendor_names_are_public(self):
        self.assertTrue(is_public_value("index", "_internal"))
        self.assertTrue(is_public_value("index", "main"))
        self.assertFalse(is_public_value("index", "contoso_prod"))
        self.assertTrue(is_public_value("app", "Splunk_TA_windows"))
        self.assertTrue(is_public_value("app", "search"))
        self.assertFalse(is_public_value("app", "contoso_billing"))
        self.assertTrue(is_public_value("user", "nobody"))

    def test_tenant_subdomains_are_not_public(self):
        self.assertTrue(is_public_domain("docs.splunk.com"))
        self.assertTrue(is_public_domain("splunkcloud.com"))
        self.assertFalse(is_public_domain("contoso.splunkcloud.com"))
        self.assertFalse(is_public_domain("contoso.okta.com"))
        self.assertFalse(is_public_domain("contoso.com"))

    def test_free_text_terms_exclude_words_and_spl(self):
        self.assertTrue(is_free_text_term("contoso_prod"))
        self.assertTrue(is_free_text_term("web01"))
        for word in ("finance", "stats", "results", "authentication", "ab", "1.2.3", "dns"):
            self.assertFalse(is_free_text_term(word), word)


class VaultTests(_TempStore, unittest.TestCase):
    def test_mapping_is_encrypted_and_persistent(self):
        vault = self.store.vault("global")
        stand_in = vault.ensure_one("host", "web01.contoso.local")
        self.assertEqual(stand_in, "host_0001")
        raw = vault.path.read_bytes()
        self.assertNotIn(b"contoso", raw)
        reopened = StandInVault(vault.path, self.fernet)
        self.assertEqual(reopened.lookup("host", "WEB01.contoso.local"), "host_0001")
        self.assertEqual(reopened.real_for("HOST_0001"), ("host", "web01.contoso.local"))

    def test_two_processes_never_reuse_a_stand_in(self):
        first = self.store.vault("global")
        second = StandInVault(first.path, self.fernet)
        a = first.ensure_one("host", "alpha-node")
        b = second.ensure_one("host", "bravo-node")
        self.assertNotEqual(a, b)
        self.assertEqual(first.real_for(b), ("host", "bravo-node"))
        self.assertEqual(second.lookup("host", "alpha-node"), a)

    def test_wrong_key_fails_closed(self):
        vault = self.store.vault("global")
        vault.ensure_one("index", "contoso_prod")
        session = IncognitoStore(self.root, Fernet(Fernet.generate_key())).open_session(
            owner="o", provider_kind="cloud", scope="global", state=IncognitoState(active=True)
        )
        with self.assertRaises(IncognitoBlocked):
            session.mask_text("index=contoso_prod")

    def test_rotate_starts_a_new_mapping(self):
        vault = self.store.vault("global")
        vault.ensure_one("host", "alpha-node")
        self.store.rotate("global")
        self.assertIsNone(vault.lookup("host", "alpha-node"))
        self.assertFalse(vault.path.exists())

    def test_addresses_keep_subnets_and_class(self):
        vault = self.store.vault("global")
        a = vault.ensure_one("ip", "10.20.30.40")
        b = vault.ensure_one("ip", "10.20.30.41")
        c = vault.ensure_one("ip", "10.20.31.40")
        public = vault.ensure_one("ip", "52.14.200.7")
        self.assertEqual(a.rsplit(".", 1)[0], b.rsplit(".", 1)[0])
        self.assertTrue(a.endswith(".40") and b.endswith(".41"))
        self.assertNotEqual(a.rsplit(".", 1)[0], c.rsplit(".", 1)[0])
        self.assertTrue(a.startswith("198.18."))
        self.assertEqual(public, "192.0.2.7")


class MaskerTests(_TempStore, unittest.TestCase):
    SAMPLE = (
        "Host web01 and dc01.corp.contoso.local sent data to index=contoso_prod from 10.20.30.40. "
        "User jdoe (jdoe@contoso.com) signed in as CONTOSO\\jdoe with SID "
        "S-1-5-21-1111111111-2222222222-3333333333-1104 from MAC 00:1A:2B:3C:4D:5E. "
        "Profile C:\\Users\\jdoe\\Desktop, /home/jdoe/.bashrc, url https://splunk.contoso.com:8000/app/search. "
        "Authorization: Bearer abcDEF1234567890ghijKLMN and device 6F9619FF-8B86-D011-B42D-00C04FC964FF. "
        "Vendor data stays: index=_internal sourcetype=WinEventLog:Security app Splunk_TA_windows https://docs.splunk.com"
    )

    def seeded(self, **policy):
        masker = self.masker(**policy)
        masker.seed({"host": ["web01", "dc01.corp.contoso.local"], "index": ["contoso_prod", "finance", "main"],
                     "user": ["jdoe"]})
        return masker

    def test_identifying_values_are_replaced(self):
        masker = self.seeded()
        masked = masker.mask_text(self.SAMPLE)
        for real in ("web01", "contoso", "jdoe", "10.20.30.40", "1111111111", "00:1A:2B", "abcDEF1234567890",
                     "6F9619FF"):
            self.assertNotIn(real.lower(), masked.lower(), real)
        for kept in ("index=_internal", "WinEventLog:Security", "Splunk_TA_windows", "https://docs.splunk.com"):
            self.assertIn(kept, masked)
        self.assertIn("-1104", masked)
        self.assertEqual(masker.find_leaks(masked), [])

    def test_round_trip_restores_the_original(self):
        masker = self.seeded()
        masked = masker.mask_text(self.SAMPLE)
        restored, unknown = masker.restore_text(masked)
        self.assertEqual(restored, self.SAMPLE)
        self.assertEqual(unknown, [])

    def test_generic_names_only_masked_as_field_values(self):
        masker = self.seeded()
        masked = masker.mask_text("Search the finance data with index=finance | stats count")
        self.assertTrue(masked.startswith("Search the finance data"))
        self.assertIn("index=idx_", masked)
        self.assertIn("stats count", masked)

    def test_sentence_punctuation_is_not_part_of_a_field_value(self):
        masker = self.seeded()
        text = "Why is index=contoso_prod? Check host=app-db-07. Also user IN (bwayne, asmith)."
        masked = masker.mask_text(text)
        self.assertRegex(masked, r"index=idx_\d{4}\? Check host=host_\d{4}\. Also")
        self.assertIsNone(masker.vault.lookup("index", "contoso_prod?"))
        self.assertIsNotNone(masker.vault.lookup("host", "app-db-07"))
        self.assertEqual(masker.restore_text(masked)[0], text)

    def test_main_index_and_public_accounts_stay(self):
        masker = self.seeded()
        masked = masker.mask_text('index=main user=nobody host="localhost"')
        self.assertEqual(masked, 'index=main user=nobody host="localhost"')

    def test_field_contexts_learn_new_names(self):
        masker = self.seeded()
        masked = masker.mask_text('{"host": "app-db-07", "user": "bwayne"} user IN ("asmith", nobody)')
        self.assertNotIn("app-db-07", masked)
        self.assertNotIn("bwayne", masked)
        self.assertNotIn("asmith", masked)
        self.assertIn("nobody", masked)
        later = masker.mask_text("Investigate app-db-07 now")
        self.assertNotIn("app-db-07", later)

    def test_always_mask_and_keep_visible(self):
        masker = self.seeded(always_mask_terms=["Contoso"], keep_visible_terms=["web01"])
        masked = masker.mask_text("ContosoCorp sourcetype=contoso:billing on web01")
        self.assertNotIn("contoso", masked.lower())
        self.assertIn("web01", masked)
        restored, _ = masker.restore_text(masked)
        self.assertEqual(restored.lower(), "contosocorp sourcetype=contoso:billing on web01")

    def test_stand_ins_are_not_corrupted_by_terms(self):
        masker = self.masker(always_mask_terms=["example", "host"])
        masker.seed({"index": ["contoso_prod"]})
        masked = masker.mask_text("jdoe@contoso.com index=contoso_prod")
        self.assertIn("@example.com", masked)
        self.assertRegex(masked, r"idx_\d{4}")

    def test_restore_tolerates_formatting_and_flags_unknown(self):
        masker = self.seeded()
        masker.mask_text("host web01 index=contoso_prod")
        restored, unknown = masker.restore_text("HOST_0001, idx\\_0001, host-0001 and host_0099")
        self.assertEqual(restored, "web01, contoso_prod, web01 and host_0099")
        self.assertEqual(unknown, ["host_0099"])

    def test_restore_quotes_names_with_spaces_in_spl(self):
        masker = self.masker()
        masker.seed({"host": ["Front Desk PC"], "search": ["Failed logins by host"]})
        masked = masker.mask_text('host="Front Desk PC"')
        restored, _ = masker.restore_text(masked.replace('"', "") + " | savedsearch search_0001")
        self.assertEqual(restored, 'host="Front Desk PC" | savedsearch "Failed logins by host"')

    def test_host_names_that_spell_out_an_address_are_masked(self):
        self.assertTrue(is_free_text_term("10-20-3-100"))
        self.assertFalse(is_free_text_term("1-2-3"))
        self.assertFalse(is_free_text_term("300-20-3-100"))
        masker = self.masker()
        masker.seed({"host": ["10-20-3-100"]})
        text = 'host=10-20-3-100 | stats count. Host 10-20-3-100 stopped; 10-20-3-1000 is a ticket.'
        masked = masker.mask_text(text)
        self.assertNotIn("10-20-3-100 ", masked)
        self.assertNotIn("=10-20-3-100", masked)
        self.assertIn("10-20-3-1000", masked)
        self.assertEqual(masker.find_leaks(masked), [])
        self.assertEqual(masker.restore_text(masked)[0], text)
        rows = masker.mask_rows([{"host": "10-20-30-40", "count": 3}])
        self.assertRegex(rows[0]["host"], r"^host_\d{4}$")
        self.assertEqual(rows[0]["count"], 3)
    def test_rows_drop_raw_events_and_use_tool_hints(self):
        masker = self.masker()
        rows = [{"title": "contoso_prod", "currentDBSizeMB": 10, "_raw": "web01 secret"}]
        masked = masker.mask_rows(rows, hint="index", splunk_apps=True)
        self.assertNotIn("_raw", masked[0])
        self.assertRegex(masked[0]["title"], r"idx_\d{4}")
        events = masker.mask_rows([{"app": "ms-teams", "dest": "files-srv-3", "src": "10.1.2.3", "count": 4}])
        self.assertEqual(events[0]["app"], "ms-teams")
        self.assertRegex(events[0]["dest"], r"host_\d{4}")
        self.assertTrue(events[0]["src"].startswith("198.18."))
        self.assertEqual(events[0]["count"], 4)

    def test_names_from_identity_fields_are_masked_in_earlier_free_text(self):
        masker = self.masker()
        rows = [{"message": "Lost contact with ops-relay-4 at noon", "count": 2}, {"host": "ops-relay-4"}]
        masked = masker.mask_rows(rows)
        self.assertNotIn("ops-relay-4", json.dumps(masked))
        self.assertEqual(masked[0]["message"], f"Lost contact with {masked[1]['host']} at noon")

    def test_vendor_knowledge_objects_keep_their_names(self):
        masker = self.masker()
        rows = [{"title": "Authentication", "app": "Splunk_SA_CIM"}, {"title": "contoso_lookup", "app": "contoso_app"}]
        masked = masker.mask_rows(rows, hint="object", splunk_apps=True)
        self.assertEqual(masked[0]["title"], "Authentication")
        self.assertRegex(masked[1]["title"], r"object_\d{4}")
        self.assertRegex(masked[1]["app"], r"app_\d{4}")

    def test_structures_use_parent_keys(self):
        masker = self.masker()
        data = {"indexes": [{"name": "contoso_prod", "hosts": ["web01"]}], "top_sourcetypes": ["linux_secure"]}
        masked = masker.mask_structure(data)
        self.assertRegex(masked["indexes"][0]["name"], r"idx_\d{4}")
        self.assertRegex(masked["indexes"][0]["hosts"][0], r"host_\d{4}")
        self.assertEqual(masked["top_sourcetypes"], ["linux_secure"])
        restored, unknown = masker.restore_structure(masked)
        self.assertEqual(restored, data)
        self.assertEqual(unknown, [])

    def test_json_text_keys_and_labels_are_not_taken_for_names(self):
        masker = self.masker()
        text = ('{"indexes": [{"name": "_internal"}, {"name": "contoso_prod", "size_mb": 5}], '
                '"risk": {"domain": "Data Quality", "index": "two words"}, "spl": "index=fin host=ab | stats count"}')
        masked = masker.mask_text(text)
        self.assertIn('{"name": "_internal"}', masked)
        self.assertRegex(masked, r'\{"name": "idx_\d{4}", "size_mb": 5\}')
        self.assertIn('"domain": "Data Quality", "index": "two words"', masked)
        self.assertRegex(masked, r'"spl": "index=idx_\d{4} host=host_\d{4} \| stats count"')
        self.assertIsNone(masker.vault.lookup("index", "name"))
        self.assertIsNone(masker.vault.lookup("domain", "Data Quality"))
        self.assertEqual(masker.restore_text(masked)[0], text)

    def test_spl_inside_json_strings_reads_escaped_quotes(self):
        masker = self.masker()
        masker.seed({"user": ["jdoe"], "domain": ["CONTOSO"]})
        record = {"search": 'search index=main user IN ("admin","splunk-system-user","jdoe") '
                            'src_user="CONTOSO\\jdoe" | stats count by user'}
        text = json.dumps({"finding": record})
        masked = masker.mask_text(text)
        self.assertEqual(masker.find_leaks(masked), [])
        self.assertNotIn("jdoe", masked)
        self.assertIn('\\"admin\\",\\"splunk-system-user\\"', masked)
        self.assertRegex(masked, r'user IN \(\\"admin\\",\\"splunk-system-user\\",\\"user_\d{4}\\"\)')
        self.assertIsNone(masker.vault.lookup("user", "admin\\"))
        self.assertEqual(json.loads(masker.restore_reply(masked)[0]), {"finding": record})

        session = IncognitoSession(IncognitoState(True), masker, feature="export")
        shared = session.mask_export({"finding": record, "owner": "jdoe"})
        self.assertNotIn("incognito_note", shared)
        self.assertNotIn("jdoe", json.dumps(shared))
        self.assertIn('"admin","splunk-system-user"', shared["finding"]["search"])

    def test_spl_values_in_json_strings_are_learned_without_quotes(self):
        escaped = json.dumps('index=main user IN ("contoso_svc", "admin") host="ops-relay-4"')[1:-1]
        found = spl_field_values(escaped)
        self.assertIn(("host", "ops-relay-4"), found)
        self.assertIn(("user", "contoso_svc"), found)
        self.assertFalse([value for _namespace, value in found if "\\" in value or '"' in value])

    def test_plain_prose_and_spl_are_untouched(self):
        masker = self.masker()
        text = ("Use | tstats count where index=* by sourcetype, then timechart span=1h. Version 9.2.1, "
                "file props.conf, 12:30:45, hash d41d8cd98f00b204e9800998ecf8427e, ASP.NET and node.js.")
        self.assertEqual(masker.mask_text(text), text)


class SessionTests(_TempStore, unittest.TestCase):
    def session(self, **state):
        return self.store.open_session(owner="owner-a", provider_kind="cloud", scope="global",
                                       state=IncognitoState(active=True, **state))

    def test_request_gets_notice_and_ledger_records_masked_text(self):
        session = self.session()
        session.masker.seed({"host": ["web01"]})
        prompt, messages = session.mask_request(messages=[{"role": "system", "content": "You help."},
                                                          {"role": "user", "content": "Why is web01 slow?"}])
        self.assertIsNone(prompt)
        self.assertIn(INCOGNITO_NOTICE, messages[0]["content"])
        self.assertNotIn("web01", json.dumps(messages))
        session.record(messages=messages, reply="host_0001 is busy")
        session.record(messages=messages + [{"role": "user", "content": "more"}], reply="ok")
        self.assertEqual(session.calls[1]["earlier_messages"], 2)
        self.assertEqual(session.describe()["masked"], {"host": 1})
        self.assertNotIn("web01", json.dumps(session.describe()))

    def test_later_messages_can_name_things_earlier_ones_mention(self):
        session = self.session()
        _prompt, messages = session.mask_request(messages=[
            {"role": "user", "content": "Is ops-relay-4 healthy?"},
            {"role": "user", "content": json.dumps({"results": [{"host": "ops-relay-4", "count": 3}]})},
        ])
        self.assertNotIn("ops-relay-4", json.dumps(messages))

    def test_leak_blocks_the_request(self):
        session = self.session()
        session.masker.find_leaks = lambda _text: [("host", "web01")]
        with self.assertRaises(IncognitoBlocked) as raised:
            session.mask_text("web01")
        self.assertIn("host", str(raised.exception))
        self.assertIsNotNone(session.blocked)

    def test_inactive_session_does_nothing(self):
        session = self.store.open_session(owner="o", provider_kind="local", scope="global")
        self.assertFalse(session.active)

    def test_ledger_is_only_readable_by_its_owner(self):
        session = self.session()
        session.record(prompt="masked prompt", reply="reply")
        ledger_id = self.store.save_ledger(session)
        self.assertIsNotNone(self.store.load_ledger("owner-a", ledger_id))
        self.assertIsNone(self.store.load_ledger("owner-b", ledger_id))
        self.assertIsNone(self.store.load_ledger("owner-a", "../policy"))


class PolicyTests(_TempStore, unittest.TestCase):
    def test_policy_round_trip_and_terms_cleanup(self):
        saved = self.store.save_policy(IncognitoPolicy(force_for_cloud=True, always_mask_terms=["Contoso", " contoso ", "x"]),
                                       updated_by="admin")
        self.assertEqual(saved.always_mask_terms, ["Contoso"])
        loaded = self.store.load_policy()
        self.assertTrue(loaded.force_for_cloud)
        self.assertEqual(loaded.updated_by, "admin")
        self.assertNotIn(b"Contoso", (self.root / "policy.enc").read_bytes())
        self.assertEqual(clean_terms(["a", "ab", "AB"]), ["ab"])

    def test_state_resolution(self):
        forced = IncognitoPolicy(force_for_cloud=True)
        self.assertEqual(resolve_state(forced, False, "cloud"), IncognitoState(True, True, "required_for_cloud", "cloud"))
        self.assertEqual(resolve_state(forced, False, "local").active, False)
        self.assertEqual(resolve_state(IncognitoPolicy(default_on=True), None, "local").reason, "default")
        self.assertEqual(resolve_state(IncognitoPolicy(default_on=True), False, "cloud").active, False)
        self.assertEqual(resolve_state(IncognitoPolicy(), True, "local").reason, "user_choice")

    def test_preferences_are_per_owner(self):
        self.store.set_preference("owner-a", True)
        self.assertTrue(self.store.get_preference("owner-a"))
        self.assertIsNone(self.store.get_preference("owner-b"))
        self.store.set_preference("owner-a", None)
        self.assertIsNone(self.store.get_preference("owner-a"))

    def test_unreadable_policy_fails_closed(self):
        (self.root / "policy.enc").write_bytes(b"not encrypted")
        policy = self.store.load_policy()
        self.assertTrue(policy.force_for_cloud and policy.default_on and policy.unreadable)

    def test_provider_kind(self):
        self.assertEqual(provider_kind("openai", None), "cloud")
        self.assertEqual(provider_kind("anthropic", None), "cloud")
        self.assertEqual(provider_kind("azure", "http://10.0.0.5"), "cloud")
        self.assertEqual(provider_kind("ollama", None), "local")
        self.assertEqual(provider_kind("ollama", "http://192.168.1.50:11434"), "local")
        self.assertEqual(provider_kind("ollama", "https://ollama.com"), "cloud")
        self.assertEqual(provider_kind("custom", "http://localhost:8000/v1"), "local")
        self.assertEqual(provider_kind("custom", "https://api.together.xyz/v1"), "cloud")
        self.assertEqual(provider_kind("custom", None), "cloud")


class RecordingModel:
    def __init__(self, reply="host_0001 looks fine", analysis=None):
        self.reply = reply
        self.analysis = analysis or {"recommendations": [{"title": "Watch idx_0001"}]}
        self.calls = []
        self.model = "recording"

    async def generate_response(self, prompt=None, messages=None, max_tokens=1000, temperature=0.7):
        self.calls.append({"prompt": prompt, "messages": messages, "max_tokens": max_tokens})
        return self.reply

    async def analyze_data(self, data, analysis_type):
        self.calls.append({"data": data, "type": analysis_type})
        return self.analysis


class ClientTests(_TempStore, unittest.TestCase):
    def test_passthrough_without_incognito(self):
        inner = RecordingModel(reply="plain")
        client = IncognitoLLMClient(inner, lambda: None)
        reply = asyncio.run(client.generate_response("about web01", None, 500))
        self.assertEqual(reply, "plain")
        self.assertEqual(inner.calls[0], {"prompt": "about web01", "messages": None, "max_tokens": 500})
        self.assertEqual(client.model, "recording")

    def test_masks_requests_and_restores_replies(self):
        inner = RecordingModel()
        session = self.store.open_session(owner="o", provider_kind="cloud", scope="global",
                                          state=IncognitoState(active=True))
        session.masker.seed({"host": ["web01"], "index": ["contoso_prod"]})
        client = IncognitoLLMClient(inner, lambda: session)
        reply = asyncio.run(client.generate_response(messages=[{"role": "user", "content": "Is web01 healthy?"}]))
        self.assertEqual(reply, "web01 looks fine")
        sent = json.dumps(inner.calls[0]["messages"])
        self.assertNotIn("web01", sent)
        self.assertIn("host_0001", sent)
        result = asyncio.run(client.analyze_data({"indexes": ["contoso_prod"]}, "recommendations"))
        self.assertEqual(result, {"recommendations": [{"title": "Watch contoso_prod"}]})
        self.assertNotIn("contoso_prod", json.dumps(inner.calls[1]["data"]))
        self.assertIn("incognito_note", inner.calls[1]["data"])
        self.assertEqual(len(session.calls), 2)

    def test_context_variable_selects_the_session(self):
        from incognito import current_session

        inner = RecordingModel(reply="ok")
        client = IncognitoLLMClient(inner, current_session)
        session = IncognitoSession(IncognitoState(active=True), self.store.masker("global"))
        with session_scope(session):
            asyncio.run(client.generate_response("hello"))
        self.assertTrue(inner.calls[0]["prompt"].startswith("Privacy note"))
        asyncio.run(client.generate_response("hello"))
        self.assertEqual(inner.calls[1]["prompt"], "hello")

    def test_blocked_request_never_reaches_the_model(self):
        inner = RecordingModel()
        session = IncognitoSession(IncognitoState(active=True), None, error="vault unreadable")
        client = IncognitoLLMClient(inner, lambda: session)
        with self.assertRaises(IncognitoBlocked):
            asyncio.run(client.generate_response("web01"))
        self.assertEqual(inner.calls, [])


def contoso_blueprint(extra_hosts=()):
    return {
        "discovered_inventory": {
            "hosts": ["web01.contoso.local", "dc01", *extra_hosts],
            "indexes": ["contoso_prod", "main", "_internal"],
            "kv_collections": ["contoso_assets"],
        },
        "finding_ledger": [
            {"kind": "user", "data": {"username": "jdoe", "realname": "Jane Doe", "email": "jdoe@contoso.com",
                                      "roles": "admin;contoso_analyst", "defaultApp": "contoso_portal"}},
            {"kind": "knowledge_object", "data": {"ko_type": "saved_searches", "name": "Contoso VPN failures",
                                                  "app": "contoso_portal"}},
            {"kind": "knowledge_object", "data": {"ko_type": "macros", "name": "contoso_filter", "app": "contoso_portal"}},
            {"kind": "knowledge_object", "data": {"ko_type": "datamodels", "name": "Authentication", "app": "Splunk_SA_CIM"}},
            {"kind": "index_detail", "data": {"name": "contoso_web", "splunk_server": "idx01.contoso.local"}},
            {"kind": "kv_collection", "data": {"collection": "contoso_assets"}},
            {"kind": "unrelated", "data": "not a mapping"},
        ],
        "environment_profile": {"installed_apps": {"items": [
            {"name": "contoso_portal", "label": "Contoso Portal", "builtin": False},
            {"name": "search", "label": "Search & Reporting", "builtin": True},
            {"name": "Splunk_TA_windows", "label": "Splunk Add-on for Microsoft Windows", "builtin": False},
        ]}},
        "overview": {"authenticated_user": "svc_splunk", "authenticated_user_roles": ["admin", "contoso_ops"]},
    }


class SeedingTests(_TempStore, unittest.TestCase):
    def test_inventory_lists_own_names_and_skips_vendor_content(self):
        found = inventory_from_blueprint(contoso_blueprint())
        self.assertEqual(found["host"], ["web01.contoso.local", "dc01", "idx01.contoso.local"])
        self.assertIn("contoso_web", found["index"])
        self.assertEqual(found["kv"], ["contoso_assets"])
        self.assertEqual(found["user"], ["jdoe", "Jane Doe", "svc_splunk"])
        self.assertEqual(found["email"], ["jdoe@contoso.com"])
        self.assertEqual(found["role"], ["admin", "contoso_analyst", "contoso_ops"])
        self.assertEqual(found["search"], ["Contoso VPN failures"])
        self.assertEqual(found["object"], ["contoso_filter"])
        self.assertEqual(found["app"], ["contoso_portal", "Splunk_SA_CIM", "Contoso Portal"])
        self.assertEqual(inventory_from_blueprint(["not", "a", "blueprint"])["host"], [])

    def test_names_in_saved_search_spl_are_learned(self):
        spl = 'index=contoso_vpn host IN (vpn-gw-1, "vpn gw 2") user=jdoe src=10.20.30.40 dest=$dest$ host=web* | stats count'
        found = inventory_from_blueprint({"finding_ledger": [
            {"kind": "knowledge_object", "data": {"ko_type": "saved_searches", "name": "VPN failures",
                                                  "app": "contoso_portal", "search": spl}},
            {"kind": "knowledge_object", "data": {"ko_type": "macros", "name": "contoso_filter", "app": "contoso_portal",
                                                  "definition": "index=contoso_web sourcetype=access_combined"}},
            {"kind": "knowledge_object", "data": {"ko_type": "datamodels", "name": "Authentication",
                                                  "app": "Splunk_SA_CIM", "search": "index=vendor_idx user=vendor_user"}},
        ]})
        self.assertEqual(found["index"], ["contoso_vpn", "contoso_web"])
        self.assertEqual(found["host"], ["10.20.30.40", "vpn-gw-1", "vpn gw 2"])
        self.assertEqual(found["user"], ["jdoe"])
        masker = self.masker()
        masker.seed(found)
        masked = masker.mask_text("Did jdoe use vpn-gw-1 or 10.20.30.40 yesterday?")
        for real in ("jdoe", "vpn-gw-1", "10.20.30.40"):
            self.assertNotIn(real, masked)

    def test_seeded_names_are_masked_in_free_text(self):
        masker = self.masker()
        masker.seed(inventory_from_blueprint(contoso_blueprint()))
        masked = masker.mask_text("Why did dc01 stop? Check Contoso VPN failures in contoso_portal, then index=main as admin.")
        for real in ("dc01", "Contoso VPN failures", "contoso_portal"):
            self.assertNotIn(real, masked)
        self.assertIn("index=main", masked)
        self.assertIn("as admin", masked)
        self.assertEqual(masker.vault.lookup("app", "Splunk_SA_CIM"), None)
        self.assertEqual(masker.vault.lookup("role", "admin"), None)

    def test_seeding_reads_root_and_scoped_blueprints_once(self):
        output = self.root / "output"
        scoped = output / "scopes" / "scope_a"
        scoped.mkdir(parents=True)
        (output / "v2_intelligence_blueprint_20260101_000000.json").write_text(json.dumps(contoso_blueprint()))
        (scoped / "v2_intelligence_blueprint_20260102_000000.json").write_text(
            json.dumps({"discovered_inventory": {"hosts": ["branch-fw-02"]}})
        )
        (output / "notes.json").write_text("{}")
        self.assertEqual(len(blueprint_files(output)), 2)
        masker = self.masker()
        self.assertGreater(seed_from_outputs(masker, output), 0)
        self.assertIsNotNone(masker.vault.lookup("host", "branch-fw-02"))
        self.assertEqual(seed_from_outputs(masker, output), 0)
        (output / "v2_intelligence_blueprint_20260101_000000.json").write_text(
            json.dumps(contoso_blueprint(extra_hosts=["new-host-9"]))
        )
        self.assertGreater(seed_from_outputs(masker, output), 0)
        self.assertIsNotNone(masker.vault.lookup("host", "new-host-9"))

    def test_rotating_stand_ins_seeds_again(self):
        output = self.root / "output"
        output.mkdir()
        (output / "v2_intelligence_blueprint_20260101_000000.json").write_text(json.dumps(contoso_blueprint()))
        seed_from_outputs(self.masker(), output)
        self.store.rotate("global")
        fresh = self.store.masker("global")
        self.assertIsNone(fresh.vault.lookup("host", "dc01"))
        self.assertGreater(seed_from_outputs(fresh, output), 0)
        self.assertIsNotNone(fresh.vault.lookup("host", "dc01"))


class RestoreReplyTests(_TempStore, unittest.TestCase):
    def session(self):
        return self.store.open_session(owner="owner-a", provider_kind="cloud", scope="global",
                                       state=IncognitoState(active=True))

    def test_tool_call_json_stays_valid_after_restoring(self):
        masker = self.masker()
        masker.seed({"search": ['Failed "VPN" logins']})
        stand_in = masker.vault.lookup("search", 'Failed "VPN" logins')
        reply = ('Running it now.\n<TOOL_CALL>{"tool": "splunk_run_query", "args": {"query": "| savedsearch '
                 + stand_in + '"}}</TOOL_CALL>')
        plain, _ = masker.restore_text(reply)
        with self.assertRaises(ValueError):
            json.loads(plain.split("<TOOL_CALL>")[1].split("</TOOL_CALL>")[0])
        restored, unknown = masker.restore_reply(reply)
        self.assertEqual(unknown, [])
        self.assertTrue(restored.startswith("Running it now.\n<TOOL_CALL>"))
        call = json.loads(restored.split("<TOOL_CALL>")[1].split("</TOOL_CALL>")[0])
        self.assertEqual(call["args"]["query"], '| savedsearch "Failed \\"VPN\\" logins"')

    def test_replies_without_stand_ins_are_unchanged(self):
        masker = self.masker()
        reply = 'Use {"query": "index=main | stats count"} and {not json}.'
        self.assertEqual(masker.restore_reply(reply), (reply, []))

    def test_session_restores_only_stand_ins_the_model_saw(self):
        session = self.session()
        session.masker.seed({"host": ["web01", "db01"]})
        session.mask_text("Is web01 up?")
        shown = session.masker.vault.lookup("host", "web01")
        hidden = session.masker.vault.lookup("host", "db01")
        restored = session.restore_text(f"{shown} is up, unlike {hidden} and host_0999.")
        self.assertEqual(restored, f"web01 is up, unlike {hidden} and host_0999.")
        self.assertEqual(session.unknown, [hidden, "host_0999"])
        self.assertEqual(session.unknown_in({"query": f"host={hidden} OR host={shown}"}), [hidden])
        self.assertEqual(session.restore_data({"hosts": [shown, hidden]}), {"hosts": ["web01", hidden]})

    def test_public_addresses_in_replies_are_left_alone(self):
        session = self.session()
        masked = session.mask_text("Traffic from 10.20.30.40")
        stand_in = masked.rsplit(" ", 1)[1]
        restored = session.restore_text(f"{stand_in} talked to 8.8.8.8 and 172.16.5.4")
        self.assertEqual(restored, "10.20.30.40 talked to 8.8.8.8 and 172.16.5.4")
        self.assertEqual(session.unknown, [])


class MessagesFirstModel:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    async def generate_response(self, messages=None, max_tokens=None, temperature=None, prompt=None):
        self.calls.append({"messages": messages, "max_tokens": max_tokens, "prompt": prompt})
        return self.reply


class ClientForwardingTests(_TempStore, unittest.TestCase):
    def test_keywords_reach_clients_with_other_parameter_orders(self):
        inner = MessagesFirstModel("host_0001 is fine")
        session = self.store.open_session(owner="o", provider_kind="cloud", scope="global",
                                          state=IncognitoState(active=True))
        session.masker.seed({"host": ["web01"]})
        client = IncognitoLLMClient(inner, lambda: session)
        reply = asyncio.run(client.generate_response(messages=[{"role": "user", "content": "web01?"}], max_tokens=50))
        self.assertEqual(reply, "web01 is fine")
        self.assertIsNone(inner.calls[0]["prompt"])
        self.assertEqual(inner.calls[0]["max_tokens"], 50)
        self.assertIn("host_0001?", inner.calls[0]["messages"][-1]["content"])
        asyncio.run(IncognitoLLMClient(inner, lambda: None).generate_response(prompt="plain", max_tokens=5))
        self.assertEqual(inner.calls[1], {"messages": None, "max_tokens": 5, "prompt": "plain"})

    def test_preamble_flag_survives_restoring(self):
        from llm.factory import PreambleReply

        inner = MessagesFirstModel(PreambleReply("Checking host_0001 next."))
        session = self.store.open_session(owner="o", provider_kind="cloud", scope="global",
                                          state=IncognitoState(active=True))
        session.masker.seed({"host": ["web01"]})
        session.mask_text("web01")
        reply = asyncio.run(IncognitoLLMClient(inner, lambda: session).generate_response(prompt="go"))
        self.assertIsInstance(reply, PreambleReply)
        self.assertTrue(reply.ends_on_preamble)
        self.assertEqual(str(reply), "Checking web01 next.")

class SettingsTests(unittest.TestCase):
    def test_mask_settings_from_terms(self):
        settings = MaskSettings.from_terms(["Contoso", "ab", "contoso corp"], ["Web01"])
        self.assertEqual(settings.always_mask, ("contoso corp", "contoso"))
        self.assertEqual(settings.keep_visible, frozenset({"web01"}))
        self.assertIsInstance(Masker, type)


if __name__ == "__main__":
    unittest.main()
