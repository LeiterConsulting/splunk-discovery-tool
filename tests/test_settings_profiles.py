import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from capabilities import CapabilityManager
from config_manager import MASKED_SECRET, ConfigManager, MCPCredential
from security_manager import SecurityManager
import main as app_main
import web_app


def _profile_path(name: str, suffix: str = "") -> str:
    return f"/api/mcp-configs/{quote(name, safe='')}{suffix}"


class _RecordingAsyncClient:
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        _RecordingAsyncClient.calls.append({"url": url, "headers": dict(headers or {})})
        return type("Response", (), {"status_code": 200})()


class ConfigManagerProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.temp_path = Path(self.temp_dir.name)
        self.original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.manager = ConfigManager(str(self.temp_path / "config.encrypted"))

    def tearDown(self):
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def _reload(self):
        return ConfigManager(str(self.temp_path / "config.encrypted"))

    def test_masked_or_blank_token_keeps_saved_profile_token(self):
        self.assertTrue(self.manager.save_mcp_config("prod", "https://prod.example.com/mcp", "prod-token"))
        self.assertTrue(self.manager.save_mcp_config("prod", "https://prod.example.com/mcp", MASKED_SECRET, description="edited"))
        self.assertTrue(self.manager.save_mcp_config("prod", "https://prod.example.com/mcp", ""))

        reloaded = self._reload().get_mcp_config("prod")
        self.assertEqual(reloaded.token, "prod-token")

    def test_new_profile_inherits_active_token_only_for_the_same_server(self):
        self.assertTrue(self.manager.update_mcp(url="https://prod.example.com/mcp", token="active-token"))

        self.assertTrue(self.manager.save_mcp_config("prod-copy", "https://prod.example.com/mcp/", MASKED_SECRET))
        self.assertTrue(self.manager.save_mcp_config("dev", "https://dev.example.com/mcp", MASKED_SECRET))

        reloaded = self._reload()
        self.assertEqual(reloaded.get_mcp_config("prod-copy").token, "active-token")
        self.assertEqual(reloaded.get_mcp_config("dev").token, "")

    def test_activate_applies_profile_to_active_connection(self):
        self.assertTrue(self.manager.save_mcp_config("lab", "https://lab.example.com/mcp", "lab-token", verify_ssl=True, activate=True))

        config = self._reload().get()
        self.assertEqual(config.active_mcp_config_name, "lab")
        self.assertEqual(config.mcp.url, "https://lab.example.com/mcp")
        self.assertEqual(config.mcp.token, "lab-token")
        self.assertTrue(config.mcp.verify_ssl)

    def test_loading_profile_saved_with_mask_does_not_send_mask_as_token(self):
        self.manager.get().saved_mcp_configs["broken"] = MCPCredential(name="broken", url="https://b.example.com/mcp", token=MASKED_SECRET)
        self.assertTrue(self.manager.load_mcp_config("broken"))

        config = self._reload().get()
        self.assertEqual(config.mcp.token, "")
        self.assertEqual(self.manager.export_safe()["saved_mcp_configs"]["broken"]["token"], "")

    def test_update_mcp_and_llm_ignore_masked_secrets(self):
        self.assertTrue(self.manager.update_mcp(token="real-token"))
        self.assertTrue(self.manager.update_llm(api_key="real-key"))
        self.assertTrue(self.manager.update_mcp(token=MASKED_SECRET, url="https://new.example.com/mcp"))
        self.assertTrue(self.manager.update_llm(api_key=MASKED_SECRET, model="gpt-4.1-mini"))

        config = self._reload().get()
        self.assertEqual(config.mcp.token, "real-token")
        self.assertEqual(config.mcp.url, "https://new.example.com/mcp")
        self.assertEqual(config.llm.api_key, "real-key")
        self.assertEqual(config.llm.model, "gpt-4.1-mini")

    def test_credential_update_without_key_keeps_saved_key(self):
        self.assertTrue(self.manager.save_credential("openai", "openai", "sk-saved", "gpt-4.1-mini"))
        self.assertTrue(self.manager.save_credential("openai", "openai", "", "gpt-4.1"))

        credential = self._reload().get_credential("openai")
        self.assertEqual(credential.api_key, "sk-saved")
        self.assertEqual(credential.model, "gpt-4.1")

    def test_new_credential_inherits_active_key_only_for_same_provider_and_endpoint(self):
        self.assertTrue(self.manager.update_llm(provider="openai", api_key="sk-active", endpoint_url=None))

        self.assertTrue(self.manager.save_credential("openai-copy", "openai", MASKED_SECRET, "gpt-4.1"))
        self.assertTrue(self.manager.save_credential("local", "custom", "", "llama3.1:8b", endpoint_url="http://localhost:11434/v1"))

        reloaded = self._reload()
        self.assertEqual(reloaded.get_credential("openai-copy").api_key, "sk-active")
        self.assertEqual(reloaded.get_credential("local").api_key, "")

    def test_save_failure_records_reason(self):
        self.manager.config_path = self.temp_path / "missing-dir" / "config.encrypted"

        self.assertFalse(self.manager.save_mcp_config("prod", "https://prod.example.com/mcp", "token"))
        self.assertIn("FileNotFoundError", self.manager.last_save_error or "")

    def test_save_leaves_no_temp_files(self):
        self.assertTrue(self.manager.save_mcp_config("prod", "https://prod.example.com/mcp", "token"))

        leftovers = [path.name for path in self.temp_path.iterdir() if path.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_unreadable_config_is_preserved_before_defaults_are_saved(self):
        config_path = self.temp_path / "config.encrypted"
        config_path.write_bytes(b"not-a-fernet-token")

        manager = ConfigManager(str(config_path))
        self.assertTrue(manager.save_mcp_config("prod", "https://prod.example.com/mcp", "token"))

        backups = list(self.temp_path.glob("config.encrypted.corrupted-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"not-a-fernet-token")


class SettingsProfileApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.temp_path = Path(self.temp_dir.name)
        self.original_cwd = Path.cwd()
        os.chdir(self.temp_path)

        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.security_manager = SecurityManager(str(self.temp_path / "security.db"))
        self.original_config_manager = web_app.config_manager
        self.original_capability_manager = web_app.capability_manager
        self.original_security_manager = web_app.security_manager
        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = self.security_manager
        self.client = TestClient(web_app.app)
        _RecordingAsyncClient.calls = []

    def tearDown(self):
        self.client.close()
        web_app.config_manager = self.original_config_manager
        web_app.capability_manager = self.original_capability_manager
        web_app.security_manager = self.original_security_manager
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def _save(self, **payload):
        return self.client.post("/api/mcp-configs", json=payload)

    def test_first_profile_on_fresh_install_becomes_active(self):
        response = self._save(name="Prod Splunk", url="https://prod.example.com/mcp", token="prod-token")

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["activated"])
        self.assertEqual(body["config"]["active_mcp_config_name"], "Prod Splunk")
        self.assertEqual(body["config"]["mcp"]["token"], MASKED_SECRET)
        self.assertEqual(self.config_manager.get().mcp.token, "prod-token")

    def test_updating_active_profile_without_token_keeps_token_and_updates_active_connection(self):
        self._save(name="Prod Splunk", url="https://prod.example.com/mcp", token="prod-token")

        response = self._save(name="Prod Splunk", url="https://prod2.example.com/mcp", token=MASKED_SECRET, verify_ssl=True)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["activated"])
        config = self.config_manager.get()
        self.assertEqual(config.saved_mcp_configs["Prod Splunk"].token, "prod-token")
        self.assertEqual(config.mcp.url, "https://prod2.example.com/mcp")
        self.assertEqual(config.mcp.token, "prod-token")
        self.assertTrue(config.mcp.verify_ssl)

    def test_additional_profiles_do_not_replace_the_active_connection(self):
        self._save(name="Prod Splunk", url="https://prod.example.com/mcp", token="prod-token")

        copy_response = self._save(name="Prod Copy", url="https://prod.example.com/mcp", token="")
        dev_response = self._save(name="Dev", url="https://dev.example.com/mcp", token="")

        self.assertFalse(copy_response.json()["activated"])
        self.assertTrue(copy_response.json()["token_configured"])
        self.assertFalse(dev_response.json()["token_configured"])
        config = self.config_manager.get()
        self.assertEqual(config.active_mcp_config_name, "Prod Splunk")
        self.assertEqual(config.saved_mcp_configs["Prod Copy"].token, "prod-token")
        self.assertEqual(config.saved_mcp_configs["Dev"].token, "")
        listed = self.client.get("/api/mcp-configs").json()
        self.assertEqual(listed["Dev"]["token"], "")
        self.assertEqual(listed["Prod Copy"]["token"], MASKED_SECRET)

    def test_profile_names_with_special_characters_round_trip(self):
        for name in ("Chris's Lab", "Lab/Dev #1", "Prod ? 50%", "test"):
            with self.subTest(name=name):
                save = self._save(name=name, url="https://lab.example.com/mcp", token=f"token-{len(name)}", activate=False)
                self.assertEqual(save.status_code, 200, save.text)

                fetched = self.client.get(_profile_path(name))
                self.assertEqual(fetched.status_code, 200, fetched.text)
                self.assertEqual(fetched.json()["name"], name)

                loaded = self.client.post(_profile_path(name, "/load"))
                self.assertEqual(loaded.status_code, 200, loaded.text)
                self.assertEqual(loaded.json()["config"]["active_mcp_config_name"], name)

                with patch("httpx.AsyncClient", _RecordingAsyncClient):
                    tested = self.client.post(_profile_path(name, "/test"))
                self.assertEqual(tested.json()["status"], "success", tested.text)

                deleted = self.client.delete(_profile_path(name))
                self.assertEqual(deleted.status_code, 200, deleted.text)
                self.assertIsNone(self.config_manager.get_mcp_config(name))

    def test_connection_test_resolves_masked_token_from_profile(self):
        self._save(name="Prod Splunk", url="https://prod.example.com/mcp", token="prod-token")

        with patch("httpx.AsyncClient", _RecordingAsyncClient):
            response = self.client.post(
                "/api/mcp-configs/test",
                json={"url": "https://prod.example.com/mcp", "token": MASKED_SECRET, "verify_ssl": False, "name": "Prod Splunk"},
            )

        self.assertEqual(response.json()["status"], "success", response.text)
        self.assertEqual(_RecordingAsyncClient.calls[-1]["headers"].get("Authorization"), "Bearer prod-token")

    def test_saved_profile_without_token_reports_missing_token_instead_of_calling_server(self):
        self._save(name="Dev", url="https://dev.example.com/mcp", token="", activate=False)

        with patch("httpx.AsyncClient", _RecordingAsyncClient):
            response = self.client.post(_profile_path("Dev", "/test"))

        self.assertEqual(response.json()["status"], "error")
        self.assertIn("no saved token", response.json()["message"])
        self.assertEqual(_RecordingAsyncClient.calls, [])

    def test_profile_name_validation(self):
        self.assertEqual(self._save(name="   ", url="https://x.example.com/mcp", token="t").status_code, 400)
        self.assertEqual(self._save(name="bad\nname", url="https://x.example.com/mcp", token="t").status_code, 400)
        self.assertEqual(self._save(name="ok", url="   ", token="t").status_code, 400)

    def test_save_failure_reports_reason(self):
        self.config_manager.config_path = self.temp_path / "missing-dir" / "config.encrypted"

        response = self._save(name="Prod Splunk", url="https://prod.example.com/mcp", token="prod-token")

        self.assertEqual(response.status_code, 500)
        self.assertIn("Failed to save MCP configuration: FileNotFoundError", response.json()["detail"])

    def test_config_update_with_masked_secrets_keeps_stored_values(self):
        self.assertTrue(self.config_manager.update_mcp(token="mcp-token"))
        self.assertTrue(self.config_manager.update_llm(api_key="sk-real"))

        response = self.client.post(
            "/api/config",
            json={"mcp": {"url": "https://prod.example.com/mcp", "token": MASKED_SECRET}, "llm": {"provider": "openai", "api_key": MASKED_SECRET, "model": "gpt-4.1-mini"}},
        )

        self.assertEqual(response.status_code, 200, response.text)
        config = self.config_manager.get()
        self.assertEqual(config.mcp.token, "mcp-token")
        self.assertEqual(config.llm.api_key, "sk-real")

    def test_credential_update_keeps_key_and_refreshes_active_llm(self):
        created = self.client.post("/api/credentials", json={"name": "Team OpenAI", "provider": "openai", "api_key": "sk-team", "model": "gpt-4.1-mini"})
        self.assertEqual(created.status_code, 200, created.text)
        self.assertFalse(created.json()["activated"])
        loaded = self.client.post(f"/api/credentials/{quote('Team OpenAI', safe='')}/load")
        self.assertEqual(loaded.status_code, 200, loaded.text)

        updated = self.client.post("/api/credentials", json={"name": "Team OpenAI", "provider": "openai", "api_key": "", "model": "gpt-4.1"})

        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertTrue(updated.json()["activated"])
        config = self.config_manager.get()
        self.assertEqual(config.saved_credentials["Team OpenAI"].api_key, "sk-team")
        self.assertEqual(config.llm.api_key, "sk-team")
        self.assertEqual(config.llm.model, "gpt-4.1")

    def test_credential_names_with_slashes_can_be_loaded_and_deleted(self):
        name = "Lab/Ollama's"
        self.client.post("/api/credentials", json={"name": name, "provider": "custom", "api_key": "", "model": "llama3.1:8b", "endpoint_url": "http://localhost:11434/v1"})

        loaded = self.client.post(f"/api/credentials/{quote(name, safe='')}/load")
        deleted = self.client.delete(f"/api/credentials/{quote(name, safe='')}")

        self.assertEqual(loaded.status_code, 200, loaded.text)
        self.assertEqual(deleted.status_code, 200, deleted.text)


class StartupPortTests(unittest.TestCase):
    def test_port_with_loopback_listener_is_not_available(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertFalse(app_main._is_port_available(port))
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
