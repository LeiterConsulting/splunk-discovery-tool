import asyncio
import base64
import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from capabilities import CapabilityManager
from config_manager import ConfigManager
from security_manager import SecurityManager
import troubleshooting
import web_app


GOOD_TOKEN = "good-token-0123456789"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _free_port_run(count: int) -> int:
    """First of `count` consecutive free ports, so scans over a small range find every test server."""
    for _ in range(50):
        base = _free_port()
        if base + count >= 65535:
            continue
        probes = []
        try:
            for offset in range(count):
                probe = socket.socket()
                probes.append(probe)
                probe.bind(("127.0.0.1", base + offset))
            return base
        except OSError:
            continue
        finally:
            for probe in probes:
                probe.close()
    raise RuntimeError("no run of free ports found")


def _jwt(claims):
    def _part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{_part({'alg': 'none'})}.{_part(claims)}.signature"


def _self_signed_cert(directory: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


class _FakeServer:
    """Threaded HTTP(S) server; MCP requests succeed only with GOOD_TOKEN."""

    def __init__(self, tls_files=None, routes=None, port=0):
        received = self.received = []
        bodies = self.bodies = []
        extra_routes = routes or {}

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, payload, content_type="application/json"):
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path in extra_routes:
                    status, payload = extra_routes[self.path]
                    self._send(status, payload)
                else:
                    self._send(404, {"detail": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                bodies.append(self.rfile.read(length))
                auth = self.headers.get("Authorization", "")
                received.append(auth)
                if auth != f"Bearer {GOOD_TOKEN}":
                    self._send(401, {"messages": [{"type": "ERROR", "text": "Unauthorized"}]})
                    return
                self._send(200, {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "run_query"}, {"name": "get_indexes"}]}})

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        if tls_files:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(tls_files[0]), str(tls_files[1]))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


def _checks(report, stage_id):
    stage = next(stage for stage in report["stages"] if stage["id"] == stage_id)
    return {check["id"]: check for check in stage["checks"]}


class TroubleshootApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.originals = (web_app.config_manager, web_app.capability_manager, web_app.security_manager)
        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = SecurityManager(str(self.temp_path / "security.db"))
        self.client = TestClient(web_app.app)

    def tearDown(self):
        self.client.close()
        web_app.config_manager, web_app.capability_manager, web_app.security_manager = self.originals
        os.chdir(self.original_cwd)
        try:
            os.chmod(self.temp_path, 0o700)
        except OSError:
            pass
        self.temp_dir.cleanup()

    def _mcp(self, **payload):
        response = self.client.post("/api/troubleshoot/mcp", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_working_server_lists_tools_and_test_save_leaves_settings_unchanged(self):
        before = (self.temp_path / "config.encrypted").read_bytes()
        with _FakeServer() as server:
            report = self._mcp(name="Prod", url=f"http://127.0.0.1:{server.port}/services/mcp", token=GOOD_TOKEN)

        response = _checks(report, "response")
        self.assertEqual(response["http_status"]["status"], "pass")
        self.assertEqual(response["tools"]["title"], "2 MCP tools are available")
        saving = _checks(report, "saving")
        self.assertEqual(saving["test_save"]["status"], "pass")
        self.assertIn("Creates \u201cProd\u201d", saving["save_plan"]["detail"])
        self.assertEqual((self.temp_path / "config.encrypted").read_bytes(), before)
        self.assertEqual(self.config_manager.get().saved_mcp_configs, {})
        self.assertEqual(sorted(p.name for p in self.temp_path.iterdir() if p.name.endswith(".tmp")), [])
        self.assertNotIn(GOOD_TOKEN, json.dumps(report))

    def test_rejected_token_is_explained(self):
        with _FakeServer() as server:
            report = self._mcp(url=f"http://127.0.0.1:{server.port}/services/mcp", token="wrong-token-value")

        check = _checks(report, "response")["http_status"]
        self.assertEqual(check["status"], "fail")
        self.assertIn("401", check["title"])
        self.assertIn("Settings > Tokens", check["fix"])
        self.assertEqual(report["status"], "fail")
        self.assertIn("401", report["summary"])

    def test_blank_token_uses_the_saved_profile_token(self):
        with _FakeServer() as server:
            url = f"http://127.0.0.1:{server.port}/services/mcp"
            self.config_manager.save_mcp_config("Prod", url, GOOD_TOKEN, activate=True)
            report = self._mcp(name="Prod", url=url, token="***")
            received = list(server.received)

        self.assertEqual(received, [f"Bearer {GOOD_TOKEN}"])
        values = _checks(report, "values")
        self.assertIn("saved with \u201cProd\u201d", values["token"]["title"])
        self.assertIn("Replaces the saved", _checks(report, "saving")["save_plan"]["detail"])

    def test_pasted_bearer_prefix_and_whitespace_are_removed(self):
        with _FakeServer() as server:
            report = self._mcp(url=f"http://127.0.0.1:{server.port}/services/mcp", token=f"  Bearer {GOOD_TOKEN}\n")
            received = list(server.received)

        self.assertEqual(received, [f"Bearer {GOOD_TOKEN}"])
        values = _checks(report, "values")
        self.assertEqual(values["token_bearer"]["status"], "info")
        self.assertEqual(values["token_whitespace"]["status"], "info")
        self.assertEqual(_checks(report, "response")["http_status"]["status"], "pass")

    def test_closed_port_is_reported_and_response_is_skipped(self):
        report = self._mcp(url=f"http://127.0.0.1:{_free_port()}/services/mcp", token=GOOD_TOKEN)

        tcp = _checks(report, "network")["tcp"]
        self.assertEqual(tcp["status"], "fail")
        self.assertIn("Nothing is listening", tcp["title"])
        self.assertIn("8089", tcp["fix"])
        response = next(stage for stage in report["stages"] if stage["id"] == "response")
        self.assertEqual(response["status"], "skip")

    def test_self_signed_certificate_with_verify_on_and_off(self):
        cert_files = _self_signed_cert(self.temp_path)
        with _FakeServer(tls_files=cert_files) as server:
            url = f"https://localhost:{server.port}/services/mcp"
            strict = self._mcp(url=url, token=GOOD_TOKEN, verify_ssl=True)
            relaxed = self._mcp(url=url, token=GOOD_TOKEN, verify_ssl=False)
            bundled = self._mcp(url=url, token=GOOD_TOKEN, verify_ssl=True, ca_bundle_path=str(cert_files[0]))

        tls = _checks(strict, "network")["tls"]
        self.assertEqual(tls["status"], "fail")
        self.assertIn("isn't trusted", tls["title"])
        self.assertIn("Verify SSL", tls["fix"])
        self.assertEqual(next(s for s in strict["stages"] if s["id"] == "response")["status"], "skip")

        self.assertEqual(_checks(relaxed, "network")["tls"]["status"], "warn")
        self.assertEqual(_checks(relaxed, "response")["http_status"]["status"], "pass")

        self.assertEqual(_checks(bundled, "values")["tls_settings"]["status"], "pass")
        self.assertEqual(_checks(bundled, "network")["tls"]["status"], "pass")
        self.assertEqual(_checks(bundled, "response")["tools"]["status"], "pass")

    def test_connection_test_sends_json_rpc_and_uses_the_ca_bundle(self):
        cert_files = _self_signed_cert(self.temp_path)
        with _FakeServer(tls_files=cert_files) as server:
            url = f"https://localhost:{server.port}/services/mcp"

            def run(**extra):
                response = self.client.post("/api/mcp-configs/test", json={"url": url, "token": GOOD_TOKEN, **extra})
                self.assertEqual(response.status_code, 200, response.text)
                return response.json()

            untrusted = run(verify_ssl=True)
            bundled = run(verify_ssl=True, ca_bundle_path=str(cert_files[0]))
            missing = run(verify_ssl=True, ca_bundle_path=str(self.temp_path / "missing.pem"))
            bodies = [json.loads(body) for body in server.bodies]

        self.assertEqual(untrusted["status"], "error")
        self.assertIn("isn't trusted", untrusted["message"])
        self.assertEqual(bundled["status"], "success", bundled)
        self.assertEqual(missing["status"], "error")
        self.assertIn("missing.pem", missing["message"])
        self.assertEqual(bodies, [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}])

    def test_https_url_on_a_plain_http_port(self):
        with _FakeServer() as server:
            report = self._mcp(url=f"https://127.0.0.1:{server.port}/services/mcp", token=GOOD_TOKEN)

        tls = _checks(report, "network")["tls"]
        self.assertEqual(tls["status"], "fail")
        self.assertIn("doesn't speak HTTPS", tls["title"])
        self.assertIn("http://", tls["fix"])

    def test_expired_jwt_is_reported_without_contacting_the_server(self):
        token = _jwt({"exp": int(time.time()) - 3600, "aud": "mcp"})
        report = self._mcp(url="http://127.0.0.1:9/services/mcp", token=token, check_connection=False)

        expiry = _checks(report, "values")["token_expiry"]
        self.assertEqual(expiry["status"], "fail")
        self.assertIn("expired", expiry["title"])
        self.assertIn("Audience: mcp", expiry["detail"])

    def test_url_mistakes_are_explained(self):
        report = self._mcp(url="splunk.example.com:8089/services/mcp", token=GOOD_TOKEN, check_connection=False)
        self.assertIn("missing https://", _checks(report, "values")["url"]["title"])

        report = self._mcp(url="https://splunk.example.com:8000", token=GOOD_TOKEN, check_connection=False)
        values = _checks(report, "values")
        self.assertEqual(values["url_path"]["status"], "warn")
        self.assertEqual(values["url_port"]["status"], "warn")

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "needs POSIX permissions as non-root")
    def test_read_only_settings_folder_is_reported(self):
        os.chmod(self.temp_path, 0o500)
        report = self._mcp(name="Prod", url="http://127.0.0.1:9/services/mcp", token=GOOD_TOKEN, check_connection=False)

        saving = _checks(report, "saving")
        self.assertEqual(saving["folder_writable"]["status"], "fail")
        self.assertIn("Permission", saving["folder_writable"]["detail"])
        self.assertIn("chmod u+w", saving["folder_writable"]["fix"])
        self.assertNotIn("test_save", saving)

    def test_settings_file_that_does_not_match_the_key(self):
        (self.temp_path / "config.encrypted").write_bytes(b"not a fernet token")
        report = self._mcp(name="Prod", url="http://127.0.0.1:9/services/mcp", token=GOOD_TOKEN, check_connection=False)

        config_file = _checks(report, "saving")["config_file"]
        self.assertEqual(config_file["status"], "fail")
        self.assertIn("can't be decrypted", config_file["title"])

    def test_server_running_older_code_is_reported(self):
        stale = dict(web_app.SERVER_STARTUP_STATE, fingerprint="older-code", commit="0" * 40)
        with patch.object(web_app, "SERVER_STARTUP_STATE", stale):
            report = self._mcp(url="http://127.0.0.1:9/services/mcp", token=GOOD_TOKEN, check_connection=False, check_save=False)

        server_code = _checks(report, "app")["server_code"]
        self.assertEqual(server_code["status"], "fail")
        self.assertIn("older code", server_code["title"])
        self.assertIn("--restart", server_code["fix"]) if os.name != "nt" else self.assertIn("-Restart", server_code["fix"])

    def test_server_status_endpoint_reports_stale_code(self):
        fresh = self.client.get("/api/troubleshoot/server-status")
        self.assertEqual(fresh.status_code, 200, fresh.text)
        self.assertFalse(fresh.json()["stale"])

        self.assertEqual(fresh.json()["pid"], os.getpid())
        self.assertEqual(fresh.json()["install_dir"], str(web_app.PROJECT_ROOT))
        self.assertIsInstance(fresh.json()["port"], int)

        viewer = {"auth_enabled": True, "username": "viewer", "role": "viewer", "can_manage": False}
        with patch.object(web_app, "_troubleshoot_account", return_value=viewer):
            self.assertNotIn("install_dir", self.client.get("/api/troubleshoot/server-status").json())

        stale = dict(web_app.SERVER_STARTUP_STATE, fingerprint="older-code")
        with patch.object(web_app, "SERVER_STARTUP_STATE", stale):
            body = self.client.get("/api/troubleshoot/server-status").json()
        self.assertTrue(body["stale"])
        self.assertIn("install", body["restart_hint"])
        self.assertTrue(body["started_at"].endswith("+00:00"))

    def test_values_the_save_endpoint_would_reject(self):
        response = self.client.post(
            "/api/troubleshoot/llm",
            json={"name": "Local", "provider": "ollama", "model": "llama3", "request_timeout": 99999, "check_connection": False},
        )
        self.assertEqual(response.status_code, 200, response.text)
        validation = _checks(response.json(), "values")["request_validation"]
        self.assertEqual(validation["status"], "fail")
        self.assertIn("request_timeout", validation["detail"])

        report = self._mcp(name="bad\nname", url="http://127.0.0.1:9/mcp", check_connection=False)
        self.assertIn("printable", _checks(report, "values")["request_validation"]["detail"])

    def test_local_model_server_not_running(self):
        port = _free_port()
        response = self.client.post(
            "/api/troubleshoot/llm",
            json={"provider": "ollama", "model": "llama3", "endpoint_url": f"http://127.0.0.1:{port}", "check_save": False},
        )
        report = response.json()
        tcp = _checks(report, "network")["tcp"]
        self.assertEqual(tcp["status"], "fail")
        self.assertIn("ollama serve", tcp["fix"])

    def test_refresh_failure_after_save_still_reports_success(self):
        with patch.object(web_app.capability_manager, "refresh", side_effect=RuntimeError("chromadb import failed")):
            response = self.client.post("/api/mcp-configs", json={"name": "Prod", "url": "https://prod.example.com/mcp", "token": "t"})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["activated"])
        self.assertIn("chromadb import failed", response.json()["warning"])
        self.assertEqual(self.config_manager.get().saved_mcp_configs["Prod"].token, "t")

    def test_saving_strips_pasted_bearer_prefix(self):
        response = self.client.post("/api/mcp-configs", json={"name": "Prod", "url": "https://prod.example.com/mcp", "token": " Bearer abc.def \n"})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.config_manager.get().saved_mcp_configs["Prod"].token, "abc.def")
        self.assertEqual(self.config_manager.get().mcp.token, "abc.def")


class TroubleshootUnitTests(unittest.TestCase):
    def _run(self, coroutine):
        return asyncio.run(coroutine)

    def test_code_changes_after_start_mark_the_server_stale(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "src").mkdir()
            module = root / "src" / "module.py"
            module.write_text("VALUE = 1\n", encoding="utf-8")
            startup = troubleshooting.capture_startup_state(root)
            self.assertFalse(troubleshooting.server_code_status(root, startup)["stale"])

            module.write_text("VALUE = 2\n", encoding="utf-8")
            self.assertTrue(troubleshooting.server_code_status(root, startup)["stale"])

    def test_unknown_host(self):
        endpoint = troubleshooting.parse_endpoint("https://splunk.invalid:8089/services/mcp", "")
        error = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with patch("socket.getaddrinfo", side_effect=error):
            stage, reachable = self._run(troubleshooting.network_stage(endpoint, kind="mcp", verify=False, ca_bundle=None, local_server_hint=""))

        self.assertFalse(reachable)
        dns = {check.id: check for check in stage.checks}["dns"]
        self.assertEqual(dns.status, "fail")
        self.assertIn("splunk.invalid", dns.title)
        self.assertIn("VPN", dns.fix)

    def test_missing_and_outdated_packages(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "requirements.txt").write_text("definitely-not-installed-dt4sms>=1.0\nhttpx>=999.0\n", encoding="utf-8")
            stage = troubleshooting.Stage("app", "App")
            troubleshooting.check_dependencies(stage, Path(folder))
            missing = stage.checks[0]
            self.assertEqual(missing.status, "fail")
            self.assertIn("definitely-not-installed-dt4sms", missing.title)

            Path(folder, "requirements.txt").write_text("httpx>=999.0\n", encoding="utf-8")
            stage = troubleshooting.Stage("app", "App")
            troubleshooting.check_dependencies(stage, Path(folder))
            self.assertEqual(stage.checks[0].status, "warn")
            self.assertIn("httpx", stage.checks[0].detail)

    def test_other_copy_of_the_app_is_detected(self):
        routes = {"/api/auth/status": (200, {"auth_enabled": False, "demo_mode": True})}
        with _FakeServer(routes=routes) as other:
            stage = troubleshooting.Stage("app", "App")
            self._run(troubleshooting.check_other_instances(stage, own_port=None, preferred_port=other.port - 1))

        check = stage.checks[0]
        self.assertEqual(check.status, "warn")
        self.assertIn(str(other.port), check.title)

    def test_other_copies_report_their_version_and_how_to_stop_them(self):
        auth = (200, {"auth_enabled": False, "demo_mode": True})
        current = {"/api/auth/status": auth, "/api/troubleshoot/server-status": (200, {"stale": False, "running_commit": "2a9341d97ddd"})}
        base = _free_port_run(4)
        with _FakeServer(routes={"/api/auth/status": auth}, port=base + 2) as old, _FakeServer(routes=current, port=base + 3) as new:
            first = base + 2
            stage = troubleshooting.Stage("app", "App")
            self._run(troubleshooting.check_other_instances(stage, own_port=base + 1, preferred_port=base, project_root=ROOT))
            listener = troubleshooting.listener_pid(old.port)

        check = stage.checks[0]
        self.assertEqual(check.status, "warn")
        self.assertIn("Other copies of the app are running on ports", check.title)
        self.assertIn(f"Port {old.port}: an older version of the app", check.detail)
        self.assertIn(f"Port {new.port}: up to date (commit 2a9341d)", check.detail)
        self.assertIn(f"started from {ROOT}", check.detail)
        self.assertIn(f"moves to port {first - 2}", check.fix)
        if listener is not None:
            self.assertEqual(listener, os.getpid())
            self.assertIn(f"PID {os.getpid()}", check.detail)
            self.assertIn(str(os.getpid()), check.fix)

    def test_install_folder_is_read_from_the_process_command_line(self):
        cases = {
            "/opt/homebrew/bin/python3 /Users/me/old copy/src/main.py": "/Users/me/old copy",
            "python /home/me/dt4sms/src/main.py": "/home/me/dt4sms",
            '"C:\\Users\\me\\.venv\\Scripts\\python.exe" "C:\\Users\\me\\dt4sms\\src\\main.py"': "C:\\Users\\me\\dt4sms",
            "C:\\py\\python.exe D:\\apps\\dt4sms\\src\\main.py": "D:\\apps\\dt4sms",
            "python src/main.py": None,
            "/usr/sbin/sshd -D": None,
        }
        for command, folder in cases.items():
            with self.subTest(command=command):
                self.assertEqual(troubleshooting.app_folder_from_command(command), folder)

    def test_non_admin_only_gets_app_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = ConfigManager(str(Path(folder) / "config.encrypted"))
            startup = troubleshooting.capture_startup_state(ROOT)
            report = self._run(troubleshooting.run_mcp_diagnostics(
                {"url": "http://127.0.0.1:9/mcp", "token": GOOD_TOKEN},
                config_manager=manager,
                project_root=ROOT,
                startup=startup,
                own_port=None,
                account={"auth_enabled": True, "username": "ana", "role": "analyst", "can_manage": False},
                activate=False,
                validation_errors=[],
            ))

        self.assertEqual(_checks(report, "app")["account"]["status"], "fail")
        self.assertEqual([s["status"] for s in report["stages"][1:]], ["skip"] * 4)

    def test_llm_provider_errors_are_classified_and_secrets_hidden(self):
        api_key = "AIza" + "-fake-test-value" * 2

        async def runner(payload):
            self.assertEqual(payload["api_key"], api_key)
            return {"tests": {"connection": {
                "status": "error",
                "message": f"Client error '401 Unauthorized' for url 'https://generativelanguage.googleapis.com/v1beta/models?key={api_key}'",
            }}}

        with tempfile.TemporaryDirectory() as folder:
            manager = ConfigManager(str(Path(folder) / "config.encrypted"))
            report = self._run(troubleshooting.run_llm_diagnostics(
                {"provider": "gemini", "api_key": api_key, "model": "gemini-2.5-flash", "check_save": False},
                config_manager=manager,
                project_root=ROOT,
                startup=troubleshooting.capture_startup_state(ROOT),
                own_port=None,
                account={"auth_enabled": False, "can_manage": True},
                activate=False,
                validation_errors=[],
                normalize_provider=lambda value: str(value),
                effective_endpoint=lambda provider, url: "http://127.0.0.1:9",
                runner=runner,
            ))

        self.assertNotIn(api_key, json.dumps(report))
        network = next(s for s in report["stages"] if s["id"] == "network")
        if network["status"] == "fail":
            return
        connection = _checks(report, "response")["connection"]
        self.assertIn("401", connection["title"])

    def test_classify_llm_errors(self):
        title, fix = troubleshooting.classify_llm_error("Model 'llama3' is not installed on this Ollama server", "ollama", "llama3", True)
        self.assertIn("isn't installed", title)
        self.assertIn("ollama pull llama3", fix)
        title, _ = troubleshooting.classify_llm_error("Error code: 429 - insufficient_quota", "openai", "gpt-5", False)
        self.assertIn("quota", title)
        title, _ = troubleshooting.classify_llm_error("Client error '404 Not Found'", "custom", "m", True)
        self.assertIn("404", title)

    def test_redact_hides_secrets_and_key_parameters(self):
        cleaned = troubleshooting.redact({"a": ["token abcd1234 here", "x?key=zzz&y=1"]}, ["abcd1234"])
        self.assertEqual(cleaned, {"a": ["token [hidden] here", "x?key=[hidden]&y=1"]})


if __name__ == "__main__":
    unittest.main()
