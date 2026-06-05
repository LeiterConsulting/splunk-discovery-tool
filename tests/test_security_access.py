import asyncio
import base64
import copy
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa, utils
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from capabilities import CapabilityManager
from config_manager import ConfigManager
from security_manager import SecurityManager
import web_app


def _b64url_encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def _build_unsigned_id_token(payload):
    header = _b64url_encode_bytes(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    body = _b64url_encode_bytes(json.dumps(payload).encode("utf-8"))
    return f"{header}.{body}."


def _get_test_rsa_hash_algorithm(algorithm="RS256"):
    normalized_algorithm = str(algorithm or "RS256").strip().upper()
    hash_algorithms = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
        "PS256": hashes.SHA256,
        "PS384": hashes.SHA384,
        "PS512": hashes.SHA512,
        "ES256": hashes.SHA256,
        "ES384": hashes.SHA384,
        "ES512": hashes.SHA512,
        "EDDSA": None,
    }
    hash_algorithm_factory = hash_algorithms[normalized_algorithm]
    return normalized_algorithm, hash_algorithm_factory() if hash_algorithm_factory is not None else None


def _build_test_rs256_signing_material(kid="test-signing-key", algorithm="RS256"):
    normalized_algorithm, _ = _get_test_rsa_hash_algorithm(algorithm)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    return private_key, {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": normalized_algorithm,
        "n": _b64url_encode_bytes(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url_encode_bytes(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
    }


def _get_test_ec_curve(algorithm="ES256"):
    normalized_algorithm = str(algorithm or "ES256").strip().upper()
    curves = {
        "ES256": (ec.SECP256R1, "P-256"),
        "ES384": (ec.SECP384R1, "P-384"),
        "ES512": (ec.SECP521R1, "P-521"),
    }
    curve_factory, curve_name = curves[normalized_algorithm]
    return normalized_algorithm, curve_factory(), curve_name


def _build_test_es_signing_material(kid="test-signing-key", algorithm="ES256"):
    normalized_algorithm, curve, curve_name = _get_test_ec_curve(algorithm)
    private_key = ec.generate_private_key(curve)
    public_numbers = private_key.public_key().public_numbers()
    coordinate_length = (curve.key_size + 7) // 8
    return private_key, {
        "kty": "EC",
        "use": "sig",
        "kid": kid,
        "alg": normalized_algorithm,
        "crv": curve_name,
        "x": _b64url_encode_bytes(public_numbers.x.to_bytes(coordinate_length, "big")),
        "y": _b64url_encode_bytes(public_numbers.y.to_bytes(coordinate_length, "big")),
    }


def _build_test_eddsa_signing_material(kid="test-signing-key", curve_name="Ed25519"):
    normalized_curve_name = str(curve_name or "Ed25519").strip()
    curve_factories = {
        "Ed25519": ed25519.Ed25519PrivateKey.generate,
        "Ed448": ed448.Ed448PrivateKey.generate,
    }
    private_key = curve_factories[normalized_curve_name]()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, {
        "kty": "OKP",
        "use": "sig",
        "kid": kid,
        "alg": "EdDSA",
        "crv": normalized_curve_name,
        "x": _b64url_encode_bytes(public_key_bytes),
    }


def _build_test_signed_id_token(private_key, payload, kid="test-signing-key", algorithm="RS256"):
    normalized_algorithm, hash_algorithm = _get_test_rsa_hash_algorithm(algorithm)
    header_segment = _b64url_encode_bytes(json.dumps({"alg": normalized_algorithm, "typ": "JWT", "kid": kid}).encode("utf-8"))
    body_segment = _b64url_encode_bytes(json.dumps(payload).encode("utf-8"))
    signing_input = f"{header_segment}.{body_segment}".encode("ascii")
    if normalized_algorithm == "EDDSA":
        signature = private_key.sign(signing_input)
    elif normalized_algorithm.startswith("ES"):
        der_signature = private_key.sign(signing_input, ec.ECDSA(hash_algorithm))
        r_value, s_value = utils.decode_dss_signature(der_signature)
        coordinate_length = (private_key.curve.key_size + 7) // 8
        signature = r_value.to_bytes(coordinate_length, "big") + s_value.to_bytes(coordinate_length, "big")
    elif normalized_algorithm.startswith("PS"):
        signature_padding = padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.DIGEST_LENGTH)
        signature = private_key.sign(signing_input, signature_padding, hash_algorithm)
    else:
        signature_padding = padding.PKCS1v15()
        signature = private_key.sign(signing_input, signature_padding, hash_algorithm)
    return f"{header_segment}.{body_segment}.{_b64url_encode_bytes(signature)}"


class SecurityManagerTests(unittest.TestCase):
    def test_bootstrap_admin_session_and_password_rotation_flow(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            manager = SecurityManager(str(temp_path / "security.db"))

            bootstrap = manager.ensure_bootstrap_admin(require_password_reset=True)
            self.assertTrue(bootstrap["created"])
            self.assertEqual(bootstrap["username"], "admin")

            user = manager.authenticate_local_user("admin", "password")
            self.assertIsNotNone(user)
            self.assertTrue(user["require_password_reset"])

            session = manager.create_session(int(user["id"]), timeout_minutes=30)
            resolved = manager.resolve_session(session["session_token"])
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved["username"], "admin")

            self.assertTrue(manager.update_password(int(user["id"]), "BetterPassword123!", require_password_reset=False))
            self.assertIsNone(manager.authenticate_local_user("admin", "password"))

            updated_user = manager.authenticate_local_user("admin", "BetterPassword123!")
            self.assertIsNotNone(updated_user)
            self.assertFalse(updated_user["require_password_reset"])

    def test_user_crud_and_last_admin_protection(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            manager = SecurityManager(str(temp_path / "security.db"))

            bootstrap = manager.ensure_bootstrap_admin(require_password_reset=False)
            admin_user = manager.get_user_by_username(bootstrap["username"])
            self.assertIsNotNone(admin_user)

            analyst = manager.create_user(
                username="analyst-one",
                password="AnalystPassword123!",
                role="analyst",
                require_password_reset=False,
                mcp_config_name="tenant-a",
            )
            self.assertEqual(analyst["mcp_config_name"], "tenant-a")

            users = manager.list_users()
            self.assertEqual(len(users), 2)

            updated_user = manager.update_user(
                int(analyst["id"]),
                role="viewer",
                mcp_config_name="tenant-b",
            )
            self.assertIsNotNone(updated_user)
            self.assertEqual(updated_user["role"], "viewer")
            self.assertEqual(updated_user["mcp_config_name"], "tenant-b")

            with self.assertRaises(ValueError):
                manager.delete_user(int(admin_user["id"]))

            second_admin = manager.create_user(
                username="admin-two",
                password="AdminPassword123!",
                role="admin",
                require_password_reset=False,
            )
            self.assertTrue(manager.delete_user(int(second_admin["id"])))

    def test_access_token_issue_authenticate_and_revoke_flow(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            manager = SecurityManager(str(temp_path / "security.db"))

            bootstrap = manager.ensure_bootstrap_admin(require_password_reset=False)
            admin_user = manager.get_user_by_username(bootstrap["username"])
            self.assertIsNotNone(admin_user)

            analyst = manager.create_user(
                username="analyst-one",
                password="AnalystPassword123!",
                role="analyst",
                require_password_reset=False,
            )

            issued = manager.issue_access_token(
                name="RAG reader",
                scopes=["rag:search", "rag:assets:read"],
                token_type="external_api",
                owner_user_id=int(analyst["id"]),
                created_by_user_id=int(admin_user["id"]),
                expires_in_days=7,
            )
            self.assertTrue(str(issued["access_token"]).startswith("dt4sms_"))
            self.assertEqual(issued["token"]["owner_user_id"], int(analyst["id"]))
            self.assertEqual(issued["token"]["owner_username"], "analyst-one")
            self.assertEqual(issued["token"]["token_type"], "external_api")
            self.assertEqual(issued["token"]["scopes"], ["rag:search", "rag:assets:read"])

            listed_tokens = manager.list_access_tokens()
            self.assertEqual(len(listed_tokens), 1)
            self.assertEqual(listed_tokens[0]["id"], issued["token"]["id"])
            self.assertIsNone(listed_tokens[0]["last_used_at"])

            resolved = manager.resolve_access_token(
                issued["access_token"],
                required_scopes=["rag:search"],
                token_type="external_api",
                used_from="unit-test",
            )
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved["id"], issued["token"]["id"])
            self.assertEqual(resolved["last_used_from"], "unit-test")
            self.assertEqual(resolved["use_count"], 1)
            self.assertIsNotNone(resolved["last_used_at"])

            denied = manager.resolve_access_token(
                issued["access_token"],
                required_scopes=["mcp:tools:read"],
                token_type="external_api",
            )
            self.assertIsNone(denied)

            self.assertTrue(manager.revoke_access_token(int(issued["token"]["id"]), revoked_by_user_id=int(admin_user["id"])))
            self.assertIsNone(manager.resolve_access_token(issued["access_token"], token_type="external_api"))
            self.assertTrue(manager.delete_access_token(int(issued["token"]["id"]), deleted_by_user_id=int(admin_user["id"])))
            self.assertIsNone(manager.get_access_token(int(issued["token"]["id"])))
            self.assertEqual(manager.list_access_tokens(), [])

    def test_external_identity_username_collision_provisions_distinct_user_and_reuses_mapping(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            manager = SecurityManager(str(temp_path / "security.db"))

            existing_local_user = manager.create_user(
                username="analyst-one",
                password="AnalystPassword123!",
                role="analyst",
                require_password_reset=False,
            )

            collision_user = manager.resolve_or_provision_external_user(
                auth_provider="oidc",
                subject="subject-existing",
                preferred_username="analyst-one",
                email="analyst-one@example.com",
                role="viewer",
                claims={"sub": "subject-existing", "preferred_username": "analyst-one"},
            )
            self.assertNotEqual(collision_user["id"], existing_local_user["id"])
            self.assertEqual(collision_user["username"], "analyst-one-2")

            mapping = manager.get_external_identity("oidc", "subject-existing")
            self.assertIsNotNone(mapping)
            self.assertEqual(mapping["user"]["username"], "analyst-one-2")

            provisioned_user = manager.resolve_or_provision_external_user(
                auth_provider="oidc",
                subject="subject-new",
                preferred_username="oidc-user",
                email="oidc-user@example.com",
                role="viewer",
                mcp_config_name="tenant-a",
                claims={"sub": "subject-new", "preferred_username": "oidc-user"},
            )
            self.assertEqual(provisioned_user["username"], "oidc-user")
            self.assertEqual(provisioned_user["role"], "viewer")
            self.assertEqual(provisioned_user["mcp_config_name"], "tenant-a")

            repeat_login = manager.resolve_or_provision_external_user(
                auth_provider="oidc",
                subject="subject-existing",
                preferred_username="ignored-name",
                email="analyst-one@example.com",
                role="admin",
                claims={"sub": "subject-existing", "preferred_username": "ignored-name"},
            )
            self.assertEqual(repeat_login["id"], collision_user["id"])

    def test_external_identity_relogin_syncs_explicit_role_and_assignment(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            manager = SecurityManager(str(temp_path / "security.db"))

            first_login = manager.resolve_or_provision_external_user(
                auth_provider="oidc",
                subject="subject-sync",
                preferred_username="oidc-sync-user",
                email="oidc-sync-user@example.com",
                role="viewer",
                mcp_config_name="tenant-a",
                claims={"sub": "subject-sync", "preferred_username": "oidc-sync-user"},
            )
            self.assertEqual(first_login["role"], "viewer")
            self.assertEqual(first_login["mcp_config_name"], "tenant-a")

            second_login = manager.resolve_or_provision_external_user(
                auth_provider="oidc",
                subject="subject-sync",
                preferred_username="oidc-sync-user",
                email="oidc-sync-user@example.com",
                role="analyst",
                mcp_config_name="tenant-b",
                claims={"sub": "subject-sync", "preferred_username": "oidc-sync-user"},
            )
            self.assertEqual(second_login["id"], first_login["id"])
            self.assertEqual(second_login["role"], "analyst")
            self.assertEqual(second_login["mcp_config_name"], "tenant-b")

    def test_admin_link_external_identity_maps_existing_local_user(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            manager = SecurityManager(str(temp_path / "security.db"))

            local_user = manager.create_user(
                username="analyst-one",
                password="AnalystPassword123!",
                role="analyst",
                require_password_reset=False,
                mcp_config_name="tenant-a",
            )

            linked_user = manager.link_external_identity(
                user_id=int(local_user["id"]),
                auth_provider="oidc",
                subject="subject-linked",
                email="analyst-one@example.com",
                claims={"sub": "subject-linked", "preferred_username": "analyst-one"},
            )

            self.assertEqual(linked_user["id"], local_user["id"])

            mapping = manager.get_external_identity("oidc", "subject-linked")
            self.assertIsNotNone(mapping)
            self.assertEqual(mapping["user_id"], int(local_user["id"]))
            self.assertEqual(mapping["user"]["username"], "analyst-one")

            with self.assertRaises(ValueError):
                manager.link_external_identity(
                    user_id=int(local_user["id"]),
                    auth_provider="oidc",
                    subject="subject-other",
                    email="analyst-one@example.com",
                )


class WebAppLocalAuthTests(unittest.TestCase):
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
        self.original_external_surface_rate_limiter = web_app.external_surface_rate_limiter
        self.original_oidc_login_state_store = web_app.oidc_login_state_store

        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = self.security_manager
        web_app.external_surface_rate_limiter = web_app.ExternalSurfaceRateLimiter()
        web_app.oidc_login_state_store = web_app.OIDCLoginStateStore()
        if hasattr(web_app, "clear_oidc_provider_jwks_cache"):
            web_app.clear_oidc_provider_jwks_cache()
        if hasattr(web_app, "clear_m26_14_validation_cache"):
            web_app.clear_m26_14_validation_cache()

        self.client = TestClient(web_app.app)

    def tearDown(self):
        self.client.close()
        web_app.config_manager = self.original_config_manager
        web_app.capability_manager = self.original_capability_manager
        web_app.security_manager = self.original_security_manager
        web_app.external_surface_rate_limiter = self.original_external_surface_rate_limiter
        web_app.oidc_login_state_store = self.original_oidc_login_state_store
        if hasattr(web_app, "clear_oidc_provider_jwks_cache"):
            web_app.clear_oidc_provider_jwks_cache()
        if hasattr(web_app, "clear_m26_14_validation_cache"):
            web_app.clear_m26_14_validation_cache()
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def _enable_auth_and_complete_admin_reset(self, updated_password: str = "BetterPassword123!"):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))

        login = self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.json()["password_reset_required"])

        reset = self.client.post(
            "/api/auth/reset-password",
            json={
                "current_password": "password",
                "new_password": updated_password,
                "confirm_password": updated_password,
            },
        )
        self.assertEqual(reset.status_code, 200)
        self.assertFalse(reset.json()["password_reset_required"])
        return updated_password

    def _register_discovery_session_fixture(self, timestamp, scope_key=None, active_mcp_config_name=None):
        report_name = f"v2_intelligence_blueprint_{timestamp}.json"
        output_dir = web_app._discovery_scope_output_dir(scope_key)
        (output_dir / report_name).write_text("{}", encoding="utf-8")

        overview = SimpleNamespace(
            total_indexes=0,
            total_sourcetypes=0,
            total_hosts=0,
            total_users=0,
            data_volume_24h="unknown",
            splunk_version="unknown",
        )

        discovery_scope = None
        normalized_scope_key = web_app._normalize_discovery_scope_key(scope_key)
        if normalized_scope_key != web_app.DISCOVERY_SCOPE_GLOBAL:
            discovery_scope = {
                "scope_key": normalized_scope_key,
                "scope_label": active_mcp_config_name or normalized_scope_key,
                "active_mcp_config_name": active_mcp_config_name,
            }

        return web_app.register_discovery_session(
            timestamp=timestamp,
            overview=overview,
            report_paths=[report_name],
            mcp_capabilities={},
            classifications={},
            recommendations=[],
            suggested_use_cases=[],
            discovery_step_count=0,
            discovery_scope=discovery_scope,
        )

    def _enable_m26_14_advisor(self):
        install_result = web_app.capability_manager.install_capability("m26_14_advisor")
        self.assertTrue(install_result.ok, install_result.message)

        enable_result = web_app.capability_manager.enable_capability("m26_14_advisor")
        self.assertTrue(enable_result.ok, enable_result.message)

    def test_demo_mode_leaves_config_access_available(self):
        status = self.client.get("/api/auth/status")
        self.assertEqual(status.status_code, 200)
        self.assertFalse(status.json()["auth_enabled"])
        self.assertTrue(status.json()["demo_mode"])

        config_response = self.client.get("/api/config")
        self.assertEqual(config_response.status_code, 200)
        self.assertIn("security", config_response.json())

    def test_connection_info_hides_unconfigured_default_placeholders(self):
        connection_response = self.client.get("/connection-info")
        self.assertEqual(connection_response.status_code, 200)

        payload = connection_response.json()
        self.assertEqual(payload["status"], "disconnected")
        self.assertFalse(payload["llm"]["configured"])
        self.assertEqual(payload["llm"]["display_label"], "")
        self.assertEqual(payload["llm"]["model"], "")
        self.assertEqual(payload["llm"]["endpoint"], "")
        self.assertFalse(payload["mcp"]["configured"])
        self.assertEqual(payload["mcp"]["endpoint"], "")

    def test_m26_14_profile_and_validation_catalog_endpoints_return_advisor_data(self):
        self._enable_m26_14_advisor()
        session_id = "20260526_120000"
        self._register_discovery_session_fixture(session_id)

        profile_response = self.client.get("/api/discovery/m26-14/profile")
        self.assertEqual(profile_response.status_code, 200)
        profile_payload = profile_response.json()
        self.assertTrue(profile_payload["has_data"])
        self.assertEqual(profile_payload["timestamp"], session_id)
        self.assertTrue(any(pack.get("id") == "retention_and_searchability" for pack in profile_payload["validation_packs"]))
        self.assertTrue(any(session.get("timestamp") == session_id for session in profile_payload["sessions"]))

        catalog_response = self.client.get("/api/discovery/m26-14/validation-packs")
        self.assertEqual(catalog_response.status_code, 200)
        catalog_payload = catalog_response.json()
        self.assertEqual(catalog_payload["status"], "success")
        self.assertTrue(any(pack.get("id") == "audit_and_admin_activity" for pack in catalog_payload["packs"]))
        self.assertEqual(catalog_payload["capability"]["health_status"], "ready")

    def test_m26_14_compare_endpoint_uses_session_history_and_deduplicates_recommended_packs(self):
        self._enable_m26_14_advisor()
        previous_session_id = "20260525_120000"
        latest_session_id = "20260526_120000"
        self._register_discovery_session_fixture(previous_session_id)
        self._register_discovery_session_fixture(latest_session_id)

        profile_by_timestamp = {
            latest_session_id: {
                "has_data": True,
                "framework": "OMB M-26-14",
                "readiness_estimate": 82,
                "confidence": "medium",
                "maturity_floor": {"level": 3, "explanation": "Latest session shows broader evidence coverage."},
                "priority_objectives": {},
                "maturity_elements": [],
                "live_validation": {
                    "curated_pack_count": 2,
                    "recommended_pack_ids": [
                        "network_visibility_coverage",
                        "audit_and_admin_activity",
                    ],
                },
                "source_summary": {},
            },
            previous_session_id: {
                "has_data": True,
                "framework": "OMB M-26-14",
                "readiness_estimate": 64,
                "confidence": "low",
                "maturity_floor": {"level": 2, "explanation": "Previous session had narrower evidence coverage."},
                "priority_objectives": {},
                "maturity_elements": [],
                "live_validation": {
                    "curated_pack_count": 2,
                    "recommended_pack_ids": [
                        "audit_and_admin_activity",
                        "timestamp_freshness_sanity",
                    ],
                },
                "source_summary": {},
            },
        }

        def stub_build_profile_from_blueprint(blueprint):
            timestamp = blueprint.get("_session", {}).get("timestamp")
            return copy.deepcopy(profile_by_timestamp[timestamp])

        with patch.object(web_app, "build_m26_14_profile_from_blueprint", side_effect=stub_build_profile_from_blueprint):
            compare_response = self.client.get("/api/discovery/m26-14/compare?current=latest&baseline=previous")

        self.assertEqual(compare_response.status_code, 200)
        compare_payload = compare_response.json()
        self.assertTrue(compare_payload["has_data"])
        self.assertEqual(compare_payload["current"]["timestamp"], latest_session_id)
        self.assertEqual(compare_payload["baseline"]["timestamp"], previous_session_id)
        self.assertEqual(compare_payload["comparison"]["readiness_delta"], 18)
        self.assertEqual(compare_payload["comparison"]["maturity_floor_delta"], 1)
        self.assertEqual(
            compare_payload["comparison"]["recommended_pack_ids"],
            [
                "network_visibility_coverage",
                "audit_and_admin_activity",
                "timestamp_freshness_sanity",
            ],
        )
        self.assertEqual(
            [session.get("timestamp") for session in compare_payload["sessions"][:2]],
            [latest_session_id, previous_session_id],
        )

    def test_m26_14_validation_endpoint_rejects_viewer_role(self):
        self._enable_m26_14_advisor()
        self._enable_auth_and_complete_admin_reset()

        create_viewer = self.client.post(
            "/api/security/users",
            json={
                "username": "viewer-m2614",
                "password": "ViewerPassword123!",
                "role": "viewer",
                "require_password_reset": False,
            },
        )
        self.assertEqual(create_viewer.status_code, 200)

        logout_response = self.client.post("/api/auth/logout")
        self.assertEqual(logout_response.status_code, 200)

        viewer_login = self.client.post(
            "/api/auth/login",
            json={"username": "viewer-m2614", "password": "ViewerPassword123!"},
        )
        self.assertEqual(viewer_login.status_code, 200)

        validation_response = self.client.post(
            "/api/discovery/m26-14/validate",
            json={"pack_id": "retention_and_searchability"},
        )
        self.assertEqual(validation_response.status_code, 403)
        self.assertIn("analyst or admin", validation_response.json()["detail"].lower())

    def test_m26_14_validation_endpoint_allows_admin_and_analyst_execution(self):
        admin_password = self._enable_auth_and_complete_admin_reset()
        self._enable_m26_14_advisor()

        create_analyst = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst-m2614",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
            },
        )
        self.assertEqual(create_analyst.status_code, 200)

        captured_calls = []

        def build_runtime_config(request=None):
            return SimpleNamespace(
                mcp=SimpleNamespace(url="https://mcp.example.com"),
                active_mcp_config_name="global",
            )

        async def stub_execute_mcp_tool_call(payload, runtime_config):
            captured_calls.append(
                {
                    "payload": copy.deepcopy(payload),
                    "runtime_url": getattr(runtime_config.mcp, "url", None),
                    "runtime_name": getattr(runtime_config, "active_mcp_config_name", None),
                }
            )
            return {
                "result": {
                    "structuredContent": {
                        "status_code": 200,
                        "results": [
                            {
                                "index": "main",
                                "retention_days": 400,
                                "retention_status": "meets_floor",
                            }
                        ],
                    }
                }
            }

        with patch.object(web_app, "resolve_effective_runtime_config", side_effect=build_runtime_config), patch.object(
            web_app,
            "execute_mcp_tool_call",
            new=AsyncMock(side_effect=stub_execute_mcp_tool_call),
        ):
            admin_response = self.client.post(
                "/api/discovery/m26-14/validate",
                json={
                    "pack_id": "retention_and_searchability",
                    "earliest": "-14d",
                    "latest": "now",
                },
            )

            self.assertEqual(admin_response.status_code, 200)
            admin_payload = admin_response.json()
            self.assertEqual(admin_payload["status"], "success")
            self.assertEqual(admin_payload["result"]["status_code"], 200)
            self.assertEqual(admin_payload["result"]["summary"]["status"], "observed")
            self.assertEqual(admin_payload["result"]["summary"]["row_count"], 1)
            self.assertEqual(admin_payload["time_range"], {"earliest": "-14d", "latest": "now"})

            admin_logout = self.client.post("/api/auth/logout")
            self.assertEqual(admin_logout.status_code, 200)

            analyst_login = self.client.post(
                "/api/auth/login",
                json={"username": "analyst-m2614", "password": "AnalystPassword123!"},
            )
            self.assertEqual(analyst_login.status_code, 200)

            analyst_response = self.client.post(
                "/api/discovery/m26-14/validate",
                json={
                    "pack_id": "retention_and_searchability",
                    "earliest": "-7d",
                    "latest": "now",
                },
            )

        self.assertEqual(analyst_response.status_code, 200)
        analyst_payload = analyst_response.json()
        self.assertEqual(analyst_payload["status"], "success")
        self.assertEqual(analyst_payload["pack"]["id"], "retention_and_searchability")
        self.assertEqual(analyst_payload["result"]["rows"][0]["index"], "main")
        self.assertEqual(analyst_payload["result"]["summary"]["sample_fields"], ["index", "retention_days", "retention_status"])

        self.assertEqual(len(captured_calls), 2)
        self.assertEqual(captured_calls[0]["runtime_url"], "https://mcp.example.com")
        self.assertEqual(captured_calls[1]["runtime_name"], "global")
        self.assertEqual(captured_calls[0]["payload"]["params"]["name"], "splunk_run_query")
        self.assertEqual(captured_calls[0]["payload"]["params"]["arguments"]["earliest_time"], "-14d")
        self.assertEqual(captured_calls[1]["payload"]["params"]["arguments"]["earliest_time"], "-7d")
        self.assertIn("| rest /services/data/indexes", captured_calls[0]["payload"]["params"]["arguments"]["query"])

        admin_relogin = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": admin_password},
        )
        self.assertEqual(admin_relogin.status_code, 200)

    def test_m26_14_validation_endpoint_reuses_cached_result_for_repeated_requests(self):
        self._enable_auth_and_complete_admin_reset()
        self._enable_m26_14_advisor()
        session_id = "20260526_120000"
        self._register_discovery_session_fixture(session_id)

        captured_calls = []

        def build_runtime_config(request=None):
            return SimpleNamespace(
                mcp=SimpleNamespace(url="https://mcp.example.com"),
                active_mcp_config_name="global",
            )

        async def stub_execute_mcp_tool_call(payload, runtime_config):
            captured_calls.append(
                {
                    "payload": copy.deepcopy(payload),
                    "runtime_url": getattr(runtime_config.mcp, "url", None),
                    "runtime_name": getattr(runtime_config, "active_mcp_config_name", None),
                }
            )
            return {
                "result": {
                    "structuredContent": {
                        "status_code": 200,
                        "results": [
                            {
                                "index": "main",
                                "retention_days": 400,
                                "retention_status": "meets_floor",
                            }
                        ],
                    }
                }
            }

        request_payload = {
            "pack_id": "retention_and_searchability",
            "timestamp": "latest",
            "earliest": "-14d",
            "latest": "now",
        }

        with patch.object(web_app, "resolve_effective_runtime_config", side_effect=build_runtime_config), patch.object(
            web_app,
            "execute_mcp_tool_call",
            new=AsyncMock(side_effect=stub_execute_mcp_tool_call),
        ):
            first_response = self.client.post("/api/discovery/m26-14/validate", json=request_payload)
            second_response = self.client.post("/api/discovery/m26-14/validate", json=request_payload)
            changed_range_response = self.client.post(
                "/api/discovery/m26-14/validate",
                json={**request_payload, "earliest": "-7d"},
            )

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(changed_range_response.status_code, 200)

        first_payload = first_response.json()
        second_payload = second_response.json()
        changed_range_payload = changed_range_response.json()

        self.assertFalse(first_payload["from_cache"])
        self.assertFalse(changed_range_payload["from_cache"])
        self.assertTrue(second_payload["from_cache"])
        self.assertEqual(first_payload["cache_key"], second_payload["cache_key"])
        self.assertNotEqual(first_payload["cache_key"], changed_range_payload["cache_key"])
        self.assertEqual(first_payload["cached_at"], second_payload["cached_at"])
        self.assertEqual(second_payload["result"], first_payload["result"])
        self.assertEqual(len(captured_calls), 2)
        self.assertEqual(captured_calls[0]["payload"]["params"]["arguments"]["earliest_time"], "-14d")
        self.assertEqual(captured_calls[1]["payload"]["params"]["arguments"]["earliest_time"], "-7d")

    def test_m26_14_validation_endpoint_returns_grounded_advisory_context(self):
        self._enable_auth_and_complete_admin_reset()
        self._enable_m26_14_advisor()
        session_id = "20260526_120000"
        self._register_discovery_session_fixture(session_id)

        def build_runtime_config(request=None):
            return SimpleNamespace(
                mcp=SimpleNamespace(url="https://mcp.example.com"),
                active_mcp_config_name="global",
            )

        async def stub_execute_mcp_tool_call(payload, runtime_config):
            return {
                "result": {
                    "structuredContent": {
                        "status_code": 200,
                        "results": [
                            {
                                "index": "main",
                                "retention_days": 400,
                                "retention_status": "meets_floor",
                            }
                        ],
                    }
                }
            }

        fake_profile_payload = {
            "has_data": True,
            "timestamp": session_id,
            "readiness_estimate": 78,
            "confidence": "medium",
            "maturity_floor": {"level": 3, "explanation": "Fixture floor"},
            "priority_objectives": {
                "thirf": {
                    "objective": "Threat Hunting, Investigation, and Response Findings",
                    "notes": ["Retention evidence is the current focus."],
                },
            },
            "maturity_elements": [
                {
                    "id": "data_retention",
                    "label": "Data Retention",
                    "gaps": ["Searchable retention needs confirmation for critical indexes."],
                    "remediation": ["Validate the highest-value indexes first."],
                },
            ],
            "source_summary": {
                "total_indexes": 4,
                "total_hosts": 12,
                "security_source_count": 3,
                "compliance_source_count": 1,
            },
            "live_validation": {
                "recommended_pack_ids": ["retention_and_searchability"],
            },
        }
        fake_rag_context = {
            "status": "ready",
            "provider": "rag_chromadb",
            "query": "M-26-14 advisory Retention and Searchability",
            "message": "Built context preview from indexed assets.",
            "context_text": "Knowledge asset context preview for retention review.",
            "operator_brief": "Use the retention runbook to compare frozen buckets against one-year expectations.",
            "chunks": [],
            "matched_assets": [],
            "reusable_spl_queries": [
                {
                    "title": "Known-good retention review",
                    "query": "| rest /services/data/indexes | table title frozenTimePeriodInSecs",
                    "why_reuse": "Previously validated against similar Splunk layouts.",
                    "environment_fit_status": "aligned",
                    "validation_status": "known_good",
                    "reuse_tier": "known_good",
                    "known_good": True,
                },
            ],
            "recommended_uses": ["Cross-check curated retention findings against the runbook baseline."],
            "coverage_gaps": ["No archived storage policy note was matched in indexed context."],
            "coverage_summary": {"asset_count": 1},
            "index_summary": {},
            "asset_summary": {},
        }
        fake_llm_client = SimpleNamespace(
            generate_response=AsyncMock(
                return_value=json.dumps(
                    {
                        "summary": "Retention settings currently look favorable for the sampled indexes, but searchable retention still needs confirmation.",
                        "environment_relevance": "This environment already shows enough indexed context to compare retention intent against prior operator guidance.",
                        "recommended_adjustments": [
                            "Confirm that the highest-value indexes preserve at least six months of immediately searchable history.",
                        ],
                        "suggested_follow_ups": [
                            "Review archived storage and thaw procedures for the affected indexes.",
                        ],
                        "evidence_gaps": [
                            "The result does not prove searchable retention duration for each critical data set.",
                        ],
                        "confidence_notes": [
                            "The advisory is grounded in one validation result and one retrieved knowledge asset.",
                        ],
                    }
                )
            )
        )

        with patch.object(web_app, "resolve_effective_runtime_config", side_effect=build_runtime_config), patch.object(
            web_app,
            "execute_mcp_tool_call",
            new=AsyncMock(side_effect=stub_execute_mcp_tool_call),
        ), patch.object(
            web_app,
            "build_m26_14_profile_payload",
            return_value=fake_profile_payload,
        ), patch.object(
            web_app,
            "_build_m26_14_rag_context_payload",
            return_value=fake_rag_context,
        ), patch.object(
            web_app,
            "_is_llm_available_for_m26_14_advisory",
            return_value=(True, ""),
        ), patch.object(
            web_app,
            "get_or_create_llm_client",
            return_value=fake_llm_client,
        ):
            response = self.client.post(
                "/api/discovery/m26-14/validate",
                json={
                    "pack_id": "retention_and_searchability",
                    "timestamp": "latest",
                    "earliest": "-14d",
                    "latest": "now",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("advisory", payload)
        self.assertEqual(payload["advisory"]["status"], "ready")
        self.assertTrue(payload["advisory"]["profile_snapshot"]["has_data"])
        self.assertEqual(payload["advisory"]["profile_snapshot"]["timestamp"], session_id)
        self.assertEqual(payload["advisory"]["rag_context"]["provider"], "rag_chromadb")
        self.assertEqual(payload["advisory"]["rag_context"]["reusable_spl_queries"][0]["title"], "Known-good retention review")
        self.assertEqual(payload["advisory"]["llm_analysis"]["status"], "ready")
        self.assertIn("Retention settings currently look favorable", payload["advisory"]["llm_analysis"]["summary"])
        self.assertEqual(
            payload["advisory"]["llm_analysis"]["recommended_adjustments"],
            ["Confirm that the highest-value indexes preserve at least six months of immediately searchable history."],
        )

    def test_discovery_status_endpoint_returns_runtime_snapshot(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_discovery_session = web_app.current_discovery_session
        fake_worker_pid = 424242

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.current_discovery_session = None
            web_app._update_discovery_runtime_state(
                status="running",
                session_id=4242,
                worker_pid=fake_worker_pid,
                execution_mode="worker",
                started_at="2026-05-18T08:15:00",
                completed_at=None,
                result_timestamp=None,
                report_count=0,
                error=None,
                progress={
                    "percentage": 42,
                    "current_step": 42,
                    "total_steps": 100,
                    "description": "Collecting evidence across the platform surface...",
                    "eta_seconds": 96,
                },
            )

            with patch.object(web_app, "_is_process_running", return_value=True):
                response = self.client.get("/api/discovery/status")

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["status"], "running")
            self.assertTrue(payload["is_active"])
            self.assertEqual(payload["session_id"], 4242)
            self.assertEqual(payload["worker_pid"], fake_worker_pid)
            self.assertEqual(payload["execution_mode"], "worker")
            self.assertEqual(payload["progress"]["percentage"], 42.0)
            self.assertEqual(payload["progress"]["description"], "Collecting evidence across the platform surface...")
            self.assertEqual(payload["progress"]["eta_seconds"], 96.0)
            self.assertIsNone(payload["progress"]["eta_method"])
            self.assertEqual(payload["started_at"], "2026-05-18T08:15:00")
            self.assertEqual(payload["phase_plan"], [])
            self.assertIsNone(payload["current_phase_title"])
            self.assertIsNone(payload["last_run_outcome"])
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.current_discovery_session = original_discovery_session

    def test_is_process_running_prefers_windows_probe_before_os_kill(self):
        with patch.object(web_app, "_is_process_running_windows", return_value=True) as windows_probe, \
             patch.object(web_app.os, "kill", side_effect=AssertionError("os.kill should not be used when the Windows probe succeeds")):
            self.assertTrue(web_app._is_process_running(424242))

        windows_probe.assert_called_once_with(424242)

    def test_start_discovery_primes_bootstrap_phase_as_active(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)
        original_discovery_session = web_app.current_discovery_session

        try:
            fake_worker_pid = 424242
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.summarization_progress = {}
            web_app.current_discovery_session = None

            with patch.object(web_app, "_launch_runtime_job_worker", return_value=SimpleNamespace(pid=fake_worker_pid)), \
                 patch.object(web_app, "_build_discovery_runtime_binding", return_value={}), \
                 patch.object(web_app, "_broadcast_discovery_runtime_state", new=AsyncMock()):
                response = self.client.post("/start-discovery")

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            discovery = payload["discovery"]
            self.assertEqual(discovery["status"], "starting")
            self.assertEqual(discovery["worker_pid"], fake_worker_pid)
            self.assertEqual(discovery["current_phase_key"], "pipeline_boot")
            self.assertEqual(discovery["current_phase_title"], "Bootstrap")
            self.assertGreater(len(discovery["phase_plan"]), 0)
            self.assertEqual(discovery["phase_plan"][0]["key"], "pipeline_boot")
            self.assertEqual(discovery["phase_plan"][0]["status"], "active")
            self.assertIsNotNone(discovery["phase_plan"][0]["started_at"])
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app.current_discovery_session = original_discovery_session
            web_app._persist_runtime_state()

    def test_start_discovery_isolated_by_mcp_scope(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)
        original_discovery_session = web_app.current_discovery_session

        try:
            self._enable_auth_and_complete_admin_reset()
            self.security_manager.create_user(
                username="analyst-a",
                password="AnalystPassword123!",
                role="analyst",
                is_enabled=True,
                require_password_reset=False,
                mcp_config_name="tenant-a",
            )
            self.security_manager.create_user(
                username="analyst-b",
                password="AnalystPassword123!",
                role="analyst",
                is_enabled=True,
                require_password_reset=False,
                mcp_config_name="tenant-a",
            )
            self.security_manager.create_user(
                username="analyst-c",
                password="AnalystPassword123!",
                role="analyst",
                is_enabled=True,
                require_password_reset=False,
                mcp_config_name="tenant-b",
            )

            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app.summarization_progress = {}
            web_app.current_discovery_session = None

            with patch.object(
                web_app,
                "_launch_runtime_job_worker",
                side_effect=[SimpleNamespace(pid=424242), SimpleNamespace(pid=525252)],
            ) as launch_worker, patch.object(web_app, "_broadcast_discovery_runtime_state", new=AsyncMock()), patch.object(web_app, "_is_process_running", return_value=True):
                self.client.cookies.clear()
                login_a = self.client.post(
                    "/api/auth/login",
                    json={"username": "analyst-a", "password": "AnalystPassword123!"},
                )
                self.assertEqual(login_a.status_code, 200)
                first_start = self.client.post("/start-discovery")

                self.client.cookies.clear()
                login_b = self.client.post(
                    "/api/auth/login",
                    json={"username": "analyst-b", "password": "AnalystPassword123!"},
                )
                self.assertEqual(login_b.status_code, 200)
                shared_scope_start = self.client.post("/start-discovery")

                self.client.cookies.clear()
                login_c = self.client.post(
                    "/api/auth/login",
                    json={"username": "analyst-c", "password": "AnalystPassword123!"},
                )
                self.assertEqual(login_c.status_code, 200)
                other_scope_start = self.client.post("/start-discovery")

            self.assertEqual(first_start.status_code, 200)
            self.assertEqual(first_start.json()["discovery"]["scope_key"], "mcp:tenant-a")
            self.assertEqual(first_start.json()["worker_pid"], 424242)

            self.assertEqual(shared_scope_start.status_code, 200)
            self.assertEqual(shared_scope_start.json()["error"], "Discovery already in progress")
            self.assertEqual(shared_scope_start.json()["discovery"]["scope_key"], "mcp:tenant-a")
            self.assertEqual(shared_scope_start.json()["discovery"]["worker_pid"], 424242)

            self.assertEqual(other_scope_start.status_code, 200)
            self.assertEqual(other_scope_start.json()["discovery"]["scope_key"], "mcp:tenant-b")
            self.assertEqual(other_scope_start.json()["worker_pid"], 525252)
            self.assertEqual(launch_worker.call_count, 2)
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app.current_discovery_session = original_discovery_session
            web_app._persist_runtime_state()

    def test_discovery_status_endpoint_isolated_by_mcp_scope(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))

        try:
            self._enable_auth_and_complete_admin_reset()
            self.security_manager.create_user(
                username="analyst-a",
                password="AnalystPassword123!",
                role="analyst",
                is_enabled=True,
                require_password_reset=False,
                mcp_config_name="tenant-a",
            )
            self.security_manager.create_user(
                username="analyst-b",
                password="AnalystPassword123!",
                role="analyst",
                is_enabled=True,
                require_password_reset=False,
                mcp_config_name="tenant-b",
            )

            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app._update_discovery_runtime_state(
                scope_key="mcp:tenant-a",
                scope_label="tenant-a",
                active_mcp_config_name="tenant-a",
                status="running",
                session_id=111,
                worker_pid=111,
                execution_mode="worker",
            )
            web_app._update_discovery_runtime_state(
                scope_key="mcp:tenant-b",
                scope_label="tenant-b",
                active_mcp_config_name="tenant-b",
                status="running",
                session_id=222,
                worker_pid=222,
                execution_mode="worker",
            )

            self.client.cookies.clear()
            login_a = self.client.post(
                "/api/auth/login",
                json={"username": "analyst-a", "password": "AnalystPassword123!"},
            )
            self.assertEqual(login_a.status_code, 200)
            with patch.object(web_app, "_is_process_running", return_value=True):
                status_a = self.client.get("/api/discovery/status")

            self.client.cookies.clear()
            login_b = self.client.post(
                "/api/auth/login",
                json={"username": "analyst-b", "password": "AnalystPassword123!"},
            )
            self.assertEqual(login_b.status_code, 200)
            with patch.object(web_app, "_is_process_running", return_value=True):
                status_b = self.client.get("/api/discovery/status")

            self.assertEqual(status_a.status_code, 200)
            self.assertEqual(status_a.json()["scope_key"], "mcp:tenant-a")
            self.assertEqual(status_a.json()["worker_pid"], 111)

            self.assertEqual(status_b.status_code, 200)
            self.assertEqual(status_b.json()["scope_key"], "mcp:tenant-b")
            self.assertEqual(status_b.json()["worker_pid"], 222)
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app._persist_runtime_state()

    def test_reports_and_latest_blueprint_are_filtered_by_mcp_scope(self):
        self._enable_auth_and_complete_admin_reset()
        self.security_manager.create_user(
            username="analyst-a",
            password="AnalystPassword123!",
            role="analyst",
            is_enabled=True,
            require_password_reset=False,
            mcp_config_name="tenant-a",
        )
        self.security_manager.create_user(
            username="analyst-b",
            password="AnalystPassword123!",
            role="analyst",
            is_enabled=True,
            require_password_reset=False,
            mcp_config_name="tenant-b",
        )

        timestamp = "20260522_010101"
        report_name = f"v2_intelligence_blueprint_{timestamp}.json"
        overview = SimpleNamespace(
            total_indexes=0,
            total_sourcetypes=0,
            total_hosts=0,
            total_users=0,
            data_volume_24h="unknown",
            splunk_version="unknown",
        )

        tenant_a_dir = web_app._discovery_scope_output_dir("mcp:tenant-a")
        tenant_b_dir = web_app._discovery_scope_output_dir("mcp:tenant-b")
        (tenant_a_dir / report_name).write_text(json.dumps({"marker": "tenant-a"}), encoding="utf-8")
        (tenant_b_dir / report_name).write_text(json.dumps({"marker": "tenant-b"}), encoding="utf-8")

        web_app.register_discovery_session(
            timestamp=timestamp,
            overview=overview,
            report_paths=[report_name],
            mcp_capabilities={"tool_count": 1, "tools": ["tenant-a"]},
            classifications={},
            recommendations=[],
            suggested_use_cases=[],
            discovery_step_count=1,
            discovery_scope={
                "scope_key": "mcp:tenant-a",
                "scope_label": "tenant-a",
                "active_mcp_config_name": "tenant-a",
            },
        )
        web_app.register_discovery_session(
            timestamp=timestamp,
            overview=overview,
            report_paths=[report_name],
            mcp_capabilities={"tool_count": 1, "tools": ["tenant-b"]},
            classifications={},
            recommendations=[],
            suggested_use_cases=[],
            discovery_step_count=1,
            discovery_scope={
                "scope_key": "mcp:tenant-b",
                "scope_label": "tenant-b",
                "active_mcp_config_name": "tenant-b",
            },
        )

        self.client.cookies.clear()
        login_a = self.client.post(
            "/api/auth/login",
            json={"username": "analyst-a", "password": "AnalystPassword123!"},
        )
        self.assertEqual(login_a.status_code, 200)
        reports_a = self.client.get("/reports")
        report_a = self.client.get(f"/reports/{report_name}")
        latest_a = self.client.get("/api/v2/intelligence")

        self.client.cookies.clear()
        login_b = self.client.post(
            "/api/auth/login",
            json={"username": "analyst-b", "password": "AnalystPassword123!"},
        )
        self.assertEqual(login_b.status_code, 200)
        reports_b = self.client.get("/reports")
        report_b = self.client.get(f"/reports/{report_name}")
        latest_b = self.client.get("/api/v2/intelligence")

        self.assertEqual(reports_a.status_code, 200)
        self.assertEqual(len(reports_a.json()["sessions"]), 1)
        self.assertEqual(reports_a.json()["sessions"][0]["scope_key"], "mcp:tenant-a")
        self.assertEqual(reports_a.json()["reports"][0]["name"], report_name)
        self.assertEqual(report_a.status_code, 200)
        self.assertEqual(report_a.json()["content"]["marker"], "tenant-a")
        self.assertEqual(latest_a.status_code, 200)
        self.assertEqual(latest_a.json()["blueprint"]["marker"], "tenant-a")

        self.assertEqual(reports_b.status_code, 200)
        self.assertEqual(len(reports_b.json()["sessions"]), 1)
        self.assertEqual(reports_b.json()["sessions"][0]["scope_key"], "mcp:tenant-b")
        self.assertEqual(reports_b.json()["reports"][0]["name"], report_name)
        self.assertEqual(report_b.status_code, 200)
        self.assertEqual(report_b.json()["content"]["marker"], "tenant-b")
        self.assertEqual(latest_b.status_code, 200)
        self.assertEqual(latest_b.json()["blueprint"]["marker"], "tenant-b")

    def test_discovery_status_endpoint_hydrates_persisted_worker_snapshot(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)
        fake_worker_pid = 424242

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.summarization_progress = {}
            web_app._update_discovery_runtime_state(
                status="running",
                session_id=5252,
                worker_pid=fake_worker_pid,
                execution_mode="worker",
                started_at="2026-05-18T10:15:00",
                progress={
                    "percentage": 33,
                    "current_step": 33,
                    "total_steps": 100,
                    "description": "Worker-backed discovery is collecting evidence.",
                },
            )

            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            with patch.object(web_app, "_is_process_running", return_value=True):
                response = self.client.get("/api/discovery/status")

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["status"], "running")
            self.assertEqual(payload["session_id"], 5252)
            self.assertEqual(payload["worker_pid"], fake_worker_pid)
            self.assertEqual(payload["execution_mode"], "worker")
            self.assertEqual(payload["progress"]["description"], "Worker-backed discovery is collecting evidence.")
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.summarization_progress = original_summarization_progress
            web_app._persist_runtime_state()

    def test_runtime_state_bridge_rebroadcasts_persisted_discovery_snapshot(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)
        original_active_connections = web_app.active_connections
        original_bridge_file_marker = web_app.runtime_state_bridge_last_file_marker
        original_bridge_signature = web_app.runtime_state_bridge_last_discovery_signature
        fake_worker_pid = 424242

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app.summarization_progress = {}
            web_app.active_connections = [object()]
            web_app._persist_runtime_state()
            web_app._remember_runtime_state_bridge_snapshot()

            web_app._update_discovery_runtime_state(
                status="running",
                session_id=4343,
                worker_pid=fake_worker_pid,
                execution_mode="worker",
                started_at="2026-05-18T11:30:00",
                progress={
                    "percentage": 57,
                    "current_step": 57,
                    "total_steps": 100,
                    "description": "Worker-backed discovery is collecting remote evidence.",
                },
            )

            with patch.object(web_app, "_is_runtime_worker_process", return_value=False), \
                 patch.object(web_app, "_is_process_running", return_value=True), \
                 patch.object(web_app, "_broadcast_discovery_runtime_state", new=AsyncMock()) as broadcast_mock:
                rebroadcasted = asyncio.run(web_app._check_for_persisted_runtime_state_rebroadcast(force=True))

            self.assertTrue(rebroadcasted)
            broadcast_mock.assert_awaited_once_with(scope_key=web_app.DISCOVERY_SCOPE_GLOBAL)
            snapshot = web_app._snapshot_discovery_runtime_state(web_app.DISCOVERY_SCOPE_GLOBAL)
            self.assertEqual(snapshot["status"], "running")
            self.assertEqual(snapshot["session_id"], 4343)
            self.assertEqual(snapshot["worker_pid"], fake_worker_pid)
            self.assertEqual(snapshot["execution_mode"], "worker")
            self.assertEqual(snapshot["progress"]["description"], "Worker-backed discovery is collecting remote evidence.")
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app.active_connections = original_active_connections
            web_app.runtime_state_bridge_last_file_marker = original_bridge_file_marker
            web_app.runtime_state_bridge_last_discovery_signature = original_bridge_signature
            web_app._persist_runtime_state()

    def test_summarize_progress_endpoint_hydrates_persisted_worker_snapshot(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)
        fake_worker_pid = 424242

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app.summarization_progress = {}
            session_id = "20260518_101500"
            self._register_discovery_session_fixture(session_id)
            web_app._set_summarization_progress(
                session_id,
                stage="ai_analysis",
                progress=65,
                message="Worker-backed summary analysis is in progress.",
                worker_pid=fake_worker_pid,
                execution_mode="worker",
            )

            web_app.summarization_progress = {}
            with patch.object(web_app, "_is_process_running", return_value=True):
                response = self.client.get(f"/summarize-progress/{session_id}")

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["stage"], "ai_analysis")
            self.assertEqual(payload["progress"], 65)
            self.assertEqual(payload["worker_pid"], fake_worker_pid)
            self.assertEqual(payload["execution_mode"], "worker")
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app._persist_runtime_state()

    def test_abort_summary_endpoint_stops_active_worker(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)
        fake_worker_pid = 424242

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app.summarization_progress = {}
            session_id = "20260518_103000"
            self._register_discovery_session_fixture(session_id)
            web_app._set_summarization_progress(
                session_id,
                stage="ai_analysis",
                progress=65,
                message="Worker-backed summary analysis is in progress.",
                worker_pid=fake_worker_pid,
                execution_mode="worker",
            )

            with patch.object(web_app, "_is_process_running", return_value=True), \
                 patch.object(web_app, "_terminate_runtime_worker_process", return_value=True):
                response = self.client.post(
                    "/abort-summary",
                    json={"timestamp": session_id},
                )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["status"], "aborted")
            self.assertEqual(payload["progress"]["stage"], "aborted")
            self.assertIn("aborted by operator", payload["progress"]["message"].lower())
            self.assertIsNone(payload["progress"]["worker_pid"])
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app._persist_runtime_state()

    def test_summarize_session_reuses_active_worker_without_spawning_new_one(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app.summarization_progress = {}
            session_id = "20260518_104500"
            self._register_discovery_session_fixture(session_id)
            expected_payload = {
                "success": True,
                "session_id": session_id,
                "from_cache": False,
                "reused_worker": True,
            }
            web_app._set_summarization_progress(
                session_id,
                stage="ai_analysis",
                progress=72,
                message="Worker-backed summary analysis is already running.",
                worker_pid=424242,
                execution_mode="worker",
            )

            with patch.object(web_app, "_is_runtime_worker_process", return_value=False), \
                 patch.object(web_app, "_load_cached_summary_if_available", return_value=None), \
                 patch.object(web_app, "_is_process_running", return_value=True), \
                 patch.object(web_app, "_launch_runtime_job_worker") as launch_worker_mock, \
                 patch.object(web_app, "_wait_for_summary_result", new=AsyncMock(return_value=expected_payload)) as wait_mock:
                response = self.client.post(
                    "/summarize-session",
                    json={"timestamp": session_id},
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), expected_payload)
            launch_worker_mock.assert_not_called()
            wait_mock.assert_awaited_once_with(session_id, scope_key=web_app.DISCOVERY_SCOPE_GLOBAL)
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app._persist_runtime_state()

    def test_markdown_section_extraction_accepts_numbered_summary_headings(self):
        summary_text = """## 1) Executive Summary
Environment summary.

## 2) Priority Actions
1. **Build** a health dashboard
2. Validate SNMP coverage

## 3) Quick Wins
- **Create** a coverage dashboard
- Add storage tracking
"""

        self.assertEqual(
            web_app._extract_markdown_section_items(summary_text, "Priority Actions", max_items=4),
            ["Build a health dashboard", "Validate SNMP coverage"],
        )
        self.assertEqual(
            web_app._extract_markdown_section_items(summary_text, "Quick Wins", max_items=4),
            ["Create a coverage dashboard", "Add storage tracking"],
        )

    def test_runtime_state_persistence_restores_interrupted_runtime_jobs(self):
        original_runtime_state = copy.deepcopy(web_app.discovery_runtime_state)
        original_runtime_states = copy.deepcopy(getattr(web_app, "discovery_runtime_states", {}))
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)

        try:
            web_app.discovery_runtime_state = web_app._build_discovery_runtime_state()
            web_app.discovery_runtime_states = {web_app.DISCOVERY_SCOPE_GLOBAL: web_app.discovery_runtime_state}
            web_app.summarization_progress = {}

            phase_plan = web_app._build_discovery_phase_plan("v2")
            phase_plan[2]["status"] = "active"
            phase_plan[2]["title"] = "Evidence Collection"
            phase_plan[2]["started_at"] = "2026-05-18T08:15:00"

            web_app._update_discovery_runtime_state(
                status="running",
                session_id=4242,
                started_at="2026-05-18T08:10:00",
                current_phase_key="evidence_collection",
                current_phase_title="Evidence Collection",
                phase_plan=phase_plan,
                progress={
                    "percentage": 42,
                    "current_step": 42,
                    "total_steps": 100,
                    "description": "Collecting evidence across the platform surface...",
                },
            )
            web_app._set_summarization_progress(
                "20260518_081500",
                stage="ai_analysis",
                progress=65,
                message="AI analyzing findings (this may take 1-3 minutes)...",
            )

            self.assertTrue(web_app._runtime_state_store_path().exists())

            with patch.object(web_app, "_is_runtime_worker_process", return_value=False):
                restored_discovery_states, restored_summarization = web_app._load_persisted_runtime_state()
            restored_discovery = restored_discovery_states[web_app.DISCOVERY_SCOPE_GLOBAL]

            self.assertEqual(restored_discovery["status"], "interrupted")
            self.assertEqual(restored_discovery["current_phase_title"], "Evidence Collection")
            self.assertIn("restarted", restored_discovery["error"].lower())
            self.assertEqual(restored_discovery["last_run_outcome"]["status"], "interrupted")

            summary_entry = restored_summarization["20260518_081500"]
            self.assertEqual(summary_entry["stage"], "interrupted")
            self.assertEqual(summary_entry["progress"], 65)
            self.assertIn("re-run summarization", summary_entry["message"].lower())
        finally:
            web_app.discovery_runtime_state = original_runtime_state
            web_app.discovery_runtime_states = original_runtime_states
            web_app.summarization_progress = original_summarization_progress
            web_app._persist_runtime_state()

    def test_runtime_state_restore_marks_saved_summary_complete_after_restart(self):
        original_summarization_progress = copy.deepcopy(web_app.summarization_progress)

        try:
            web_app.summarization_progress = {}
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)
            session_id = "20260518_091500"
            summary_path = output_dir / f"v2_ai_summary_{session_id}.json"
            summary_path.write_text(json.dumps({"schema_version": "2.0"}), encoding="utf-8")

            web_app._set_summarization_progress(
                session_id,
                stage="creating_summary",
                progress=82,
                message="AI creating executive summary (30-60 seconds)...",
            )

            _, restored_summarization = web_app._load_persisted_runtime_state()
            summary_entry = restored_summarization[session_id]

            self.assertEqual(summary_entry["stage"], "complete")
            self.assertEqual(summary_entry["progress"], 100)
            self.assertIn("saved artifacts", summary_entry["message"].lower())
        finally:
            web_app.summarization_progress = original_summarization_progress
            web_app._persist_runtime_state()

    def test_oidc_config_can_be_enabled_when_ready(self):
        stage_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_provider": "oidc",
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "audience": "dt4sms-api",
                        "scopes": ["openid", "profile", "email", "groups"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                        "mcp_assignment_claim": "splunk_tenant",
                    },
                }
            },
        )
        self.assertEqual(stage_oidc.status_code, 200)

        config_response = self.client.get("/api/config")
        self.assertEqual(config_response.status_code, 200)
        security = config_response.json()["security"]
        self.assertEqual(security["auth_provider"], "oidc")
        self.assertEqual(security["oidc"]["issuer_url"], "https://idp.example.com/application/o/dt4sms/")
        self.assertEqual(security["oidc"]["client_secret"], "***")
        self.assertTrue(security["oidc"]["client_secret_configured"])

        status = self.client.get("/api/auth/status")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["auth_provider"], "oidc")
        self.assertTrue(status.json()["demo_mode"])
        self.assertTrue(status.json()["auth_provider_status"]["oidc"]["implemented"])
        self.assertTrue(status.json()["auth_provider_status"]["oidc"]["configured"])
        self.assertTrue(status.json()["auth_provider_status"]["oidc"]["ready"])
        self.assertTrue(status.json()["auth_provider_status"]["oidc"]["can_enable_auth"])

        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        enabled_status = self.client.get("/api/auth/status")
        self.assertEqual(enabled_status.status_code, 200)
        self.assertTrue(enabled_status.json()["auth_enabled"])
        self.assertEqual(enabled_status.json()["auth_provider"], "oidc")

    def test_oidc_callback_flow_provisions_session_backed_user(self):
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-a",
                url="https://tenant-a.example.com/mcp",
                token="token-a",
                verify_ssl=True,
                description="Tenant A",
            )
        )

        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email", "groups"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                        "mcp_assignment_claim": "splunk_tenant",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        landing = self.client.get("/")
        self.assertEqual(landing.status_code, 200)
        self.assertIn("Sign In With OpenID Connect", landing.text)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        private_key, jwk = _build_test_rs256_signing_material()

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "demo-code")
            self.assertIn("/api/auth/oidc/callback", redirect_uri)
            return {
                "access_token": "stub-access-token",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-123",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    }
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token")
            return {
                "sub": "oidc-subject-123",
                "preferred_username": "oidc-analyst",
                "email": "oidc-analyst@example.com",
                "roles": ["analyst"],
                "splunk_tenant": "tenant-a",
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_target = urlparse(start.headers["location"])
            self.assertEqual(redirect_target.scheme, "https")
            self.assertEqual(redirect_target.netloc, "idp.example.com")
            redirect_query = parse_qs(redirect_target.query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=demo-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)
            self.assertEqual(callback.headers["location"], "/")

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["username"], "oidc-analyst")
            self.assertEqual(auth_status.json()["user"]["role"], "analyst")
            self.assertEqual(auth_status.json()["user"]["mcp_config_name"], "tenant-a")
            self.assertFalse(auth_status.json()["password_reset_required"])

            oidc_identity = self.security_manager.get_external_identity("oidc", "oidc-subject-123")
            self.assertIsNotNone(oidc_identity)
            self.assertEqual(oidc_identity["user"]["username"], "oidc-analyst")

            authenticated_config = self.client.get("/api/config")
            self.assertEqual(authenticated_config.status_code, 403)

            reset_attempt = self.client.post(
                "/api/auth/reset-password",
                json={
                    "current_password": "irrelevant",
                    "new_password": "NewPassword123!",
                    "confirm_password": "NewPassword123!",
                },
            )
            self.assertEqual(reset_attempt.status_code, 400)
            self.assertIn("local-password authentication", reset_attempt.json()["detail"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_reuses_cached_jwks_across_repeated_sign_ins(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        jwks_loads = {"count": 0}
        private_key, jwk = _build_test_rs256_signing_material()

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            jwks_loads["count"] += 1
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "jwks-cache")
            return {
                "access_token": "stub-access-token-jwks-cache",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-jwks-cache",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    }
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-jwks-cache")
            return {
                "sub": "oidc-subject-jwks-cache",
                "preferred_username": "oidc-jwks-cache",
                "email": "oidc-jwks-cache@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            for _ in range(2):
                start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
                self.assertEqual(start.status_code, 303)
                redirect_query = parse_qs(urlparse(start.headers["location"]).query)
                oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
                state = redirect_query["state"][0]

                callback = self.client.get(f"/api/auth/oidc/callback?code=jwks-cache&state={state}", follow_redirects=False)
                self.assertEqual(callback.status_code, 303)

                auth_status = self.client.get("/api/auth/status")
                self.assertEqual(auth_status.status_code, 200)
                self.assertTrue(auth_status.json()["authenticated"])

                logout = self.client.post("/api/auth/logout")
                self.assertEqual(logout.status_code, 200)

            self.assertEqual(jwks_loads["count"], 1)
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_refreshes_cached_jwks_after_signing_key_rotation(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        jwks_loads = {"count": 0}
        first_private_key, first_jwk = _build_test_rs256_signing_material(kid="initial-signing-key")
        second_private_key, second_jwk = _build_test_rs256_signing_material(kid="rotated-signing-key")

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            jwks_loads["count"] += 1
            if jwks_loads["count"] == 1:
                return {"keys": [first_jwk]}
            return {"keys": [second_jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            token_payload = {
                "iss": "https://idp.example.com/application/o/dt4sms/",
                "sub": "oidc-subject-jwks-rotation",
                "aud": "dt4sms-client",
                "exp": int(time.time()) + 300,
                "iat": int(time.time()),
                "nonce": oidc_runtime_context["nonce"],
            }
            if code == "initial-login":
                return {
                    "access_token": "stub-access-token-jwks-rotation",
                    "token_type": "Bearer",
                    "id_token": _build_test_signed_id_token(first_private_key, token_payload, kid="initial-signing-key"),
                }

            self.assertEqual(code, "rotated-login")
            return {
                "access_token": "stub-access-token-jwks-rotation",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(second_private_key, token_payload, kid="rotated-signing-key"),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-jwks-rotation")
            return {
                "sub": "oidc-subject-jwks-rotation",
                "preferred_username": "oidc-jwks-rotation",
                "email": "oidc-jwks-rotation@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            first_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(first_start.status_code, 303)
            first_redirect_query = parse_qs(urlparse(first_start.headers["location"]).query)
            oidc_runtime_context["nonce"] = first_redirect_query["nonce"][0]
            first_state = first_redirect_query["state"][0]

            first_callback = self.client.get(f"/api/auth/oidc/callback?code=initial-login&state={first_state}", follow_redirects=False)
            self.assertEqual(first_callback.status_code, 303)

            logout = self.client.post("/api/auth/logout")
            self.assertEqual(logout.status_code, 200)

            second_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(second_start.status_code, 303)
            second_redirect_query = parse_qs(urlparse(second_start.headers["location"]).query)
            oidc_runtime_context["nonce"] = second_redirect_query["nonce"][0]
            second_state = second_redirect_query["state"][0]

            second_callback = self.client.get(f"/api/auth/oidc/callback?code=rotated-login&state={second_state}", follow_redirects=False)
            self.assertEqual(second_callback.status_code, 303)

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(jwks_loads["count"], 2)
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_ignores_non_verify_jwks_keys_without_use(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        signing_private_key, signing_jwk = _build_test_rs256_signing_material(kid="signing-key")
        _, non_verify_jwk = _build_test_rs256_signing_material(kid="encrypt-only-key")
        non_verify_jwk.pop("use", None)
        non_verify_jwk["key_ops"] = ["encrypt"]

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [signing_jwk, non_verify_jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "key-ops-filter")
            return {
                "access_token": "stub-access-token-key-ops",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    signing_private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-key-ops",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    },
                    kid="",
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-key-ops")
            return {
                "sub": "oidc-subject-key-ops",
                "preferred_username": "oidc-key-ops-user",
                "email": "oidc-key-ops-user@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=key-ops-filter&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["username"], "oidc-key-ops-user")
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_accepts_ps256_signed_id_token(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        private_key, jwk = _build_test_rs256_signing_material(algorithm="PS256")

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "ps256-code")
            return {
                "access_token": "stub-access-token-ps256",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-ps256",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    },
                    algorithm="PS256",
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-ps256")
            return {
                "sub": "oidc-subject-ps256",
                "preferred_username": "oidc-ps256-user",
                "email": "oidc-ps256-user@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=ps256-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)
            self.assertEqual(callback.headers["location"], "/")

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["username"], "oidc-ps256-user")
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_accepts_es256_signed_id_token(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        private_key, jwk = _build_test_es_signing_material(algorithm="ES256")

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "es256-code")
            return {
                "access_token": "stub-access-token-es256",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-es256",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    },
                    algorithm="ES256",
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-es256")
            return {
                "sub": "oidc-subject-es256",
                "preferred_username": "oidc-es256-user",
                "email": "oidc-es256-user@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=es256-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)
            self.assertEqual(callback.headers["location"], "/")

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["username"], "oidc-es256-user")
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_accepts_eddsa_signed_id_token(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        private_key, jwk = _build_test_eddsa_signing_material(curve_name="Ed25519")

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "eddsa-code")
            return {
                "access_token": "stub-access-token-eddsa",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-eddsa",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    },
                    algorithm="EdDSA",
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-eddsa")
            return {
                "sub": "oidc-subject-eddsa",
                "preferred_username": "oidc-eddsa-user",
                "email": "oidc-eddsa-user@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=eddsa-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)
            self.assertEqual(callback.headers["location"], "/")

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["username"], "oidc-eddsa-user")
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_encrypted_id_token_before_jwks_or_userinfo(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            self.fail("jwks should not be loaded when the id_token is encrypted")

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "encrypted-id-token")
            return {
                "access_token": "stub-access-token-encrypted-id-token",
                "token_type": "Bearer",
                "id_token": ".".join(
                    [
                        _b64url_encode_bytes(b'{"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT"}'),
                        _b64url_encode_bytes(b"encrypted-key"),
                        _b64url_encode_bytes(b"initialization-vector"),
                        _b64url_encode_bytes(b"ciphertext"),
                        _b64url_encode_bytes(b"auth-tag"),
                    ]
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.fail("userinfo should not be called when the id_token is encrypted")

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=encrypted-id-token&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("encrypted", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_symmetric_id_token_before_jwks_or_userinfo(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            self.fail("jwks should not be loaded when the id_token uses a symmetric algorithm")

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            self.assertEqual(code, "hs256-id-token")
            header_segment = _b64url_encode_bytes(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
            body_segment = _b64url_encode_bytes(
                json.dumps(
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-hs256",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    }
                ).encode("utf-8")
            )
            signature_segment = _b64url_encode_bytes(b"not-a-real-hmac")
            return {
                "access_token": "stub-access-token-hs256",
                "token_type": "Bearer",
                "id_token": f"{header_segment}.{body_segment}.{signature_segment}",
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.fail("userinfo should not be called when the id_token uses a symmetric algorithm")

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=hs256-id-token&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("symmetric", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_logout_returns_provider_logout_guidance_when_supported(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "end_session_endpoint": "https://idp.example.com/oauth2/logout",
            }

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {"access_token": "stub-access-token-logout"}

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-logout")
            return {
                "sub": "oidc-subject-logout",
                "preferred_username": "oidc-logout-user",
                "email": "oidc-logout-user@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=logout-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)

            logout = self.client.post("/api/auth/logout")
            self.assertEqual(logout.status_code, 200)
            logout_payload = logout.json()
            self.assertEqual(logout_payload["status"], "success")
            self.assertEqual(logout_payload["provider_logout"]["provider"], "oidc")
            self.assertTrue(logout_payload["provider_logout"]["supported"])
            self.assertEqual(logout_payload["provider_logout"]["mode"], "front_channel_redirect")

            logout_target = urlparse(logout_payload["provider_logout"]["url"])
            self.assertEqual(logout_target.scheme, "https")
            self.assertEqual(logout_target.netloc, "idp.example.com")
            logout_query = parse_qs(logout_target.query)
            self.assertEqual(logout_query["client_id"], ["dt4sms-client"])
            self.assertEqual(logout_query["post_logout_redirect_uri"], ["http://testserver/"])

            protected_after_logout = self.client.get("/api/config")
            self.assertEqual(protected_after_logout.status_code, 401)
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_unsupported_token_type(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
            }

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {"access_token": "stub-access-token-invalid", "token_type": "mac"}

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.fail("userinfo should not be called when token_type is unsupported")

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=invalid-token-type&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("unsupported token type", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_id_token_with_mismatched_nonce(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        private_key, jwk = _build_test_rs256_signing_material()

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {
                "access_token": "stub-access-token-id-token",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-id-token",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": "wrong-nonce",
                    }
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.fail("userinfo should not be called when the id_token nonce does not match")

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            self.assertIn("nonce", redirect_query)

            state = redirect_query["state"][0]
            callback = self.client.get(f"/api/auth/oidc/callback?code=nonce-mismatch&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("nonce", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_unsecured_id_token_algorithm(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            self.fail("jwks should not be loaded when the id_token uses an unsecured algorithm")

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {
                "access_token": "stub-access-token-unsecured-id-token",
                "token_type": "Bearer",
                "id_token": _build_unsigned_id_token(
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-unsecured",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    }
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.fail("userinfo should not be called when the id_token uses an unsecured algorithm")

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=alg-none&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("signing algorithm", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_id_token_with_invalid_signature(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        signing_private_key, _ = _build_test_rs256_signing_material()
        _, verification_jwk = _build_test_rs256_signing_material()

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [verification_jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {
                "access_token": "stub-access-token-invalid-signature",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    signing_private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-invalid-signature",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    }
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.fail("userinfo should not be called when the id_token signature does not match the JWKS")

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=invalid-signature&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("signature validation failed", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_rejects_userinfo_subject_mismatch_with_id_token(self):
        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_load_jwks = getattr(web_app, "load_oidc_provider_jwks", None)
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo
        oidc_runtime_context = {}
        private_key, jwk = _build_test_rs256_signing_material()

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
                "jwks_uri": "https://idp.example.com/oauth2/keys",
            }

        async def stub_load_jwks(provider_metadata):
            return {"keys": [jwk]}

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {
                "access_token": "stub-access-token-subject-mismatch",
                "token_type": "Bearer",
                "id_token": _build_test_signed_id_token(
                    private_key,
                    {
                        "iss": "https://idp.example.com/application/o/dt4sms/",
                        "sub": "oidc-subject-from-id-token",
                        "aud": "dt4sms-client",
                        "exp": int(time.time()) + 300,
                        "iat": int(time.time()),
                        "nonce": oidc_runtime_context["nonce"],
                    }
                ),
            }

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-subject-mismatch")
            return {
                "sub": "oidc-subject-from-userinfo",
                "preferred_username": "oidc-subject-mismatch",
                "email": "oidc-subject-mismatch@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.load_oidc_provider_jwks = stub_load_jwks
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            redirect_query = parse_qs(urlparse(start.headers["location"]).query)
            oidc_runtime_context["nonce"] = redirect_query["nonce"][0]
            state = redirect_query["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=subject-mismatch&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 400)
            self.assertIn("subject", callback.text.lower())

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["authenticated"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.load_oidc_provider_jwks = original_load_jwks
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_relogin_without_explicit_claims_preserves_existing_role_and_assignment(self):
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-a",
                url="https://tenant-a.example.com/mcp",
                token="token-a",
                verify_ssl=True,
                description="Tenant A",
            )
        )

        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                        "mcp_assignment_claim": "splunk_tenant",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
            }

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {"access_token": f"stub-access-token-{code}"}

        userinfo_payloads = [
            {
                "sub": "oidc-subject-preserve",
                "preferred_username": "oidc-preserve",
                "email": "oidc-preserve@example.com",
                "roles": ["analyst"],
                "splunk_tenant": "tenant-a",
            },
            {
                "sub": "oidc-subject-preserve",
                "preferred_username": "oidc-preserve",
                "email": "oidc-preserve@example.com",
            },
        ]

        async def stub_fetch_userinfo(provider_metadata, access_token):
            return userinfo_payloads.pop(0)

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            first_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            first_state = parse_qs(urlparse(first_start.headers["location"]).query)["state"][0]
            first_callback = self.client.get(f"/api/auth/oidc/callback?code=first-code&state={first_state}", follow_redirects=False)
            self.assertEqual(first_callback.status_code, 303)

            first_status = self.client.get("/api/auth/status")
            self.assertEqual(first_status.status_code, 200)
            self.assertEqual(first_status.json()["user"]["role"], "analyst")
            self.assertEqual(first_status.json()["user"]["mcp_config_name"], "tenant-a")

            self.client.post("/api/auth/logout")

            second_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            second_state = parse_qs(urlparse(second_start.headers["location"]).query)["state"][0]
            second_callback = self.client.get(f"/api/auth/oidc/callback?code=second-code&state={second_state}", follow_redirects=False)
            self.assertEqual(second_callback.status_code, 303)

            second_status = self.client.get("/api/auth/status")
            self.assertEqual(second_status.status_code, 200)
            self.assertEqual(second_status.json()["user"]["role"], "analyst")
            self.assertEqual(second_status.json()["user"]["mcp_config_name"], "tenant-a")
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_relogin_with_empty_or_unsupported_claims_preserves_existing_role_and_assignment(self):
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-a",
                url="https://tenant-a.example.com/mcp",
                token="token-a",
                verify_ssl=True,
                description="Tenant A",
            )
        )

        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                        "mcp_assignment_claim": "splunk_tenant",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
            }

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {"access_token": f"stub-access-token-{code}"}

        userinfo_payloads = [
            {
                "sub": "oidc-subject-policy",
                "preferred_username": "oidc-policy-user",
                "email": "oidc-policy-user@example.com",
                "roles": ["analyst"],
                "splunk_tenant": "tenant-a",
            },
            {
                "sub": "oidc-subject-policy",
                "preferred_username": "oidc-policy-user",
                "email": "oidc-policy-user@example.com",
                "roles": [],
                "splunk_tenant": "tenant-missing",
            },
            {
                "sub": "oidc-subject-policy",
                "preferred_username": "oidc-policy-user",
                "email": "oidc-policy-user@example.com",
                "roles": ["super-admin"],
                "splunk_tenant": "",
            },
        ]

        async def stub_fetch_userinfo(provider_metadata, access_token):
            return userinfo_payloads.pop(0)

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            first_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            first_state = parse_qs(urlparse(first_start.headers["location"]).query)["state"][0]
            first_callback = self.client.get(f"/api/auth/oidc/callback?code=first-code&state={first_state}", follow_redirects=False)
            self.assertEqual(first_callback.status_code, 303)

            first_status = self.client.get("/api/auth/status")
            self.assertEqual(first_status.status_code, 200)
            self.assertEqual(first_status.json()["user"]["role"], "analyst")
            self.assertEqual(first_status.json()["user"]["mcp_config_name"], "tenant-a")

            self.client.post("/api/auth/logout")

            second_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            second_state = parse_qs(urlparse(second_start.headers["location"]).query)["state"][0]
            second_callback = self.client.get(f"/api/auth/oidc/callback?code=second-code&state={second_state}", follow_redirects=False)
            self.assertEqual(second_callback.status_code, 303)

            second_status = self.client.get("/api/auth/status")
            self.assertEqual(second_status.status_code, 200)
            self.assertEqual(second_status.json()["user"]["role"], "analyst")
            self.assertEqual(second_status.json()["user"]["mcp_config_name"], "tenant-a")

            self.client.post("/api/auth/logout")

            third_start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            third_state = parse_qs(urlparse(third_start.headers["location"]).query)["state"][0]
            third_callback = self.client.get(f"/api/auth/oidc/callback?code=third-code&state={third_state}", follow_redirects=False)
            self.assertEqual(third_callback.status_code, 303)

            third_status = self.client.get("/api/auth/status")
            self.assertEqual(third_status.status_code, 200)
            self.assertEqual(third_status.json()["user"]["role"], "analyst")
            self.assertEqual(third_status.json()["user"]["mcp_config_name"], "tenant-a")
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_oidc_callback_username_collision_provisions_distinct_external_user(self):
        existing_local_user = self.security_manager.create_user(
            username="oidc-analyst",
            password="ExistingPassword123!",
            role="admin",
            require_password_reset=False,
        )

        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                        "mcp_assignment_claim": "splunk_tenant",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
            }

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {"access_token": "stub-access-token-collision"}

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-collision")
            return {
                "sub": "oidc-subject-collision",
                "preferred_username": "oidc-analyst",
                "email": "oidc-analyst@example.com",
                "roles": ["viewer"],
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=collision-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["username"], "oidc-analyst-2")
            self.assertEqual(auth_status.json()["user"]["role"], "viewer")

            preserved_local_user = self.security_manager.get_user_by_id(int(existing_local_user["id"]))
            self.assertIsNotNone(preserved_local_user)
            self.assertEqual(preserved_local_user["username"], "oidc-analyst")
            self.assertEqual(preserved_local_user["role"], "admin")

            oidc_identity = self.security_manager.get_external_identity("oidc", "oidc-subject-collision")
            self.assertIsNotNone(oidc_identity)
            self.assertEqual(oidc_identity["user"]["username"], "oidc-analyst-2")
            self.assertNotEqual(oidc_identity["user_id"], int(existing_local_user["id"]))
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_admin_can_link_local_user_to_oidc_identity_before_callback_login(self):
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-a",
                url="https://tenant-a.example.com/mcp",
                token="token-a",
                verify_ssl=True,
                description="Tenant A",
            )
        )

        admin_password = self._enable_auth_and_complete_admin_reset()

        create_user = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst1",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
                "mcp_config_name": "tenant-a",
            },
        )
        self.assertEqual(create_user.status_code, 200)
        local_user = create_user.json()["user"]

        link_response = self.client.post(
            f"/api/security/users/{local_user['id']}/external-identities",
            json={
                "auth_provider": "oidc",
                "subject": "oidc-subject-linked",
                "email": "analyst1@example.com",
                "claims": {"sub": "oidc-subject-linked", "preferred_username": "analyst1"},
            },
        )
        self.assertEqual(link_response.status_code, 200)
        self.assertEqual(link_response.json()["user"]["id"], local_user["id"])
        self.assertEqual(link_response.json()["external_identity"]["subject"], "oidc-subject-linked")

        enable_oidc = self.client.post(
            "/api/config",
            json={
                "security": {
                    "auth_enabled": True,
                    "auth_provider": "oidc",
                    "session_timeout_minutes": 60,
                    "oidc": {
                        "issuer_url": "https://idp.example.com/application/o/dt4sms/",
                        "client_id": "dt4sms-client",
                        "client_secret": "oidc-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "username_claim": "preferred_username",
                        "email_claim": "email",
                        "role_claim": "roles",
                        "default_role": "viewer",
                        "mcp_assignment_claim": "splunk_tenant",
                    },
                }
            },
        )
        self.assertEqual(enable_oidc.status_code, 200)

        self.client.post("/api/auth/logout")

        original_load_metadata = web_app.load_oidc_provider_metadata
        original_exchange_code = web_app.exchange_oidc_authorization_code
        original_fetch_userinfo = web_app.fetch_oidc_userinfo

        async def stub_load_metadata(oidc_settings):
            return {
                "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
                "token_endpoint": "https://idp.example.com/oauth2/token",
                "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
            }

        async def stub_exchange_code(oidc_settings, provider_metadata, code, redirect_uri):
            return {"access_token": "stub-access-token-linked"}

        async def stub_fetch_userinfo(provider_metadata, access_token):
            self.assertEqual(access_token, "stub-access-token-linked")
            return {
                "sub": "oidc-subject-linked",
                "preferred_username": "analyst1",
                "email": "analyst1@example.com",
                "roles": ["admin"],
                "splunk_tenant": "tenant-a",
            }

        web_app.load_oidc_provider_metadata = stub_load_metadata
        web_app.exchange_oidc_authorization_code = stub_exchange_code
        web_app.fetch_oidc_userinfo = stub_fetch_userinfo
        try:
            start = self.client.get("/api/auth/oidc/start", follow_redirects=False)
            self.assertEqual(start.status_code, 303)
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

            callback = self.client.get(f"/api/auth/oidc/callback?code=linked-code&state={state}", follow_redirects=False)
            self.assertEqual(callback.status_code, 303)

            auth_status = self.client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertTrue(auth_status.json()["authenticated"])
            self.assertEqual(auth_status.json()["user"]["id"], local_user["id"])
            self.assertEqual(auth_status.json()["user"]["username"], "analyst1")
            self.assertEqual(auth_status.json()["user"]["role"], "admin")
            self.assertEqual(auth_status.json()["user"]["mcp_config_name"], "tenant-a")

            linked_identity = self.security_manager.get_external_identity("oidc", "oidc-subject-linked")
            self.assertIsNotNone(linked_identity)
            self.assertEqual(linked_identity["user_id"], local_user["id"])
        finally:
            web_app.load_oidc_provider_metadata = original_load_metadata
            web_app.exchange_oidc_authorization_code = original_exchange_code
            web_app.fetch_oidc_userinfo = original_fetch_userinfo

    def test_auth_enabled_requires_login_then_password_reset_before_normal_access(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))

        landing = self.client.get("/")
        self.assertEqual(landing.status_code, 200)
        self.assertIn("DT4SMS Sign In", landing.text)

        status = self.client.get("/api/auth/status")
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.json()["auth_enabled"])
        self.assertFalse(status.json()["authenticated"])

        protected = self.client.get("/api/config")
        self.assertEqual(protected.status_code, 401)

        login = self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.json()["password_reset_required"])

        blocked_until_reset = self.client.get("/api/config")
        self.assertEqual(blocked_until_reset.status_code, 403)

        reset = self.client.post(
            "/api/auth/reset-password",
            json={
                "current_password": "password",
                "new_password": "BetterPassword123!",
                "confirm_password": "BetterPassword123!",
            },
        )
        self.assertEqual(reset.status_code, 200)
        self.assertFalse(reset.json()["password_reset_required"])

        allowed = self.client.get("/api/config")
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("security", allowed.json())

        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200)

        protected_after_logout = self.client.get("/api/config")
        self.assertEqual(protected_after_logout.status_code, 401)

        relogin = self.client.post("/api/auth/login", json={"username": "admin", "password": "BetterPassword123!"})
        self.assertEqual(relogin.status_code, 200)
        self.assertFalse(relogin.json()["password_reset_required"])

    def test_admin_user_crud_and_mcp_assignment_flow(self):
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-a",
                url="https://tenant-a.example.com/mcp",
                token="token-a",
                verify_ssl=True,
                description="Tenant A",
            )
        )
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-b",
                url="https://tenant-b.example.com/mcp",
                token="token-b",
                verify_ssl=True,
                description="Tenant B",
            )
        )

        admin_password = self._enable_auth_and_complete_admin_reset()

        create_user = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst1",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
                "mcp_config_name": "tenant-a",
            },
        )
        self.assertEqual(create_user.status_code, 200)
        created_user = create_user.json()["user"]
        self.assertEqual(created_user["mcp_config_name"], "tenant-a")

        user_list = self.client.get("/api/security/users")
        self.assertEqual(user_list.status_code, 200)
        self.assertEqual(user_list.json()["count"], 2)

        updated = self.client.patch(
            f"/api/security/users/{created_user['id']}",
            json={"mcp_config_name": "tenant-b"},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["user"]["mcp_config_name"], "tenant-b")

        self.client.post("/api/auth/logout")

        analyst_login = self.client.post(
            "/api/auth/login",
            json={"username": "analyst1", "password": "AnalystPassword123!"},
        )
        self.assertEqual(analyst_login.status_code, 200)
        self.assertFalse(analyst_login.json()["password_reset_required"])

        analyst_status = self.client.get("/api/auth/status")
        self.assertEqual(analyst_status.status_code, 200)
        self.assertEqual(analyst_status.json()["user"]["mcp_config_name"], "tenant-b")

        analyst_config = self.client.get("/api/config")
        self.assertEqual(analyst_config.status_code, 403)

        analyst_user_list = self.client.get("/api/security/users")
        self.assertEqual(analyst_user_list.status_code, 403)

        analyst_mcp_configs = self.client.get("/api/mcp-configs")
        self.assertEqual(analyst_mcp_configs.status_code, 403)

        self.client.post("/api/auth/logout")

        admin_relogin = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": admin_password},
        )
        self.assertEqual(admin_relogin.status_code, 200)

        delete_user = self.client.delete(f"/api/security/users/{created_user['id']}")
        self.assertEqual(delete_user.status_code, 200)

        missing_user = self.client.get(f"/api/security/users/{created_user['id']}")
        self.assertEqual(missing_user.status_code, 404)

    def test_runtime_mcp_selection_uses_assignment_for_runtime_endpoints(self):
        self.assertTrue(
            self.config_manager.update_mcp(
                url="https://global.example.com/mcp",
                token="global-token",
                verify_ssl=True,
            )
        )
        self.assertTrue(
            self.config_manager.save_mcp_config(
                name="tenant-b",
                url="https://tenant-b.example.com/mcp",
                token="token-b",
                verify_ssl=True,
                description="Tenant B",
            )
        )

        admin_password = self._enable_auth_and_complete_admin_reset()

        analyst_create = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst1",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
                "mcp_config_name": "tenant-b",
            },
        )
        self.assertEqual(analyst_create.status_code, 200)

        viewer_create = self.client.post(
            "/api/security/users",
            json={
                "username": "viewer1",
                "password": "ViewerPassword123!",
                "role": "viewer",
                "require_password_reset": False,
                "mcp_config_name": "tenant-b",
            },
        )
        self.assertEqual(viewer_create.status_code, 200)

        original_chat_logic = web_app.chat_with_splunk_logic
        original_build_deeplink = web_app.capability_manager.build_deeplink

        async def stub_chat_logic(request_payload: dict, status_callback=None, runtime_config=None):
            return {
                "message": request_payload.get("message"),
                "mcp_url": runtime_config.mcp.url if runtime_config else None,
                "active_mcp_config_name": getattr(runtime_config, "active_mcp_config_name", None),
            }

        class StubDeeplinkResult:
            def __init__(self, payload: dict):
                self.payload = payload

            def to_dict(self):
                return {
                    "ok": True,
                    "message": "stubbed",
                    "details": {
                        "received_mcp_url_override": self.payload.get("mcp_url_override"),
                    },
                }

        web_app.chat_with_splunk_logic = stub_chat_logic
        web_app.capability_manager.build_deeplink = lambda name, link_type, payload: StubDeeplinkResult(payload)
        try:
            analyst_logout = self.client.post("/api/auth/logout")
            self.assertEqual(analyst_logout.status_code, 200)

            analyst_login = self.client.post(
                "/api/auth/login",
                json={"username": "analyst1", "password": "AnalystPassword123!"},
            )
            self.assertEqual(analyst_login.status_code, 200)

            analyst_connection = self.client.get("/connection-info")
            self.assertEqual(analyst_connection.status_code, 200)
            self.assertEqual(analyst_connection.json()["mcp"]["endpoint"], "https://tenant-b.example.com/mcp")

            analyst_chat = self.client.post("/chat", json={"message": "hello"})
            self.assertEqual(analyst_chat.status_code, 200)
            self.assertEqual(analyst_chat.json()["mcp_url"], "https://tenant-b.example.com/mcp")
            self.assertEqual(analyst_chat.json()["active_mcp_config_name"], "tenant-b")

            analyst_deeplink = self.client.post(
                "/api/capabilities/deeplinks/build",
                json={"link_type": "search", "query": "index=_internal"},
            )
            self.assertEqual(analyst_deeplink.status_code, 200)
            self.assertEqual(
                analyst_deeplink.json()["details"]["received_mcp_url_override"],
                "https://tenant-b.example.com/mcp",
            )

            viewer_logout = self.client.post("/api/auth/logout")
            self.assertEqual(viewer_logout.status_code, 200)

            viewer_login = self.client.post(
                "/api/auth/login",
                json={"username": "viewer1", "password": "ViewerPassword123!"},
            )
            self.assertEqual(viewer_login.status_code, 200)

            viewer_connection = self.client.get("/connection-info")
            self.assertEqual(viewer_connection.status_code, 200)
            self.assertEqual(viewer_connection.json()["mcp"]["endpoint"], "")

            viewer_chat = self.client.post("/chat", json={"message": "hello"})
            self.assertEqual(viewer_chat.status_code, 200)
            self.assertEqual(viewer_chat.json()["mcp_url"], "")
            self.assertIsNone(viewer_chat.json()["active_mcp_config_name"])

            viewer_deeplink = self.client.post(
                "/api/capabilities/deeplinks/build",
                json={"link_type": "search", "query": "index=_internal"},
            )
            self.assertEqual(viewer_deeplink.status_code, 200)
            self.assertEqual(viewer_deeplink.json()["details"]["received_mcp_url_override"], "")

            admin_logout = self.client.post("/api/auth/logout")
            self.assertEqual(admin_logout.status_code, 200)

            admin_login = self.client.post(
                "/api/auth/login",
                json={"username": "admin", "password": admin_password},
            )
            self.assertEqual(admin_login.status_code, 200)

            admin_connection = self.client.get("/connection-info")
            self.assertEqual(admin_connection.status_code, 200)
            self.assertEqual(admin_connection.json()["mcp"]["endpoint"], "https://global.example.com/mcp")

            admin_chat = self.client.post("/chat", json={"message": "hello"})
            self.assertEqual(admin_chat.status_code, 200)
            self.assertEqual(admin_chat.json()["mcp_url"], "https://global.example.com/mcp")

            admin_deeplink = self.client.post(
                "/api/capabilities/deeplinks/build",
                json={"link_type": "search", "query": "index=_internal"},
            )
            self.assertEqual(admin_deeplink.status_code, 200)
            self.assertEqual(
                admin_deeplink.json()["details"]["received_mcp_url_override"],
                "https://global.example.com/mcp",
            )
        finally:
            web_app.chat_with_splunk_logic = original_chat_logic
            web_app.capability_manager.build_deeplink = original_build_deeplink

    def test_admin_token_lifecycle_endpoints(self):
        admin_password = self._enable_auth_and_complete_admin_reset()

        create_user = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst1",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
            },
        )
        self.assertEqual(create_user.status_code, 200)
        analyst_user_id = create_user.json()["user"]["id"]

        create_token = self.client.post(
            "/api/security/tokens",
            json={
                "name": "External RAG Read Token",
                "token_type": "external_api",
                "scopes": ["rag:search", "rag:assets:read"],
                "owner_user_id": analyst_user_id,
                "expires_in_days": 14,
            },
        )
        self.assertEqual(create_token.status_code, 200)
        token_payload = create_token.json()
        self.assertTrue(str(token_payload["access_token"]).startswith("dt4sms_"))
        self.assertEqual(token_payload["token"]["owner_user_id"], analyst_user_id)
        self.assertEqual(token_payload["token"]["owner_username"], "analyst1")
        self.assertEqual(token_payload["token"]["created_by_username"], "admin")
        token_id = token_payload["token"]["id"]

        create_service_token = self.client.post(
            "/api/security/tokens",
            json={
                "name": "Inbound MCP Service Token",
                "token_type": "inbound_mcp",
                "scopes": ["mcp:tools:read"],
                "expires_in_days": 7,
            },
        )
        self.assertEqual(create_service_token.status_code, 200)
        service_token_payload = create_service_token.json()
        self.assertIsNone(service_token_payload["token"]["owner_user_id"])
        self.assertIsNone(service_token_payload["token"]["owner_username"])

        resolved = self.security_manager.resolve_access_token(
            token_payload["access_token"],
            required_scopes=["rag:search"],
            token_type="external_api",
            used_from="web-app-test",
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["id"], token_id)
        self.assertEqual(resolved["use_count"], 1)
        self.assertEqual(resolved["last_used_from"], "web-app-test")

        resolved_service_token = self.security_manager.resolve_access_token(
            service_token_payload["access_token"],
            required_scopes=["mcp:tools:read"],
            token_type="inbound_mcp",
            used_from="service-test",
        )
        self.assertIsNotNone(resolved_service_token)
        self.assertIsNone(resolved_service_token["owner_user_id"])
        self.assertEqual(resolved_service_token["use_count"], 1)

        token_list = self.client.get("/api/security/tokens")
        self.assertEqual(token_list.status_code, 200)
        self.assertEqual(token_list.json()["count"], 2)
        self.assertNotIn("access_token", token_list.json()["tokens"][0])
        token_ids = {token["id"] for token in token_list.json()["tokens"]}
        self.assertEqual(token_ids, {token_id, service_token_payload["token"]["id"]})

        token_detail = self.client.get(f"/api/security/tokens/{token_id}")
        self.assertEqual(token_detail.status_code, 200)
        self.assertEqual(token_detail.json()["owner_username"], "analyst1")

        delete_service_token = self.client.delete(f"/api/security/tokens/{service_token_payload['token']['id']}")
        self.assertEqual(delete_service_token.status_code, 200)

        missing_service_token = self.client.get(f"/api/security/tokens/{service_token_payload['token']['id']}")
        self.assertEqual(missing_service_token.status_code, 404)

        token_list_after_delete = self.client.get("/api/security/tokens")
        self.assertEqual(token_list_after_delete.status_code, 200)
        self.assertEqual(token_list_after_delete.json()["count"], 1)

        self.client.post("/api/auth/logout")

        analyst_login = self.client.post(
            "/api/auth/login",
            json={"username": "analyst1", "password": "AnalystPassword123!"},
        )
        self.assertEqual(analyst_login.status_code, 200)

        analyst_token_list = self.client.get("/api/security/tokens")
        self.assertEqual(analyst_token_list.status_code, 403)

        self.client.post("/api/auth/logout")

        admin_relogin = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": admin_password},
        )
        self.assertEqual(admin_relogin.status_code, 200)

        revoke_token = self.client.post(f"/api/security/tokens/{token_id}/revoke")
        self.assertEqual(revoke_token.status_code, 200)
        self.assertIsNotNone(revoke_token.json()["token"]["revoked_at"])
        self.assertIsNone(self.security_manager.resolve_access_token(token_payload["access_token"], token_type="external_api"))

    def test_security_config_rejects_invalid_ranges(self):
        invalid_update = self.client.post(
            "/api/config",
            json={
                "security": {
                    "session_timeout_minutes": 0,
                    "password_min_length": 4,
                    "external_api_rate_limit_requests": 0,
                    "external_mcp_rate_limit_window_seconds": 0,
                }
            },
        )
        self.assertEqual(invalid_update.status_code, 422)

        detail = invalid_update.json().get("detail", [])
        field_locations = {
            ".".join(str(part) for part in entry.get("loc", []))
            for entry in detail
            if isinstance(entry, dict)
        }
        self.assertIn("body.security.session_timeout_minutes", field_locations)
        self.assertIn("body.security.password_min_length", field_locations)
        self.assertIn("body.security.external_api_rate_limit_requests", field_locations)
        self.assertIn("body.security.external_mcp_rate_limit_window_seconds", field_locations)

    def test_admin_security_endpoints_reject_invalid_assignments_and_non_admin_token_access(self):
        admin_password = self._enable_auth_and_complete_admin_reset()

        invalid_user_assignment = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst-invalid",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
                "mcp_config_name": "missing-assignment",
            },
        )
        self.assertEqual(invalid_user_assignment.status_code, 400)
        self.assertIn("does not exist", invalid_user_assignment.json()["detail"])

        create_user = self.client.post(
            "/api/security/users",
            json={
                "username": "analyst1",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "require_password_reset": False,
            },
        )
        self.assertEqual(create_user.status_code, 200)

        invalid_token_owner = self.client.post(
            "/api/security/tokens",
            json={
                "name": "Invalid Owner Token",
                "token_type": "external_api",
                "scopes": ["rag:search"],
                "owner_user_id": 9999,
            },
        )
        self.assertEqual(invalid_token_owner.status_code, 400)
        self.assertIn("owner_user_id", invalid_token_owner.json()["detail"])

        valid_token = self.client.post(
            "/api/security/tokens",
            json={
                "name": "Analyst Visibility Token",
                "token_type": "external_api",
                "scopes": ["rag:search"],
            },
        )
        self.assertEqual(valid_token.status_code, 200)
        token_id = valid_token.json()["token"]["id"]

        self.client.post("/api/auth/logout")

        analyst_login = self.client.post(
            "/api/auth/login",
            json={"username": "analyst1", "password": "AnalystPassword123!"},
        )
        self.assertEqual(analyst_login.status_code, 200)

        analyst_token_detail = self.client.get(f"/api/security/tokens/{token_id}")
        self.assertEqual(analyst_token_detail.status_code, 403)

        analyst_revoke = self.client.post(f"/api/security/tokens/{token_id}/revoke")
        self.assertEqual(analyst_revoke.status_code, 403)

        analyst_delete = self.client.delete(f"/api/security/tokens/{token_id}")
        self.assertEqual(analyst_delete.status_code, 403)

        self.client.post("/api/auth/logout")

        admin_relogin = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": admin_password},
        )
        self.assertEqual(admin_relogin.status_code, 200)

        revoke_token = self.client.post(f"/api/security/tokens/{token_id}/revoke")
        self.assertEqual(revoke_token.status_code, 200)
        self.assertIsNotNone(revoke_token.json()["token"]["revoked_at"])

    def test_external_rag_api_requires_scoped_token_and_sanitizes_payloads(self):
        discovery_when_disabled = self.client.get("/api/external/info")
        self.assertEqual(discovery_when_disabled.status_code, 404)

        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_api_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        search_token = self.security_manager.issue_access_token(
            name="External Search Token",
            token_type="external_api",
            scopes=["rag:search"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )
        read_token = self.security_manager.issue_access_token(
            name="External Read Token",
            token_type="external_api",
            scopes=["rag:search", "rag:assets:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        original_get_capability_state = web_app.capability_manager.get_capability_state
        original_list_rag_assets = web_app.capability_manager.list_rag_assets
        original_get_rag_asset_detail = web_app.capability_manager.get_rag_asset_detail
        original_build_rag_context_preview = web_app.capability_manager.build_rag_context_preview

        class StubActionResult:
            def __init__(self, payload: dict):
                self.payload = payload

            def to_dict(self):
                return {
                    "ok": True,
                    "message": "stubbed",
                    "details": self.payload,
                }

        rag_index_summary = {
            "collection_name": "rag-chromadb",
            "storage_dir": "C:/sensitive/storage",
            "source_dir": "C:/sensitive/output",
            "index_schema_version": 4,
            "document_count": 3,
            "source_file_count": 1,
            "source_type_counts": {"knowledge_asset": 3},
            "sample_sources": ["rag/assets/platform-health-guide.md"],
            "last_indexed_at": "2026-05-15T12:00:00+00:00",
        }
        rag_asset = {
            "asset_id": "asset-1",
            "title": "Platform Health Guide",
            "asset_type": "reference_document",
            "source_label": "ops",
            "description": "Operational runbook for platform health.",
            "summary": "Summarizes platform health indicators.",
            "preview": "Use this guide to investigate queue pressure.",
            "headings": ["Overview"],
            "key_points": ["Check ingestion queues."],
            "focus_terms": ["platform", "health"],
            "usage_guidance": ["Use for platform triage."],
            "tags": ["ops", "health"],
            "attributes": {"category": "runbook"},
            "library_status": "checked_in",
            "checked_out_at": None,
            "last_checked_in_at": "2026-05-15T11:00:00+00:00",
            "content_path": "platform-health-guide.md",
            "import_method": "text",
            "original_filename": None,
            "created_at": "2026-05-15T10:00:00+00:00",
            "updated_at": "2026-05-15T11:00:00+00:00",
            "text_char_count": 128,
            "word_count": 22,
        }
        rag_asset_summary = {
            "asset_count": 1,
            "checked_in_asset_count": 1,
            "checked_out_asset_count": 0,
            "library_status_counts": {"checked_in": 1, "checked_out": 0},
            "asset_type_counts": {"reference_document": 1},
            "asset_dir": "C:/sensitive/assets",
            "manifest_path": "C:/sensitive/manifest.json",
            "assets": [dict(rag_asset)],
        }

        web_app.capability_manager.get_capability_state = lambda name, refresh_health=False: {
            "installed": True,
            "enabled": True,
            "health_status": "ready",
            "index_summary": dict(rag_index_summary),
            "knowledge_asset_summary": dict(rag_asset_summary),
        }
        web_app.capability_manager.list_rag_assets = lambda name="rag_chromadb": StubActionResult(dict(rag_asset_summary))
        web_app.capability_manager.get_rag_asset_detail = lambda name, asset_id: StubActionResult(
            {
                "asset": dict(rag_asset),
                "stored_path": "platform-health-guide.md",
                "stored_sections": [{"title": "Overview", "content": "Queue pressure response steps."}],
                "context_body": "Queue pressure response steps.",
                "context_character_count": 30,
                "chunk_sections": [
                    {
                        "document_id": "chunk-1",
                        "section": "Overview",
                        "content": "Queue pressure response steps.",
                        "character_count": 30,
                        "source_name": "platform-health-guide.md",
                        "metadata": {
                            "source_type": "knowledge_asset",
                            "asset_type": "reference_document",
                            "asset_source_label": "ops",
                        },
                    }
                ],
                "chunk_count": 1,
                "index_summary": dict(rag_index_summary),
            }
        )
        web_app.capability_manager.build_rag_context_preview = lambda name, query, max_chunks=4: StubActionResult(
            {
                "query": query,
                "context_text": "Knowledge asset context preview for platform health",
                "operator_brief": "Use the platform health guide first.",
                "chunks": [
                    {
                        "source": "rag/assets/platform-health-guide.md",
                        "score": 91,
                        "snippet": "Queue pressure response steps.",
                        "metadata": {
                            "source_type": "knowledge_asset",
                            "asset_type": "reference_document",
                            "asset_source_label": "ops",
                            "source_path": "sensitive/path.md",
                        },
                        "document_id": "chunk-1",
                        "section": "Overview",
                        "asset_id": "asset-1",
                        "asset_title": "Platform Health Guide",
                    }
                ],
                "matched_assets": [
                    {
                        **dict(rag_asset),
                        "spl_query": None,
                        "reuse_tier": None,
                        "reuse_score": 0,
                        "known_good": False,
                        "validation_status": None,
                        "environment_fit_status": None,
                        "environment_fit_score": 0,
                        "environment_fit_reason": "",
                        "matched_sections": ["Overview"],
                        "matched_chunk_ids": ["chunk-1"],
                        "matched_chunks": [
                            {
                                "document_id": "chunk-1",
                                "section": "Overview",
                                "score": 91,
                                "snippet": "Queue pressure response steps.",
                                "source": "rag/assets/platform-health-guide.md",
                            }
                        ],
                        "best_excerpt": "Queue pressure response steps.",
                        "best_chunk_document_id": "chunk-1",
                        "match_score": 91,
                        "why_matched": "Matched platform health guidance.",
                    }
                ],
                "reusable_spl_queries": [
                    {
                        "asset_id": "spl-1",
                        "title": "Queue Pressure SPL",
                        "query": "index=_internal queue pressure",
                        "source_label": "ops",
                        "intent": "platform health",
                        "environment_fit_status": "good",
                        "environment_fit_score": 88,
                        "validation_status": "known_good",
                        "success_count": 3,
                        "failure_count": 0,
                        "reuse_tier": "preferred",
                        "reuse_score": 92,
                        "known_good": True,
                        "why_reuse": "Known-good query for queue pressure.",
                        "app": "search",
                        "earliest": "-24h",
                        "latest": "now",
                        "unexpected": "hidden",
                    }
                ],
                "retrieved_key_points": ["Check indexing queues."],
                "recommended_uses": ["Platform triage"],
                "coverage_gaps": ["No dedicated dashboard asset matched this query."],
                "coverage_summary": {"asset_count": 1, "asset_types": ["reference_document"]},
                "index_summary": dict(rag_index_summary),
                "asset_summary": dict(rag_asset_summary),
                "message": "Built context preview from 1 indexed knowledge chunk(s).",
            }
        )

        try:
            discovery = self.client.get("/api/external/info")
            self.assertEqual(discovery.status_code, 200)
            self.assertEqual(discovery.json()["api_name"], "dt4sms-external-rag")

            unauthorized_summary = self.client.get("/api/external/rag/index-summary")
            self.assertEqual(unauthorized_summary.status_code, 401)

            search_response = self.client.post(
                "/api/external/rag/search",
                headers={"Authorization": f"Bearer {search_token['access_token']}"},
                json={"query": "platform health", "limit": 3},
            )
            self.assertEqual(search_response.status_code, 200)
            self.assertEqual(search_response.json()["provider"], "rag_chromadb")
            self.assertNotIn("storage_dir", search_response.json()["index_summary"])
            self.assertNotIn("source_dir", search_response.json()["index_summary"])
            self.assertNotIn("asset_dir", search_response.json()["asset_summary"])
            self.assertNotIn("manifest_path", search_response.json()["asset_summary"])
            self.assertNotIn("content_path", search_response.json()["matched_assets"][0])
            self.assertNotIn("unexpected", search_response.json()["reusable_spl_queries"][0])

            denied_assets = self.client.get(
                "/api/external/rag/assets",
                headers={"Authorization": f"Bearer {search_token['access_token']}"},
            )
            self.assertEqual(denied_assets.status_code, 403)

            index_summary = self.client.get(
                "/api/external/rag/index-summary",
                headers={"Authorization": f"Bearer {read_token['access_token']}"},
            )
            self.assertEqual(index_summary.status_code, 200)
            self.assertNotIn("storage_dir", index_summary.json()["index_summary"])
            self.assertNotIn("asset_dir", index_summary.json()["asset_summary"])

            asset_list = self.client.get(
                "/api/external/rag/assets",
                headers={"Authorization": f"Bearer {read_token['access_token']}"},
            )
            self.assertEqual(asset_list.status_code, 200)
            self.assertEqual(asset_list.json()["asset_count"], 1)
            self.assertNotIn("content_path", asset_list.json()["assets"][0])

            asset_detail = self.client.get(
                "/api/external/rag/assets/asset-1",
                headers={"Authorization": f"Bearer {read_token['access_token']}"},
            )
            self.assertEqual(asset_detail.status_code, 200)
            self.assertEqual(asset_detail.json()["asset"]["asset_id"], "asset-1")
            self.assertNotIn("content_path", asset_detail.json()["asset"])
            self.assertNotIn("stored_path", asset_detail.json())
            self.assertNotIn("storage_dir", asset_detail.json()["index_summary"])
        finally:
            web_app.capability_manager.get_capability_state = original_get_capability_state
            web_app.capability_manager.list_rag_assets = original_list_rag_assets
            web_app.capability_manager.get_rag_asset_detail = original_get_rag_asset_detail
            web_app.capability_manager.build_rag_context_preview = original_build_rag_context_preview

    def test_external_rag_api_rate_limits_requests_per_token(self):
        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_api_enabled=True,
                external_api_rate_limit_requests=2,
                external_api_rate_limit_window_seconds=60,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        read_token = self.security_manager.issue_access_token(
            name="Rate Limited External Read Token",
            token_type="external_api",
            scopes=["rag:assets:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        original_get_capability_state = web_app.capability_manager.get_capability_state
        web_app.capability_manager.get_capability_state = lambda name, refresh_health=False: {
            "installed": True,
            "enabled": True,
            "health_status": "ready",
            "index_summary": {"document_count": 1},
            "knowledge_asset_summary": {"asset_count": 1, "assets": []},
        }

        try:
            headers = {"Authorization": f"Bearer {read_token['access_token']}"}
            first = self.client.get("/api/external/rag/index-summary", headers=headers)
            second = self.client.get("/api/external/rag/index-summary", headers=headers)
            third = self.client.get("/api/external/rag/index-summary", headers=headers)

            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 200)
            self.assertEqual(third.status_code, 429)
            self.assertIn("rate limit exceeded", third.json()["detail"].lower())
            self.assertIn("retry-after", third.headers)

            token_record = self.security_manager.get_access_token(int(read_token["token"]["id"]))
            self.assertIsNotNone(token_record)
            self.assertEqual(token_record["use_count"], 2)
        finally:
            web_app.capability_manager.get_capability_state = original_get_capability_state

    def test_external_mcp_requires_inbound_token_and_exposes_read_only_rag_tools(self):
        discovery_when_disabled = self.client.get("/api/external/mcp/info")
        self.assertEqual(discovery_when_disabled.status_code, 404)

        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        wrong_surface_token = self.security_manager.issue_access_token(
            name="Wrong Token Type",
            token_type="external_api",
            scopes=["rag:search"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )
        mcp_token = self.security_manager.issue_access_token(
            name="Inbound MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        original_get_capability_state = web_app.capability_manager.get_capability_state
        original_list_rag_assets = web_app.capability_manager.list_rag_assets
        original_get_rag_asset_detail = web_app.capability_manager.get_rag_asset_detail
        original_build_rag_context_preview = web_app.capability_manager.build_rag_context_preview

        class StubActionResult:
            def __init__(self, payload: dict):
                self.payload = payload

            def to_dict(self):
                return {
                    "ok": True,
                    "message": "stubbed",
                    "details": self.payload,
                }

        rag_index_summary = {
            "collection_name": "rag-chromadb",
            "storage_dir": "C:/sensitive/storage",
            "source_dir": "C:/sensitive/output",
            "index_schema_version": 4,
            "document_count": 3,
            "source_file_count": 1,
            "source_type_counts": {"knowledge_asset": 3},
            "sample_sources": ["rag/assets/platform-health-guide.md"],
            "last_indexed_at": "2026-05-15T12:00:00+00:00",
        }
        rag_asset = {
            "asset_id": "asset-1",
            "title": "Platform Health Guide",
            "asset_type": "reference_document",
            "source_label": "ops",
            "description": "Operational runbook for platform health.",
            "summary": "Summarizes platform health indicators.",
            "preview": "Use this guide to investigate queue pressure.",
            "headings": ["Overview"],
            "key_points": ["Check ingestion queues."],
            "focus_terms": ["platform", "health"],
            "usage_guidance": ["Use for platform triage."],
            "tags": ["ops", "health"],
            "attributes": {"category": "runbook"},
            "library_status": "checked_in",
            "checked_out_at": None,
            "last_checked_in_at": "2026-05-15T11:00:00+00:00",
            "content_path": "platform-health-guide.md",
            "import_method": "text",
            "original_filename": None,
            "created_at": "2026-05-15T10:00:00+00:00",
            "updated_at": "2026-05-15T11:00:00+00:00",
            "text_char_count": 128,
            "word_count": 22,
        }
        rag_asset_summary = {
            "asset_count": 1,
            "checked_in_asset_count": 1,
            "checked_out_asset_count": 0,
            "library_status_counts": {"checked_in": 1, "checked_out": 0},
            "asset_type_counts": {"reference_document": 1},
            "asset_dir": "C:/sensitive/assets",
            "manifest_path": "C:/sensitive/manifest.json",
            "assets": [dict(rag_asset)],
        }

        web_app.capability_manager.get_capability_state = lambda name, refresh_health=False: {
            "installed": True,
            "enabled": True,
            "health_status": "ready",
            "index_summary": dict(rag_index_summary),
            "knowledge_asset_summary": dict(rag_asset_summary),
        }
        web_app.capability_manager.list_rag_assets = lambda name="rag_chromadb": StubActionResult(dict(rag_asset_summary))
        web_app.capability_manager.get_rag_asset_detail = lambda name, asset_id: StubActionResult(
            {
                "asset": dict(rag_asset),
                "stored_path": "platform-health-guide.md",
                "stored_sections": [{"title": "Overview", "content": "Queue pressure response steps."}],
                "context_body": "Queue pressure response steps.",
                "context_character_count": 30,
                "chunk_sections": [
                    {
                        "document_id": "chunk-1",
                        "section": "Overview",
                        "content": "Queue pressure response steps.",
                        "character_count": 30,
                        "source_name": "platform-health-guide.md",
                        "metadata": {
                            "source_type": "knowledge_asset",
                            "asset_type": "reference_document",
                            "asset_source_label": "ops",
                        },
                    }
                ],
                "chunk_count": 1,
                "index_summary": dict(rag_index_summary),
            }
        )
        web_app.capability_manager.build_rag_context_preview = lambda name, query, max_chunks=4: StubActionResult(
            {
                "query": query,
                "context_text": "Knowledge asset context preview for platform health",
                "operator_brief": "Use the platform health guide first.",
                "chunks": [
                    {
                        "source": "rag/assets/platform-health-guide.md",
                        "score": 91,
                        "snippet": "Queue pressure response steps.",
                        "metadata": {
                            "source_type": "knowledge_asset",
                            "asset_type": "reference_document",
                            "asset_source_label": "ops",
                            "source_path": "sensitive/path.md",
                        },
                        "document_id": "chunk-1",
                        "section": "Overview",
                        "asset_id": "asset-1",
                        "asset_title": "Platform Health Guide",
                    }
                ],
                "matched_assets": [
                    {
                        **dict(rag_asset),
                        "spl_query": None,
                        "reuse_tier": None,
                        "reuse_score": 0,
                        "known_good": False,
                        "validation_status": None,
                        "environment_fit_status": None,
                        "environment_fit_score": 0,
                        "environment_fit_reason": "",
                        "matched_sections": ["Overview"],
                        "matched_chunk_ids": ["chunk-1"],
                        "matched_chunks": [
                            {
                                "document_id": "chunk-1",
                                "section": "Overview",
                                "score": 91,
                                "snippet": "Queue pressure response steps.",
                                "source": "rag/assets/platform-health-guide.md",
                            }
                        ],
                        "best_excerpt": "Queue pressure response steps.",
                        "best_chunk_document_id": "chunk-1",
                        "match_score": 91,
                        "why_matched": "Matched platform health guidance.",
                    }
                ],
                "reusable_spl_queries": [
                    {
                        "asset_id": "spl-1",
                        "title": "Queue Pressure SPL",
                        "query": "index=_internal queue pressure",
                        "source_label": "ops",
                        "intent": "platform health",
                        "environment_fit_status": "good",
                        "environment_fit_score": 88,
                        "validation_status": "known_good",
                        "success_count": 3,
                        "failure_count": 0,
                        "reuse_tier": "preferred",
                        "reuse_score": 92,
                        "known_good": True,
                        "why_reuse": "Known-good query for queue pressure.",
                        "app": "search",
                        "earliest": "-24h",
                        "latest": "now",
                        "unexpected": "hidden",
                    }
                ],
                "retrieved_key_points": ["Check indexing queues."],
                "recommended_uses": ["Platform triage"],
                "coverage_gaps": ["No dedicated dashboard asset matched this query."],
                "coverage_summary": {"asset_count": 1, "asset_types": ["reference_document"]},
                "index_summary": dict(rag_index_summary),
                "asset_summary": dict(rag_asset_summary),
                "message": "Built context preview from 1 indexed knowledge chunk(s).",
            }
        )

        try:
            info = self.client.get("/api/external/mcp/info")
            self.assertEqual(info.status_code, 200)
            self.assertEqual(info.json()["server_name"], "dt4sms-external-mcp")
            self.assertEqual(info.json()["authentication"]["token_type"], "inbound_mcp")

            missing_token = self.client.post(
                "/api/external/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            self.assertEqual(missing_token.status_code, 401)

            wrong_token_type = self.client.post(
                "/api/external/mcp",
                headers={"Authorization": f"Bearer {wrong_surface_token['access_token']}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            self.assertEqual(wrong_token_type.status_code, 401)

            initialize = self.client.post(
                "/api/external/mcp",
                headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "clientInfo": {"name": "unit-test", "version": "1.0"},
                    },
                },
            )
            self.assertEqual(initialize.status_code, 200)
            self.assertEqual(initialize.json()["result"]["protocolVersion"], "2025-03-26")
            self.assertFalse(initialize.json()["result"]["capabilities"]["tools"]["listChanged"])

            tools_list = self.client.post(
                "/api/external/mcp",
                headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
                json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            )
            self.assertEqual(tools_list.status_code, 200)
            tool_names = {tool["name"] for tool in tools_list.json()["result"]["tools"]}
            self.assertEqual(
                tool_names,
                {
                    "rag_search",
                    "rag_list_assets",
                    "rag_get_asset_detail",
                    "rag_build_context",
                    "system_get_runtime_summary",
                    "capabilities_list",
                    "capabilities_get_detail",
                    "artifacts_list",
                    "artifacts_get_detail",
                    "discovery_get_dashboard",
                    "discovery_get_latest_intelligence",
                    "discovery_get_runbook",
                    "discovery_compare_sessions",
                },
            )

            search_call = self.client.post(
                "/api/external/mcp",
                headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "rag_search",
                        "arguments": {"query": "platform health", "limit": 2},
                    },
                },
            )
            self.assertEqual(search_call.status_code, 200)
            search_result = search_call.json()["result"]["structuredContent"]
            self.assertEqual(search_result["provider"], "rag_chromadb")
            self.assertNotIn("storage_dir", search_result["index_summary"])
            self.assertNotIn("asset_dir", search_result["asset_summary"])
            self.assertNotIn("content_path", search_result["matched_assets"][0])
            self.assertNotIn("unexpected", search_result["reusable_spl_queries"][0])

            asset_call = self.client.post(
                "/api/external/mcp",
                headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "rag_get_asset_detail",
                        "arguments": {"asset_id": "asset-1"},
                    },
                },
            )
            self.assertEqual(asset_call.status_code, 200)
            asset_result = asset_call.json()["result"]["structuredContent"]
            self.assertEqual(asset_result["asset"]["asset_id"], "asset-1")
            self.assertNotIn("content_path", asset_result["asset"])
            self.assertNotIn("stored_path", asset_result)
            self.assertNotIn("storage_dir", asset_result["index_summary"])

            token_record = self.security_manager.get_access_token(mcp_token["token"]["id"])
            self.assertIsNotNone(token_record)
            self.assertEqual(token_record["use_count"], 4)
        finally:
            web_app.capability_manager.get_capability_state = original_get_capability_state
            web_app.capability_manager.list_rag_assets = original_list_rag_assets
            web_app.capability_manager.get_rag_asset_detail = original_get_rag_asset_detail
            web_app.capability_manager.build_rag_context_preview = original_build_rag_context_preview

    def test_external_mcp_exposes_sanitized_operational_context_tools(self):
        output_dir = self.temp_path / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "v2_operator_runbook_20260517_101010.md").write_text(
            "# Queue Pressure Runbook\n\nUse this runbook to investigate queue pressure signals.",
            encoding="utf-8",
        )
        (output_dir / "v2_intelligence_blueprint_20260517_101010.json").write_text(
            json.dumps(
                {
                    "mission": "Platform health triage",
                    "recommendations": ["Inspect parsing queues first."],
                    "confidence": 0.91,
                    "notes": (
                        "Queue pressure investigation should inspect parsing and indexing queues before broader escalation. "
                        "Validate sustained queue depth, review blocked parsing pipelines, compare indexing throughput, "
                        "and confirm whether license or forwarding constraints are contributing to ingestion lag before "
                        "routing to a larger platform incident."
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        self.assertTrue(
            self.config_manager.update_mcp(
                url="https://splunk.example.local:8089/services/mcp",
                token="splunk-secret-token",
                verify_ssl=True,
            )
        )
        self.assertTrue(
            self.config_manager.update_llm(
                provider="openai",
                api_key="llm-secret-key",
                model="gpt-4.1-mini",
            )
        )
        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                auth_provider="oidc",
                external_api_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=45,
                password_min_length=14,
                oidc={
                    "issuer_url": "https://login.example.local/issuer",
                    "client_id": "dt4sms-client",
                    "client_secret": "oidc-secret",
                },
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Operational Context MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        original_get_summary = web_app.capability_manager.get_summary
        original_list_capabilities = web_app.capability_manager.list_capabilities
        original_get_capability_state = web_app.capability_manager.get_capability_state

        capability_summary = {
            "total": 2,
            "installed": 2,
            "enabled": 2,
            "ready": 1,
            "restart_required": 0,
        }
        capability_states = {
            "rag_chromadb": {
                "name": "rag_chromadb",
                "title": "Managed RAG Index",
                "category": "retrieval",
                "description": "Indexed retrieval over managed knowledge assets.",
                "purpose": "Grounded context retrieval",
                "intent": "Provide reusable indexed context",
                "capability_set": ["retrieval", "knowledge_assets"],
                "dependency_packages": ["chromadb"],
                "runtime_available": True,
                "requires_restart_on_install": False,
                "maturity": "ga",
                "installed": True,
                "enabled": True,
                "version": "bundled",
                "health_status": "ready",
                "health_message": "Indexed artifact search is ready.",
                "last_tested_at": "2026-05-17T10:15:00+00:00",
                "restart_required": False,
                "config": {
                    "source_dir": "C:/sensitive/output",
                    "storage_dir": "C:/sensitive/storage",
                },
                "index_summary": {
                    "collection_name": "rag-chromadb",
                    "storage_dir": "C:/sensitive/storage",
                    "source_dir": "C:/sensitive/output",
                    "index_schema_version": 4,
                    "document_count": 12,
                    "source_file_count": 4,
                    "source_type_counts": {"knowledge_asset": 12},
                    "sample_sources": ["rag/assets/platform-health-guide.md"],
                    "last_indexed_at": "2026-05-17T10:00:00+00:00",
                },
                "knowledge_asset_summary": {
                    "asset_count": 3,
                    "checked_in_asset_count": 3,
                    "checked_out_asset_count": 0,
                    "library_status_counts": {"checked_in": 3},
                    "asset_type_counts": {"reference_document": 3},
                    "asset_dir": "C:/sensitive/assets",
                    "manifest_path": "C:/sensitive/assets/manifest.json",
                },
            },
            "export_tools": {
                "name": "export_tools",
                "title": "Deterministic Export Bundles",
                "category": "artifacts",
                "description": "Build deterministic report packages from discovery outputs.",
                "purpose": "Package outputs for delivery",
                "intent": "Operational export packaging",
                "capability_set": ["exports"],
                "dependency_packages": [],
                "runtime_available": True,
                "requires_restart_on_install": False,
                "maturity": "beta",
                "installed": True,
                "enabled": True,
                "version": "bundled",
                "health_status": "degraded",
                "health_message": "Export runtime is available but no bundles have been generated yet.",
                "last_tested_at": "2026-05-17T10:20:00+00:00",
                "restart_required": False,
                "config": {
                    "source_dir": "C:/sensitive/output",
                    "export_dir": "C:/sensitive/exports",
                },
                "output_dir": "C:/sensitive/output",
                "export_dir": "C:/sensitive/exports",
                "supported_outputs": ["bundle_zip", "manifest_json", "summary_markdown"],
                "max_bundle_files": 12,
                "available_session_count": 4,
                "latest_session_timestamp": "20260517_101010",
                "bundle_count": 1,
                "latest_bundle": {
                    "name": "dt4sms_report_package_20260517_101010.zip",
                    "size_bytes": 4096,
                    "modified_at": "2026-05-17T10:18:00+00:00",
                },
            },
        }

        def _clone_payload(value):
            return json.loads(json.dumps(value))

        web_app.capability_manager.get_summary = lambda: dict(capability_summary)
        web_app.capability_manager.list_capabilities = lambda refresh_health=True: _clone_payload(capability_states)
        web_app.capability_manager.get_capability_state = lambda name, refresh_health=False: _clone_payload(capability_states[name])

        headers = {
            "Authorization": f"Bearer {mcp_token['access_token']}",
            "Content-Type": "application/json",
        }

        try:
            tools_list = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            self.assertEqual(tools_list.status_code, 200)
            tool_names = {tool["name"] for tool in tools_list.json()["result"]["tools"]}
            self.assertTrue(
                {
                    "system_get_runtime_summary",
                    "capabilities_list",
                    "capabilities_get_detail",
                    "artifacts_list",
                    "artifacts_get_detail",
                }.issubset(tool_names)
            )

            runtime_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "system_get_runtime_summary", "arguments": {}},
                },
            )
            self.assertEqual(runtime_call.status_code, 200)
            runtime_result = runtime_call.json()["result"]["structuredContent"]
            self.assertEqual(runtime_result["security"]["auth_provider"], "oidc")
            self.assertTrue(runtime_result["security"]["oidc"]["issuer_configured"])
            self.assertTrue(runtime_result["mcp"]["url_configured"])
            self.assertEqual(runtime_result["artifacts"]["count"], 2)
            runtime_serialized = json.dumps(runtime_result)
            self.assertNotIn("splunk-secret-token", runtime_serialized)
            self.assertNotIn("llm-secret-key", runtime_serialized)
            self.assertNotIn("splunk.example.local", runtime_serialized)
            self.assertNotIn("login.example.local", runtime_serialized)

            capabilities_list_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "capabilities_list", "arguments": {}},
                },
            )
            self.assertEqual(capabilities_list_call.status_code, 200)
            capabilities_list_result = capabilities_list_call.json()["result"]["structuredContent"]
            self.assertEqual(capabilities_list_result["summary"]["ready"], 1)
            rag_capability = next(
                capability
                for capability in capabilities_list_result["capabilities"]
                if capability["name"] == "rag_chromadb"
            )
            self.assertNotIn("config", rag_capability)
            self.assertNotIn("storage_dir", rag_capability["index_summary"])
            self.assertNotIn("asset_dir", rag_capability["knowledge_asset_summary"])

            capability_detail_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "capabilities_get_detail",
                        "arguments": {"capability_name": "export_tools"},
                    },
                },
            )
            self.assertEqual(capability_detail_call.status_code, 200)
            capability_detail_result = capability_detail_call.json()["result"]["structuredContent"]
            self.assertEqual(capability_detail_result["capability"]["name"], "export_tools")
            self.assertNotIn("config", capability_detail_result["capability"])
            self.assertNotIn("output_dir", capability_detail_result["capability"])
            self.assertNotIn("export_dir", capability_detail_result["capability"])

            artifacts_list_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "artifacts_list",
                        "arguments": {"limit": 5},
                    },
                },
            )
            self.assertEqual(artifacts_list_call.status_code, 200)
            artifacts_list_result = artifacts_list_call.json()["result"]["structuredContent"]
            self.assertEqual(artifacts_list_result["count"], 2)
            self.assertIn("v2_intelligence_blueprint_20260517_101010.json", {artifact["name"] for artifact in artifacts_list_result["artifacts"]})
            self.assertNotIn("path", artifacts_list_result["artifacts"][0])

            artifact_detail_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "artifacts_get_detail",
                        "arguments": {
                            "artifact_name": "v2_intelligence_blueprint_20260517_101010.json",
                            "max_chars": 256,
                        },
                    },
                },
            )
            self.assertEqual(artifact_detail_call.status_code, 200)
            artifact_detail_result = artifact_detail_call.json()["result"]["structuredContent"]
            self.assertEqual(artifact_detail_result["artifact"]["name"], "v2_intelligence_blueprint_20260517_101010.json")
            self.assertEqual(artifact_detail_result["content_kind"], "json")
            self.assertIn("mission", artifact_detail_result["top_level_keys"])
            self.assertTrue(artifact_detail_result["truncated"])
            self.assertNotIn("path", artifact_detail_result["artifact"])

            token_record = self.security_manager.get_access_token(int(mcp_token["token"]["id"]))
            self.assertIsNotNone(token_record)
            self.assertEqual(token_record["use_count"], 6)
        finally:
            web_app.capability_manager.get_summary = original_get_summary
            web_app.capability_manager.list_capabilities = original_list_capabilities
            web_app.capability_manager.get_capability_state = original_get_capability_state

    def test_external_mcp_artifact_detail_rejects_non_catalog_output_file(self):
        output_dir = self.temp_path / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "notes.txt").write_text(
            "This file exists under output but is not part of the published DT4SMS artifact catalog.",
            encoding="utf-8",
        )

        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Catalog Boundary MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        detail_call = self.client.post(
            "/api/external/mcp",
            headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "artifacts_get_detail",
                    "arguments": {"artifact_name": "notes.txt"},
                },
            },
        )
        self.assertEqual(detail_call.status_code, 404)
        self.assertEqual(detail_call.json()["error"]["message"], "Report not found")

    def test_external_mcp_exposes_discovery_context_tools(self):
        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Discovery Context MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        original_build_discovery_dashboard_payload = web_app.build_discovery_dashboard_payload
        original_build_session_runbook_payload = web_app.build_session_runbook_payload
        original_build_discovery_compare_payload = web_app.build_discovery_compare_payload
        original_load_latest_v2_blueprint = web_app.load_latest_v2_blueprint

        latest_session = {
            "timestamp": "20260517_101010",
            "readiness_score": 88,
            "overview": {"total_indexes": 12, "total_sourcetypes": 24, "total_hosts": 6},
            "stats": {"recommendation_count": 7},
            "mcp_capabilities": {"tool_count": 9},
            "sensitive_local_path": "C:/secret/latest.json",
        }
        previous_session = {
            "timestamp": "20260516_090000",
            "readiness_score": 77,
            "overview": {"total_indexes": 11, "total_sourcetypes": 20, "total_hosts": 5},
            "stats": {"recommendation_count": 5},
            "mcp_capabilities": {"tool_count": 8},
            "sensitive_local_path": "C:/secret/previous.json",
        }

        web_app.build_discovery_dashboard_payload = lambda: {
            "has_data": True,
            "latest": dict(latest_session),
            "previous": dict(previous_session),
            "kpis": {
                "readiness_score": 88,
                "total_indexes": 12,
                "total_sourcetypes": 24,
                "recommendation_count": 7,
                "tool_count": 9,
            },
            "trends": {
                "indexes_delta": 1,
                "sourcetypes_delta": 4,
                "recommendations_delta": 2,
                "readiness_delta": 11,
            },
            "sessions": [dict(latest_session), dict(previous_session)],
        }
        web_app.build_session_runbook_payload = lambda timestamp=None, persona="admin", voice="direct": {
            "has_data": True,
            "session": dict(latest_session),
            "persona": str(persona or "admin"),
            "voice": str(voice or "direct"),
            "voice_label": "Executive Brief" if str(voice or "direct") == "executive" else "Direct Ops",
            "title": "Admin Operational Runbook",
            "filename": f"runbook_admin_{str(voice or 'direct')}_20260517_101010.md",
            "markdown": "# Discovery Operational Runbook\n\nLeadership ask: Investigate queue pressure first.",
            "steps": [
                {
                    "step": 1,
                    "title": "Investigate queue pressure",
                    "owner": "Splunk Admin",
                    "effort": "medium",
                    "details": "Check parsing and indexing queues.",
                    "next_step": "Open pipeline health dashboards.",
                }
            ],
            "sessions": [dict(latest_session), dict(previous_session)],
        }
        web_app.build_discovery_compare_payload = lambda current_selection=None, baseline_selection=None: {
            "has_data": True,
            "current": dict(latest_session),
            "baseline": dict(previous_session),
            "metrics": {
                "readiness": {"current": 88, "baseline": 77, "delta": 11},
                "indexes": {"current": 12, "baseline": 11, "delta": 1},
            },
            "persona_deltas": {"admin_actions_delta": 2, "analyst_tracks_delta": 1},
            "sessions": [dict(latest_session), dict(previous_session)],
        }
        web_app.load_latest_v2_blueprint = lambda: {
            "mission": "Platform health triage",
            "recommendations": ["Investigate queue pressure first."],
            "confidence": 0.91,
            "sensitive_local_path": "C:/secret/blueprint.json",
            "_artifact": {
                "name": "v2_intelligence_blueprint_20260517_101010.json",
                "modified": "2026-05-17T10:30:00",
                "size": 2048,
                "path": "C:/secret/blueprint.json",
            },
        }

        headers = {
            "Authorization": f"Bearer {mcp_token['access_token']}",
            "Content-Type": "application/json",
        }

        try:
            tools_list = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            self.assertEqual(tools_list.status_code, 200)
            tool_names = {tool["name"] for tool in tools_list.json()["result"]["tools"]}
            self.assertTrue(
                {
                    "discovery_get_dashboard",
                    "discovery_get_latest_intelligence",
                    "discovery_get_runbook",
                    "discovery_compare_sessions",
                }.issubset(tool_names)
            )

            dashboard_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "discovery_get_dashboard", "arguments": {}},
                },
            )
            self.assertEqual(dashboard_call.status_code, 200)
            dashboard_result = dashboard_call.json()["result"]["structuredContent"]
            self.assertEqual(dashboard_result["latest_session"]["timestamp"], "20260517_101010")
            self.assertEqual(dashboard_result["kpis"]["readiness_score"], 88)
            self.assertNotIn("sensitive_local_path", json.dumps(dashboard_result))

            intelligence_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "discovery_get_latest_intelligence", "arguments": {}},
                },
            )
            self.assertEqual(intelligence_call.status_code, 200)
            intelligence_result = intelligence_call.json()["result"]["structuredContent"]
            self.assertEqual(intelligence_result["artifact"]["name"], "v2_intelligence_blueprint_20260517_101010.json")
            self.assertEqual(intelligence_result["blueprint"]["mission"], "Platform health triage")
            self.assertNotIn("path", intelligence_result["artifact"])
            self.assertNotIn("_artifact", intelligence_result["blueprint"])
            self.assertNotIn("sensitive_local_path", json.dumps(intelligence_result))

            runbook_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "discovery_get_runbook",
                        "arguments": {"persona": "admin", "timestamp": "20260517_101010", "voice": "executive"},
                    },
                },
            )
            self.assertEqual(runbook_call.status_code, 200)
            runbook_result = runbook_call.json()["result"]["structuredContent"]
            self.assertEqual(runbook_result["session"]["timestamp"], "20260517_101010")
            self.assertEqual(runbook_result["persona"], "admin")
            self.assertEqual(runbook_result["voice"], "executive")
            self.assertEqual(runbook_result["voice_label"], "Executive Brief")
            self.assertIn("Leadership ask:", runbook_result["markdown"])
            self.assertNotIn("sensitive_local_path", json.dumps(runbook_result))

            compare_call = self.client.post(
                "/api/external/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "discovery_compare_sessions",
                        "arguments": {
                            "current_selection": "latest",
                            "baseline_selection": "previous",
                        },
                    },
                },
            )
            self.assertEqual(compare_call.status_code, 200)
            compare_result = compare_call.json()["result"]["structuredContent"]
            self.assertEqual(compare_result["current_session"]["timestamp"], "20260517_101010")
            self.assertEqual(compare_result["metrics"]["readiness"]["delta"], 11)
            self.assertNotIn("sensitive_local_path", json.dumps(compare_result))
        finally:
            web_app.build_discovery_dashboard_payload = original_build_discovery_dashboard_payload
            web_app.build_session_runbook_payload = original_build_session_runbook_payload
            web_app.build_discovery_compare_payload = original_build_discovery_compare_payload
            web_app.load_latest_v2_blueprint = original_load_latest_v2_blueprint

    def test_build_session_runbook_payload_reflects_selected_voice(self):
        original_load_discovery_sessions = web_app.load_discovery_sessions
        original_hydrate_discovery_session = web_app.hydrate_discovery_session
        original_resolve_session_selection = web_app._resolve_session_selection

        session_payload = {
            "timestamp": "20260517_101010",
            "readiness_score": 82,
            "personas": {
                "executive": {
                    "headline": "Discovery posture is improving, but telemetry ownership is still fragmented.",
                    "business_value_themes": [
                        "Telemetry alignment reduces investigative delay.",
                    ],
                    "next_90_day_focus": [
                        "Assign a single owner for onboarding missing high-value data sources.",
                    ],
                }
            },
        }

        try:
            web_app.load_discovery_sessions = lambda scope_key=None: [dict(session_payload)]
            web_app._resolve_session_selection = lambda sessions, selection, default_index: sessions[0]
            web_app.hydrate_discovery_session = lambda session: session

            result = web_app.build_session_runbook_payload(persona="executive", voice="executive")

            self.assertTrue(result["has_data"])
            self.assertEqual(result["voice"], "executive")
            self.assertEqual(result["voice_label"], "Executive Brief")
            self.assertEqual(result["filename"], "runbook_executive_executive_20260517_101010.md")
            self.assertEqual(result["title"], "Executive Brief Executive Operational Runbook")
            self.assertIn("**Voice:** Executive Brief", result["markdown"])
            self.assertIn("Quarter Priority 1", result["markdown"])
            self.assertIn("Carry this into the next planning cycle with an accountable owner.", result["markdown"])
        finally:
            web_app.load_discovery_sessions = original_load_discovery_sessions
            web_app.hydrate_discovery_session = original_hydrate_discovery_session
            web_app._resolve_session_selection = original_resolve_session_selection

    def test_external_mcp_rejects_unknown_capability_detail_request(self):
        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Unknown Capability MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        response = self.client.post(
            "/api/external/mcp",
            headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "capabilities_get_detail",
                    "arguments": {"capability_name": "does_not_exist"},
                },
            },
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["message"], "Unknown capability 'does_not_exist'")

    def test_external_mcp_rejects_invalid_artifact_kind_filter(self):
        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Invalid Artifact Filter MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        response = self.client.post(
            "/api/external/mcp",
            headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "artifacts_list",
                    "arguments": {"artifact_kind": "package"},
                },
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["message"], "Tool argument 'artifact_kind' must be 'report' or 'infographic'")

    def test_external_mcp_returns_binary_artifact_detail_without_preview(self):
        output_dir = self.temp_path / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "v2_summary_infographic_20260517_101010.png").write_bytes(b"\x89PNG\r\n\x1a\nmockpngdata")

        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Binary Artifact MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        response = self.client.post(
            "/api/external/mcp",
            headers={"Authorization": f"Bearer {mcp_token['access_token']}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "artifacts_get_detail",
                    "arguments": {"artifact_name": "v2_summary_infographic_20260517_101010.png"},
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()["result"]["structuredContent"]
        self.assertEqual(payload["content_kind"], "binary")
        self.assertIsNone(payload["preview"])
        self.assertFalse(payload["truncated"])
        self.assertIn("preview_unavailable_reason", payload)

    def test_external_mcp_rate_limits_requests_per_token(self):
        self.assertTrue(
            self.config_manager.update_security(
                auth_enabled=True,
                external_mcp_enabled=True,
                external_mcp_rate_limit_requests=2,
                external_mcp_rate_limit_window_seconds=60,
                session_timeout_minutes=60,
                password_min_length=14,
            )
        )

        bootstrap = self.security_manager.ensure_bootstrap_admin(require_password_reset=False)
        admin_user = self.security_manager.get_user_by_username(bootstrap["username"])
        self.assertIsNotNone(admin_user)

        mcp_token = self.security_manager.issue_access_token(
            name="Rate Limited Inbound MCP Token",
            token_type="inbound_mcp",
            scopes=["mcp:tools:read"],
            owner_user_id=int(admin_user["id"]),
            created_by_user_id=int(admin_user["id"]),
            expires_in_days=7,
        )

        headers = {
            "Authorization": f"Bearer {mcp_token['access_token']}",
            "Content-Type": "application/json",
        }
        initialize_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": web_app.EXTERNAL_MCP_PROTOCOL_VERSION,
                "clientInfo": {"name": "rate-limit-test", "version": "1.0"},
            },
        }

        first = self.client.post("/api/external/mcp", headers=headers, json={**initialize_payload, "id": 1})
        second = self.client.post("/api/external/mcp", headers=headers, json={**initialize_payload, "id": 2})
        third = self.client.post("/api/external/mcp", headers=headers, json={**initialize_payload, "id": 3})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 429)
        self.assertIn("rate limit exceeded", third.json()["detail"].lower())
        self.assertIn("retry-after", third.headers)

        token_record = self.security_manager.get_access_token(int(mcp_token["token"]["id"]))
        self.assertIsNotNone(token_record)
        self.assertEqual(token_record["use_count"], 2)