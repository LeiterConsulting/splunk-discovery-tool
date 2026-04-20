import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from capabilities.install_manager import CapabilityManager
from capabilities.models import CapabilityConfig
from capabilities.rag.indexer import ArtifactSourceIndexer
from capabilities.registry import CapabilityRegistry
from capabilities.tools import DeterministicExportProvider, SplunkDeepLinkProvider, VisualizationPreviewProvider
from config_manager import ConfigManager


class CapabilityFrameworkTests(unittest.TestCase):
    def test_bootstrap_persists_known_capabilities(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())

                safe_config = manager.config_manager.export_safe()
                self.assertIn("rag_local", safe_config["capabilities"])
                self.assertIn("rag_chromadb", safe_config["capabilities"])
                self.assertFalse(safe_config["capabilities"]["rag_local"]["installed"])
                self.assertEqual(safe_config["capabilities"]["rag_local"]["install_method"], "internal")

                reloaded = ConfigManager(str(config_path))
                self.assertIn("rag_local", reloaded.export_safe()["capabilities"])
            finally:
                os.chdir(original_cwd)

    def test_rag_local_install_enable_and_query_flow(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            output_dir = temp_path / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "v2_insights_brief_test.md").write_text(
                "Platform health needs attention. _internal shows ingestion delays and queue pressure. "
                "Recommended next step: validate platform health and ingestion.",
                encoding="utf-8",
            )
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                config_manager = ConfigManager(str(config_path))
                manager = CapabilityManager(config_manager, registry=CapabilityRegistry())

                install_result = manager.install_capability("rag_local")
                self.assertTrue(install_result.ok)

                config_result = manager.update_capability_config(
                    "rag_local",
                    {"source_dir": str(output_dir)},
                )
                self.assertTrue(config_result.ok)

                enable_result = manager.enable_capability("rag_local")
                self.assertTrue(enable_result.ok)
                self.assertEqual(enable_result.details["status"], "ready")

                rag_result = manager.get_rag_context("What should I improve for platform health next?", max_chunks=2)

                self.assertEqual(rag_result["capability"], "rag_local")
                self.assertIn("OPTIONAL LOCAL RAG CONTEXT", rag_result["context_text"])
                self.assertGreaterEqual(len(rag_result["chunks"]), 1)

                reloaded_manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())
                state = reloaded_manager.get_capability_state("rag_local")

                self.assertTrue(state["installed"])
                self.assertTrue(state["enabled"])
                self.assertEqual(state["config"]["source_dir"], str(output_dir))
                self.assertEqual(state["health_status"], "ready")
            finally:
                os.chdir(original_cwd)

    def test_enable_returns_success_when_capability_health_is_degraded(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            empty_output_dir = temp_path / "output"
            empty_output_dir.mkdir(parents=True, exist_ok=True)
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())

                install_result = manager.install_capability("rag_local")
                self.assertTrue(install_result.ok)

                manager.update_capability_config("rag_local", {"source_dir": str(empty_output_dir)})
                enable_result = manager.enable_capability("rag_local")

                self.assertTrue(enable_result.ok)
                self.assertTrue(enable_result.state["enabled"])
                self.assertEqual(enable_result.state["health_status"], "degraded")
                self.assertIn("Capability enabled", enable_result.message or "Capability enabled")
            finally:
                os.chdir(original_cwd)

    def test_chroma_indexer_collects_typed_documents(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            output_dir = temp_path / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "v2_intelligence_blueprint_test.json").write_text(
                json.dumps(
                    {
                        "readiness_score": 76,
                        "overview": {
                            "total_indexes": 47,
                            "total_sourcetypes": 24,
                            "total_hosts": 4,
                            "total_sources": 12,
                            "data_volume_24h": "~26.2GB",
                            "splunk_version": "10.0.1",
                        },
                        "recommendations": [
                            {
                                "title": "Platform Health and Splunk Operational Monitoring",
                                "priority": "high",
                                "description": "Validate ingestion, queue pressure, and scheduler health.",
                            }
                        ],
                        "coverage_gaps": [
                            {
                                "gap": "Network connectivity monitoring",
                                "priority": "medium",
                                "why_it_matters": "Packet loss and latency are not yet covered.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (output_dir / "v2_operator_runbook_test.md").write_text(
                "## Queue Pressure\n\nOperators should validate queue pressure and ingestion delays in _internal before escalating.",
                encoding="utf-8",
            )
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())
                manager.update_capability_config(
                    "rag_chromadb",
                    {
                        "source_dir": str(output_dir),
                        "storage_dir": str(output_dir / "rag" / "chromadb"),
                    },
                )

                definition = manager.registry.get_definition("rag_chromadb")
                config = manager.config_manager.get_capability("rag_chromadb")
                indexer = ArtifactSourceIndexer(config=config, definition=definition)
                documents = indexer.collect_documents()

                self.assertGreaterEqual(len(documents), 3)
                source_types = {document.source_type for document in documents}
                self.assertIn("discovery_artifact", source_types)
                self.assertIn("runbook", source_types)
                self.assertTrue(any("Platform Health" in document.content for document in documents))
            finally:
                os.chdir(original_cwd)

    def test_rag_chromadb_reindex_and_query_flow(self):
        if importlib.util.find_spec("chromadb") is None:
            self.skipTest("chromadb is not installed in the active environment")

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            output_dir = temp_path / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "v2_operator_runbook_test.md").write_text(
                "Queue pressure and ingestion delays require validation in _internal. Scheduler lag and blocked pipelines should be checked next.",
                encoding="utf-8",
            )
            (output_dir / "v2_ai_summary_test.json").write_text(
                json.dumps(
                    {
                        "ai_summary": "The latest artifacts call out queue pressure, ingestion delay, and scheduler backlog as the top operational concerns."
                    }
                ),
                encoding="utf-8",
            )
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())

                install_result = manager.install_capability("rag_chromadb")
                self.assertTrue(install_result.ok)

                manager.update_capability_config(
                    "rag_chromadb",
                    {
                        "source_dir": str(output_dir),
                        "storage_dir": str(output_dir / "rag" / "chromadb"),
                    },
                )

                enable_result = manager.enable_capability("rag_chromadb")
                self.assertTrue(enable_result.ok)
                self.assertTrue(enable_result.state["enabled"])

                reindex_result = manager.reindex_capability("rag_chromadb")
                self.assertTrue(reindex_result.ok)
                self.assertGreater(reindex_result.details["index_summary"]["document_count"], 0)

                test_result = manager.test_capability("rag_chromadb")
                self.assertTrue(test_result.ok)
                self.assertEqual(test_result.state["health_status"], "ready")

                rag_result = manager.get_rag_context("What do the artifacts say about queue pressure and ingestion delays?", max_chunks=2)

                self.assertEqual(rag_result["capability"], "rag_chromadb")
                self.assertIn("OPTIONAL CHROMADB RAG CONTEXT", rag_result["context_text"])
                self.assertGreaterEqual(len(rag_result["chunks"]), 1)
                self.assertIn("source_type", rag_result["chunks"][0]["metadata"])
            finally:
                os.chdir(original_cwd)

    def test_deeplink_provider_derives_web_base_url_from_mcp_url(self):
        definition = CapabilityRegistry().get_definition("splunk_deeplink_tools")
        config = CapabilityConfig(
            name="splunk_deeplink_tools",
            installed=True,
            enabled=True,
            config=dict(definition.default_config),
        )

        provider = SplunkDeepLinkProvider(
            config=config,
            definition=definition,
            mcp_url="https://splunk.example.local:8089/services/mcp",
        )

        self.assertEqual(provider.resolve_web_base_url(), "https://splunk.example.local:8000")
        self.assertEqual(provider.resolve_base_url_source(), "mcp.url")

    def test_deeplink_provider_prefers_override_and_encodes_search_params(self):
        definition = CapabilityRegistry().get_definition("splunk_deeplink_tools")
        config = CapabilityConfig(
            name="splunk_deeplink_tools",
            installed=True,
            enabled=True,
            config={
                **definition.default_config,
                "web_base_url": "https://splunkweb.example.local/splunk",
                "default_app": "search",
            },
        )

        provider = SplunkDeepLinkProvider(
            config=config,
            definition=definition,
            mcp_url="https://ignored.example.local:8089/services/mcp",
        )
        deeplink = provider.build_search_link(
            "index=_internal error | stats count by host",
            earliest="-2h",
            latest="now",
        )
        parsed = urlsplit(deeplink["url"])
        params = parse_qs(parsed.query)

        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/en-US/', 1)[0]}", "https://splunkweb.example.local/splunk")
        self.assertEqual(params["q"][0], "search index=_internal error | stats count by host")
        self.assertEqual(params["earliest"][0], "-2h")
        self.assertEqual(params["latest"][0], "now")
        self.assertEqual(deeplink["base_url_source"], "capability_config.web_base_url")

    def test_deeplink_install_enable_test_and_build_flow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())
                manager.config_manager.update_mcp(url="https://splunk.example.local:8089/services/mcp")

                install_result = manager.install_capability("splunk_deeplink_tools")
                self.assertTrue(install_result.ok)

                enable_result = manager.enable_capability("splunk_deeplink_tools")
                self.assertTrue(enable_result.ok)
                self.assertEqual(enable_result.state["health_status"], "ready")

                test_result = manager.test_capability("splunk_deeplink_tools")
                self.assertTrue(test_result.ok)
                self.assertIn("sample_deeplink", test_result.details)

                build_result = manager.build_deeplink(
                    "splunk_deeplink_tools",
                    "search",
                    {
                        "query": "index=_internal | stats count by sourcetype",
                        "earliest": "-7d",
                        "latest": "now",
                    },
                )
                self.assertTrue(build_result.ok)
                deeplink = build_result.details["deeplink"]
                params = parse_qs(urlsplit(deeplink["url"]).query)

                self.assertEqual(deeplink["base_url"], "https://splunk.example.local:8000")
                self.assertEqual(params["q"][0], "search index=_internal | stats count by sourcetype")
                self.assertEqual(params["earliest"][0], "-7d")
                self.assertEqual(params["latest"][0], "now")
            finally:
                os.chdir(original_cwd)

    def test_deeplink_enable_can_succeed_while_health_is_degraded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())
                manager.config_manager.update_mcp(url="")

                install_result = manager.install_capability("splunk_deeplink_tools")
                self.assertTrue(install_result.ok)

                enable_result = manager.enable_capability("splunk_deeplink_tools")
                self.assertTrue(enable_result.ok)
                self.assertEqual(enable_result.state["health_status"], "degraded")
                self.assertIn("base url", enable_result.message.lower())
            finally:
                os.chdir(original_cwd)

    def test_visualization_provider_builds_line_and_bar_previews(self):
        definition = CapabilityRegistry().get_definition("visualization_tools")
        config = CapabilityConfig(
            name="visualization_tools",
            installed=True,
            enabled=True,
            config=dict(definition.default_config),
        )
        provider = VisualizationPreviewProvider(config=config, definition=definition)

        line_preview = provider.build_preview(
            [
                {"_time": "2026-04-19 14:00:00.000 EDT", "count": "42"},
                {"_time": "2026-04-19 15:00:00.000 EDT", "count": "57"},
                {"_time": "2026-04-19 16:00:00.000 EDT", "count": "39"},
            ],
            payload={"query_shape": "time_series"},
        )
        bar_preview = provider.build_preview(
            [
                {"sourcetype": "WinEventLog:Security", "count": "18"},
                {"sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "count": "11"},
                {"sourcetype": "splunkd", "count": "7"},
            ],
            payload={"query_shape": "aggregation"},
        )

        self.assertEqual(line_preview["chart_type"], "line")
        self.assertEqual(line_preview["x_field"], "_time")
        self.assertEqual(line_preview["y_field"], "count")
        self.assertEqual(len(line_preview["points"]), 3)
        self.assertEqual(bar_preview["chart_type"], "bar")
        self.assertEqual(bar_preview["y_field"], "count")
        self.assertGreaterEqual(len(bar_preview["points"]), 2)

    def test_visualization_install_enable_test_and_build_flow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())

                install_result = manager.install_capability("visualization_tools")
                self.assertTrue(install_result.ok)

                enable_result = manager.enable_capability("visualization_tools")
                self.assertTrue(enable_result.ok)
                self.assertEqual(enable_result.state["health_status"], "ready")

                test_result = manager.test_capability("visualization_tools")
                self.assertTrue(test_result.ok)
                self.assertIn("supported_chart_types", test_result.details["details"])

                build_result = manager.build_visualization(
                    "visualization_tools",
                    {
                        "rows": [
                            {"_time": "2026-04-19 14:00:00.000 EDT", "count": "42"},
                            {"_time": "2026-04-19 15:00:00.000 EDT", "count": "57"},
                            {"_time": "2026-04-19 16:00:00.000 EDT", "count": "39"},
                        ],
                        "query_shape": "time_series",
                    },
                )
                self.assertTrue(build_result.ok)
                self.assertEqual(build_result.details["visualization"]["chart_type"], "line")
                self.assertEqual(build_result.state["preview_enabled"], True)
            finally:
                os.chdir(original_cwd)

    def test_export_provider_builds_bundle_and_manifest(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            output_dir = temp_path / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = "20260419_154500"
            (output_dir / f"v2_intelligence_blueprint_{timestamp}.json").write_text(
                json.dumps({"overview": {"total_indexes": 47, "total_sourcetypes": 24, "total_hosts": 4, "data_volume_24h": "~26.2GB"}}),
                encoding="utf-8",
            )
            (output_dir / f"v2_insights_brief_{timestamp}.md").write_text(
                "Executive brief for the latest discovery session.",
                encoding="utf-8",
            )
            (output_dir / "discovery_sessions.json").write_text(
                json.dumps(
                    [
                        {
                            "timestamp": timestamp,
                            "created_at": "2026-04-19T15:45:00",
                            "overview": {
                                "total_indexes": 47,
                                "total_sourcetypes": 24,
                                "total_hosts": 4,
                                "data_volume_24h": "~26.2GB",
                            },
                            "report_paths": [
                                f"v2_intelligence_blueprint_{timestamp}.json",
                                f"v2_insights_brief_{timestamp}.md",
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )

            definition = CapabilityRegistry().get_definition("export_tools")
            config = CapabilityConfig(
                name="export_tools",
                installed=True,
                enabled=True,
                config={
                    **definition.default_config,
                    "source_dir": str(output_dir),
                    "export_dir": str(output_dir / "exports"),
                },
            )
            provider = DeterministicExportProvider(config=config, definition=definition)

            export_result = provider.build_export(
                {
                    "timestamp": timestamp,
                    "persona": "admin",
                    "runbook_markdown": "# Admin Runbook\n\nValidate queue pressure and ingestion delays.",
                    "runbook_filename": f"runbook_admin_{timestamp}.md",
                    "title": "Platform Health Export",
                }
            )

            zip_path = Path(export_result["bundle_path"])
            self.assertTrue(zip_path.exists())
            self.assertTrue((output_dir / "exports" / export_result["manifest_name"]).exists())
            self.assertTrue((output_dir / "exports" / export_result["summary_name"]).exists())
            self.assertEqual(export_result["artifact_count"], 2)
            self.assertIn(f"v2_intelligence_blueprint_{timestamp}.json", export_result["included_files"])

            with zipfile.ZipFile(zip_path, "r") as archive:
                names = set(archive.namelist())
                self.assertIn("manifest.json", names)
                self.assertIn("README.md", names)
                self.assertIn(f"artifacts/v2_intelligence_blueprint_{timestamp}.json", names)
                self.assertIn(f"generated/runbook_admin_{timestamp}.md", names)

    def test_export_install_enable_test_and_build_flow(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "config.encrypted"
            output_dir = temp_path / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = "20260419_160000"
            (output_dir / f"v2_intelligence_blueprint_{timestamp}.json").write_text(
                json.dumps({"overview": {"total_indexes": 47, "total_sourcetypes": 24, "total_hosts": 4}}),
                encoding="utf-8",
            )
            (output_dir / f"v2_operator_runbook_{timestamp}.md").write_text(
                "Operator runbook content.",
                encoding="utf-8",
            )
            (output_dir / "discovery_sessions.json").write_text(
                json.dumps(
                    [
                        {
                            "timestamp": timestamp,
                            "created_at": "2026-04-19T16:00:00",
                            "overview": {"total_indexes": 47, "total_sourcetypes": 24, "total_hosts": 4},
                            "report_paths": [
                                f"v2_intelligence_blueprint_{timestamp}.json",
                                f"v2_operator_runbook_{timestamp}.md",
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            original_cwd = Path.cwd()

            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(config_path)), registry=CapabilityRegistry())

                install_result = manager.install_capability("export_tools")
                self.assertTrue(install_result.ok)

                config_result = manager.update_capability_config(
                    "export_tools",
                    {
                        "source_dir": str(output_dir),
                        "export_dir": str(output_dir / "exports"),
                    },
                )
                self.assertTrue(config_result.ok)

                enable_result = manager.enable_capability("export_tools")
                self.assertTrue(enable_result.ok)
                self.assertEqual(enable_result.state["health_status"], "ready")

                test_result = manager.test_capability("export_tools")
                self.assertTrue(test_result.ok)
                self.assertEqual(test_result.details["details"]["latest_session_timestamp"], timestamp)

                build_result = manager.build_export(
                    "export_tools",
                    {
                        "timestamp": timestamp,
                        "persona": "executive",
                        "runbook_markdown": "# Executive Runbook\n\nFocus on readiness and business impact.",
                        "runbook_filename": f"runbook_executive_{timestamp}.md",
                    },
                )
                self.assertTrue(build_result.ok)
                export_payload = build_result.details["export"]
                self.assertEqual(export_payload["session_timestamp"], timestamp)
                self.assertEqual(export_payload["persona"], "executive")
                self.assertTrue(Path(export_payload["bundle_path"]).exists())
            finally:
                os.chdir(original_cwd)


if __name__ == "__main__":
    unittest.main()