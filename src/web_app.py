"""
FastAPI Web Application for Splunk MCP Use Case Discovery Tool

A modern web-based interface providing real-time progress tracking,
animated progress indicators, and comprehensive report management.
"""

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import asyncio
import base64
import json
import os
import re
import time
import sys
import socket
import subprocess
from urllib.parse import quote
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import uvicorn
import httpx
from pydantic import BaseModel

# DT4SMS: Use encrypted config manager instead of YAML
from config_manager import ConfigManager
from capabilities import CapabilityManager, CapabilityRegistry
from discovery.engine import DiscoveryEngine
from discovery.v2_pipeline import DiscoveryV2Pipeline
from llm.factory import (
    LLMClientFactory,
    filter_openai_generation_models,
    get_openai_model_capabilities,
    is_openai_image_generation_model,
    normalize_provider_name,
)
from discovery.context_manager import get_context_manager
from frontend_legacy import get_frontend_html

# Ensure console/log prints do not crash on Windows code pages (cp1252, etc.)
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Initialize encrypted config manager
config_manager = ConfigManager("config.encrypted")
capability_registry = CapabilityRegistry()
capability_manager = CapabilityManager(config_manager, registry=capability_registry)

# Module-level LLM client cache for performance
_cached_llm_client = None
_cached_config_hash = None


def should_enable_rag_context_by_default() -> bool:
    """Return True when any persisted optional RAG capability is installed and enabled."""
    capability_configs = config_manager.list_capabilities()
    for definition in capability_registry.rag_definitions():
        config = capability_configs.get(definition.name)
        if config and config.installed and config.enabled:
            return True
    return False


def build_default_chat_settings() -> Dict[str, Any]:
    """Build default session chat settings, including capability-aware RAG defaults."""
    return {
        # Discovery Settings
        "max_execution_time": 90,
        "max_iterations": 5,
        "discovery_freshness_days": 7,

        # LLM Behavior
        "max_tokens": 16000,
        "temperature": 0.7,
        "context_history": 6,

        # Performance Tuning
        "max_retry_delay": 300,
        "max_retries": 5,
        "query_sample_size": 2,

        # Quality Control
        "quality_threshold": 70,
        "convergence_detection": 5,

        # Demo Augmentation
        "enable_splunk_augmentation": True,
        "enable_rag_context": should_enable_rag_context_by_default(),
        "rag_max_chunks": 3,
    }


def detect_chat_runtime_provider(config: Any, llm_client: Any = None) -> str:
    """Resolve the effective provider used by the active chat runtime."""
    configured_provider = normalize_provider_name(getattr(getattr(config, "llm", None), "provider", ""))
    if configured_provider and configured_provider not in {"custom", "custom endpoint"}:
        return configured_provider

    runtime_provider = normalize_provider_name(str(getattr(llm_client, "provider_type", "") or ""))
    if runtime_provider and runtime_provider != "custom":
        return runtime_provider

    endpoint_url = str(getattr(getattr(config, "llm", None), "endpoint_url", "") or "").lower()
    if "ollama" in endpoint_url or ":11434" in endpoint_url:
        return "ollama"

    return configured_provider or runtime_provider or "generic"


def build_chat_runtime_profile(config: Any, llm_client: Any = None) -> Dict[str, Any]:
    """Return provider-aware chat behavior defaults for the active runtime."""
    try:
        session_max_tokens = int(chat_session_settings.get("max_tokens", 16000) or 16000)
    except (TypeError, ValueError):
        session_max_tokens = 16000
    try:
        context_history_limit = int(chat_session_settings.get("context_history", 6) or 6)
    except (TypeError, ValueError):
        context_history_limit = 6

    effective_provider = detect_chat_runtime_provider(config, llm_client)
    model_name = str(getattr(getattr(config, "llm", None), "model", "") or "").strip().lower()

    profile = {
        "provider": effective_provider,
        "model": model_name,
        "use_compact_prompt": effective_provider in {"custom", "generic", "ollama", "vllm", "local-vllm"},
        "short_circuit_greetings": effective_provider in {"custom", "generic", "ollama", "vllm", "local-vllm"},
        "context_history_limit": max(1, context_history_limit),
        "initial_max_tokens": max(400, min(2000, int(session_max_tokens * 0.15))),
        "followup_max_tokens": max(500, min(2500, int(session_max_tokens * 0.18))),
        "final_max_tokens": max(600, min(3000, int(session_max_tokens * 0.25))),
        "retry_max_tokens": max(400, min(2000, int(session_max_tokens * 0.15))),
        "temperature_multiplier": 1.0,
        "reasoning_guard": "",
    }

    if effective_provider == "ollama":
        profile.update({
            "use_compact_prompt": True,
            "short_circuit_greetings": True,
            "context_history_limit": min(profile["context_history_limit"], 4),
            "initial_max_tokens": max(384, min(1200, int(session_max_tokens * 0.10))),
            "followup_max_tokens": max(512, min(1400, int(session_max_tokens * 0.12))),
            "final_max_tokens": max(640, min(1800, int(session_max_tokens * 0.16))),
            "retry_max_tokens": max(384, min(1200, int(session_max_tokens * 0.10))),
            "temperature_multiplier": 0.9,
            "reasoning_guard": (
                "8) Do not emit <think>, </think>, <thinking>, or chain-of-thought markup. "
                "Return either a direct answer or a single <TOOL_CALL> block plus one short sentence."
            ),
        })

    if effective_provider in {"vllm", "local-vllm"}:
        profile.update({
            "use_compact_prompt": True,
            "short_circuit_greetings": True,
            "context_history_limit": min(profile["context_history_limit"], 5),
            "temperature_multiplier": 0.95,
        })

    return profile


chat_settings_explicit_overrides = {
    "enable_rag_context": False,
}


def sync_chat_settings_with_capability_defaults() -> None:
    """Refresh capability-aware chat defaults unless explicitly changed this session."""
    if not chat_settings_explicit_overrides.get("enable_rag_context", False):
        chat_session_settings["enable_rag_context"] = should_enable_rag_context_by_default()

def get_or_create_llm_client(config):
    """Get cached LLM client or create new one if config changed."""
    global _cached_llm_client, _cached_config_hash
    
    # Generate hash from relevant config values
    config_hash = hash(f"{config.llm.provider}{config.llm.endpoint_url}{config.llm.model}{config.llm.api_key}")
    
    # Return cached client if config hasn't changed
    if _cached_llm_client is not None and _cached_config_hash == config_hash:
        return _cached_llm_client
    
    provider_name = normalize_provider_name(config.llm.provider)
    endpoint_url = config.llm.endpoint_url

    if provider_name in {"azure", "custom"} and not endpoint_url:
        raise ValueError(f"Provider '{config.llm.provider}' requires endpoint_url")

    _cached_llm_client = LLMClientFactory.create_client(
        provider=provider_name,
        custom_endpoint=endpoint_url,
        api_key=config.llm.api_key,
        model=config.llm.model
    )
    print(f"[LLM Cache] Created {provider_name} client ({config.llm.model})")
    
    _cached_config_hash = config_hash
    return _cached_llm_client


app = FastAPI(
    title="Discovery Tool for Splunk MCP Server (DT4SMS)",
    description="Intelligent environment analysis with encrypted config, AI-powered summarization, and advanced SPL generation",
    version="1.0.0"
)

FRONTEND_STATIC_DIR = Path(__file__).with_name("static")
FRONTEND_INDEX_PATH = FRONTEND_STATIC_DIR / "index.html"

app.mount("/static", StaticFiles(directory=str(FRONTEND_STATIC_DIR), check_dir=False), name="static")

# Security: Allow external access for development/testing
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Allow any host - use specific IPs/domains in production
)

# Enable CORS with configurable access policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8003",
        "http://127.0.0.1:8003",
        "*"  # Allow external access - remove this line for production security
    ],  # Note: "*" allows any origin for development/testing
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Only allow needed methods
    allow_headers=["Content-Type", "Authorization"],  # Only allow needed headers
)

# Global state management
active_connections: List[WebSocket] = []
current_discovery_session = None
summarization_progress: Dict[str, Dict[str, Any]] = {}  # Track progress by session_id

# Debug mode support
debug_connections: List[WebSocket] = []  # WebSocket connections for debug log streaming
debug_log_queue = asyncio.Queue()  # Queue for debug messages

# Session-based chat settings (reset on server restart)
chat_session_settings = build_default_chat_settings()

MCP_TOOL_ALIASES = {
    "splunk_run_query": ["splunk_run_query", "run_splunk_query"],
    "splunk_get_info": ["splunk_get_info", "get_splunk_info"],
    "splunk_get_indexes": ["splunk_get_indexes", "get_indexes"],
    "splunk_get_index_info": ["splunk_get_index_info", "get_index_info"],
    "splunk_get_metadata": ["splunk_get_metadata", "get_metadata"],
    "splunk_get_user_info": ["splunk_get_user_info", "splunk_get_user_list", "get_user_list"],
    "splunk_get_kv_store_collections": ["splunk_get_kv_store_collections", "get_kv_store_collections"],
    "splunk_get_knowledge_objects": ["splunk_get_knowledge_objects", "get_knowledge_objects"],
    "saia_generate_spl": ["saia_generate_spl"],
    "saia_optimize_spl": ["saia_optimize_spl"],
    "saia_explain_spl": ["saia_explain_spl"],
    "saia_ask_splunk_question": ["saia_ask_splunk_question"]
}

MCP_TOOL_DESCRIPTIONS = {
    "splunk_run_query": "Run a query and return results.",
    "splunk_get_info": "Get Splunk instance version and server information.",
    "splunk_get_indexes": "List Splunk indexes you can access.",
    "splunk_get_index_info": "Get detailed information about a specific index.",
    "splunk_get_metadata": "Get hosts, sources, or sourcetypes for query building.",
    "splunk_get_user_info": "Get information about the authenticated user.",
    "splunk_get_kv_store_collections": "List KV store collections.",
    "splunk_get_knowledge_objects": "List knowledge objects (saved searches, data models, macros, etc.).",
    "saia_generate_spl": "Generate SPL from natural language.",
    "saia_optimize_spl": "Optimize existing SPL.",
    "saia_explain_spl": "Explain SPL in natural language.",
    "saia_ask_splunk_question": "Ask Splunk AI Assistant a natural language question."
}

_cached_mcp_tools = {
    "url": None,
    "tools": set(),
    "timestamp": 0.0
}

DISCOVERY_PIPELINE_VERSION = "v2"
OPENAI_IMAGE_MODEL = "gpt-image-2"
MAX_INFOGRAPHIC_SUMMARY_CHARS = 32000
MAX_INFOGRAPHIC_BRIEF_CHARS = 12000
SUMMARY_INFOGRAPHIC_DIRNAME = "summary_infographics"
SUMMARY_INFOGRAPHIC_PREFIX = "summary_infographic_"
IMAGE_ARTIFACT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

chat_agent_memory: Dict[str, Dict[str, Any]] = {}


def sanitize_chat_session_id(chat_session_id: str) -> str:
    """Sanitize chat session ID for safe in-memory and file usage."""
    if not isinstance(chat_session_id, str) or not chat_session_id.strip():
        return "default"
    cleaned = re.sub(r'[^a-zA-Z0-9_\-]', '_', chat_session_id.strip())
    return cleaned[:64] if cleaned else "default"


def _get_memory_store_path(chat_session_id: str) -> Path:
    """Get per-chat memory persistence path."""
    project_root = Path(__file__).resolve().parent.parent
    memory_dir = project_root / "output" / "chat_memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    return memory_dir / f"chat_memory_{sanitize_chat_session_id(chat_session_id)}.json"


def _default_chat_memory(chat_session_id: str) -> Dict[str, Any]:
    """Default chat memory payload."""
    now = datetime.now().isoformat()
    return {
        "chat_session_id": sanitize_chat_session_id(chat_session_id),
        "created_at": now,
        "updated_at": now,
        "primary_intent": "",
        "recent_intents": [],
        "current_focus": "",
        "last_user_message": "",
        "last_assistant_response": "",
        "recent_turns": [],
        "tracked_terms": [],
        "locations": [],
        "entities": {
            "indexes": [],
            "sourcetypes": [],
            "hosts": [],
            "sources": []
        },
        "time_preferences": [],
        "last_tools_used": [],
        "last_result": {}
    }


def load_chat_memory(chat_session_id: str) -> Dict[str, Any]:
    """Load chat memory from cache or disk."""
    session_key = sanitize_chat_session_id(chat_session_id)
    if session_key in chat_agent_memory:
        return chat_agent_memory[session_key]

    memory = _default_chat_memory(session_key)
    path = _get_memory_store_path(session_key)
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    memory.update(loaded)
        except Exception:
            pass

    chat_agent_memory[session_key] = memory
    return memory


def save_chat_memory(chat_session_id: str, memory: Dict[str, Any]) -> None:
    """Persist chat memory in cache and on disk."""
    session_key = sanitize_chat_session_id(chat_session_id)
    memory["chat_session_id"] = session_key
    memory["updated_at"] = datetime.now().isoformat()
    chat_agent_memory[session_key] = memory

    try:
        path = _get_memory_store_path(session_key)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(memory, f, indent=2)
    except Exception:
        pass


def _append_unique(target_list: List[str], values: List[str], limit: int = 25) -> List[str]:
    """Append unique non-empty string values with max length enforcement."""
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if cleaned and cleaned not in target_list:
            target_list.append(cleaned)
    if len(target_list) > limit:
        del target_list[:-limit]
    return target_list


def _extract_memory_signals(text: str) -> Dict[str, List[str]]:
    """Extract intent and entity candidates from natural language or SPL text."""
    if not text:
        return {
            "terms": [],
            "indexes": [],
            "sourcetypes": [],
            "hosts": [],
            "sources": [],
            "time_preferences": [],
            "intent": ""
        }

    lower_text = text.lower()
    terms = []
    terms.extend(re.findall(r'"([^"\n]{2,80})"', text))
    terms.extend(re.findall(r"'([^'\n]{2,80})'", text))

    indexes = re.findall(r'index=([\w\*\-\.]+)', text, flags=re.IGNORECASE)
    sourcetypes = re.findall(r'sourcetype=([\w\*\-:\.]+)', text, flags=re.IGNORECASE)
    hosts = re.findall(r'host=([\w\*\-\.]+)', text, flags=re.IGNORECASE)
    sources = re.findall(r'source=([^\s\|]+)', text, flags=re.IGNORECASE)

    natural_language_index = extract_index_from_message(text)
    if natural_language_index:
        indexes.append(natural_language_index)

    natural_language_host = extract_host_or_ip_from_message(text)
    if natural_language_host:
        hosts.append(natural_language_host)

    time_preferences = []
    for token in [
        "-24h",
        "-7d",
        "-30d",
        "today",
        "yesterday",
        "last week",
        "last month",
        "last 24 hours",
        "last 7 days",
        "last 30 days",
        "now",
    ]:
        if token in lower_text:
            time_preferences.append(token)

    intent = ""
    intent_patterns = [
        ("security investigation", ["security", "threat", "incident", "attack"]),
        ("performance monitoring", ["performance", "latency", "cpu", "memory", "slow"]),
        ("index discovery", ["index", "indexes", "sourcetype", "metadata"]),
        ("compliance reporting", ["compliance", "audit", "pci", "hipaa", "sox"]),
        ("spl optimization", ["optimize", "improve query", "explain spl", "generate spl"])
    ]
    for label, keywords in intent_patterns:
        if any(keyword in lower_text for keyword in keywords):
            intent = label
            break

    return {
        "terms": terms,
        "indexes": indexes,
        "sourcetypes": sourcetypes,
        "hosts": hosts,
        "sources": sources,
        "time_preferences": time_preferences,
        "intent": intent
    }


def _extract_last_result_context(tool_calls: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Capture compact state from the latest tool activity for follow-on routing."""
    if not isinstance(tool_calls, list) or not tool_calls:
        return {}

    last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), None)
    if not isinstance(last_call, dict):
        return {}

    args = last_call.get("args", {}) if isinstance(last_call.get("args", {}), dict) else {}
    summary = last_call.get("summary", {}) if isinstance(last_call.get("summary", {}), dict) else {}
    query = args.get("query", "") if isinstance(args.get("query", ""), str) else ""
    query_signals = _extract_memory_signals(query)

    actual_results = summary.get("actual_results", []) if isinstance(summary.get("actual_results", []), list) else []
    first_row = actual_results[0] if actual_results and isinstance(actual_results[0], dict) else {}

    def _pick_from_row(keys: List[str]) -> str:
        for key in keys:
            value = first_row.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    index_value = query_signals.get("indexes", [])[-1] if query_signals.get("indexes") else _pick_from_row(["index", "INDEX"])
    host_value = query_signals.get("hosts", [])[-1] if query_signals.get("hosts") else _pick_from_row(["host", "HOST", "src", "src_ip", "dest"])
    sourcetype_value = query_signals.get("sourcetypes", [])[-1] if query_signals.get("sourcetypes") else _pick_from_row(["sourcetype", "SOURCETYPE"])

    result_fields = summary.get("sample_fields", []) if isinstance(summary.get("sample_fields", []), list) else []
    top_dimensions = summary.get("top_dimensions", []) if isinstance(summary.get("top_dimensions", []), list) else []
    next_pivots = summary.get("next_pivots", []) if isinstance(summary.get("next_pivots", []), list) else []
    findings = summary.get("findings", []) if isinstance(summary.get("findings", []), list) else []
    time_bounds = summary.get("time_bounds", {}) if isinstance(summary.get("time_bounds", {}), dict) else {}

    context = {
        "tool": str(last_call.get("tool", "")).strip(),
        "query": query[:600],
        "row_count": _safe_int(summary.get("row_count")),
        "earliest_time": str(args.get("earliest_time", "") or ""),
        "latest_time": str(args.get("latest_time", "") or ""),
        "index": index_value,
        "host": host_value,
        "sourcetype": sourcetype_value,
        "result_fields": result_fields[:10],
        "query_shape": str(summary.get("query_shape", "") or "").strip(),
        "top_dimensions": [item for item in top_dimensions[:2] if isinstance(item, dict)],
        "next_pivots": [str(item).strip() for item in next_pivots[:3] if isinstance(item, str) and str(item).strip()],
        "findings": [str(item).strip() for item in findings[:4] if isinstance(item, str) and str(item).strip()],
        "time_bounds": time_bounds,
    }

    if not any([
        context.get("query"),
        context.get("index"),
        context.get("host"),
        context.get("sourcetype"),
        context.get("row_count"),
    ]):
        return {}

    return context


def _remembered_entity(memory: Dict[str, Any], entity_key: str) -> Optional[str]:
    """Resolve the most recent entity anchor from memory or latest result context."""
    if not isinstance(memory, dict):
        return None

    last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
    candidate = last_result.get(entity_key)
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()

    plural_map = {
        "index": "indexes",
        "host": "hosts",
        "sourcetype": "sourcetypes",
        "source": "sources",
    }
    entity_values = memory.get("entities", {}).get(plural_map.get(entity_key, ""), [])
    if isinstance(entity_values, list) and entity_values:
        last_value = entity_values[-1]
        if isinstance(last_value, str) and last_value.strip():
            return last_value.strip()
    return None


def _describe_time_window(earliest_time: str, latest_time: str) -> str:
    earliest = str(earliest_time or "").strip().lower()
    latest = str(latest_time or "").strip().lower()
    known_windows = {
        ("-24h", "now"): "the last 24 hours",
        ("-7d", "now"): "the last 7 days",
        ("-30d", "now"): "the last 30 days",
    }
    if (earliest, latest) in known_windows:
        return known_windows[(earliest, latest)]
    if earliest:
        return f"the window {earliest} to {latest or 'now'}"
    return "the recent time window"


def _make_follow_on_action(label: str, prompt: str, kind: str) -> Dict[str, str]:
    return {
        "label": label,
        "prompt": prompt,
        "kind": kind,
    }


def _normalize_response_follow_on_text(action_text: str) -> str:
    cleaned = re.sub(r'\s+', ' ', str(action_text or '')).strip(" \t\r\n:-*•")
    cleaned = cleaned.strip("`'\"")
    cleaned = re.sub(r'^to\s+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'^also\s+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\s+(?:for you|if helpful|if that helps|if you want)$', '', cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.rstrip(' .;:')
    if not cleaned:
        return ""
    return cleaned[0].upper() + cleaned[1:]


def _build_response_follow_on_label(prompt: str, limit: int = 72) -> str:
    label = str(prompt or '').strip().rstrip('.')
    if len(label) <= limit:
        return label
    shortened = label[:limit].rsplit(' ', 1)[0].strip()
    return f"{shortened or label[:limit].strip()}..."


def _extract_response_follow_on_actions(assistant_response: str) -> List[Dict[str, str]]:
    cleaned_response = sanitize_llm_response_text(str(assistant_response or ''))
    if not cleaned_response:
        return []

    patterns = [
        r"\ba good follow[ -]?up(?: question| step| action)?\s+(?:would be(?: to)?|is|might be|could be)\s+(?P<action>[^.!?\n]+)",
        r"\bif you(?:'d|’d|\swould)? like,?\s+i can\s+(?P<action>[^.!?\n]+)",
        r"\bif you want(?:\s+[^,.!?\n]+)?[,;]?\s+i can\s+(?P<action>[^.!?\n]+)",
        r"\bif helpful,?\s+i can\s+(?P<action>[^.!?\n]+)",
        r"\bor i can\s+(?P<action>[^.!?\n]+)",
        r"\bi can also\s+(?P<action>[^.!?\n]+)",
        r"\bi can\s+(?P<action>(?:list|show|compare|check|validate|investigate|review|summarize|break down|trend|prototype|measure|explain|help you find)[^.!?\n]+)",
    ]
    ignored_prefixes = (
        'do that',
        'help with that',
        'continue',
        'keep going',
        'take it further',
        'go deeper',
    )

    actions: List[Dict[str, str]] = []
    seen_prompts = set()
    for pattern in patterns:
        for match in re.finditer(pattern, cleaned_response, flags=re.IGNORECASE):
            prompt = _normalize_response_follow_on_text(match.group('action'))
            lowered_prompt = prompt.lower()
            if len(prompt.split()) < 3 or lowered_prompt.startswith(ignored_prefixes):
                continue
            if lowered_prompt in seen_prompts:
                continue
            seen_prompts.add(lowered_prompt)
            actions.append(_make_follow_on_action(
                _build_response_follow_on_label(prompt),
                prompt,
                'assistant_response_follow_up',
            ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _extract_top_dimension_context(summary: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(summary, dict):
        return {}

    top_dimensions = summary.get("top_dimensions", []) if isinstance(summary.get("top_dimensions", []), list) else []
    for dimension in top_dimensions:
        if not isinstance(dimension, dict):
            continue
        field = str(dimension.get("field", "")).strip()
        values = [
            str(value).strip()
            for value in (dimension.get("values", []) if isinstance(dimension.get("values", []), list) else [])
            if str(value).strip()
        ]
        if not field or not values:
            continue
        top_value = values[0].rsplit(" (", 1)[0].strip()
        return {
            "field": field,
            "values": values[:3],
            "top_value": top_value,
        }
    return {}


def _build_output_follow_on_actions(
    summary: Dict[str, Any],
    remembered_index: Optional[str],
    remembered_host: Optional[str],
    time_window_label: str,
) -> List[Dict[str, Any]]:
    if not isinstance(summary, dict):
        return []

    actions: List[Dict[str, Any]] = []
    row_count = _safe_int(summary.get("row_count"))
    if row_count <= 0:
        return actions

    query_shape = str(summary.get("query_shape", "") or "").strip().lower()
    findings_text = " ".join(
        item.strip().lower()
        for item in summary.get("findings", [])
        if isinstance(item, str) and item.strip()
    )
    next_pivots = [
        str(item).strip()
        for item in summary.get("next_pivots", [])
        if isinstance(item, str) and str(item).strip()
    ]
    sample_fields = [
        str(field).strip().lower()
        for field in summary.get("sample_fields", [])
        if isinstance(field, str) and str(field).strip()
    ]
    top_dimension = _extract_top_dimension_context(summary)
    dimension_field = str(top_dimension.get("field", "")).strip()
    top_value = str(top_dimension.get("top_value", "")).strip()
    top_values = top_dimension.get("values", []) if isinstance(top_dimension.get("values", []), list) else []
    index_clause = f" in index={remembered_index}" if remembered_index else ""

    if query_shape == "time_series":
        if remembered_index:
            actions.append(_make_follow_on_action(
                f"Explain changes in index={remembered_index}",
                f"Explain the biggest spikes or drops in index={remembered_index} over {time_window_label} by breaking the trend down by sourcetype and host.",
                "explain_trend_change",
            ))
            actions.append(_make_follow_on_action(
                "Compare with the previous window",
                f"Compare event volume for index={remembered_index} in {time_window_label} versus the previous equivalent window and summarize what changed.",
                "compare_previous_window",
            ))
        if remembered_host:
            actions.append(_make_follow_on_action(
                f"Inspect host={remembered_host} around the change",
                f"Show surrounding events for host={remembered_host}{index_clause} over {time_window_label} and highlight what lines up with the biggest spike or drop.",
                "host_spike_pivot",
            ))
    elif query_shape == "aggregation":
        if dimension_field and top_value:
            actions.append(_make_follow_on_action(
                f"Filter on {dimension_field}={top_value}",
                f"Filter the last query on {dimension_field}={top_value}{index_clause} over {time_window_label} and explain why it stands out.",
                "filter_dimension_value",
            ))
            if remembered_index:
                actions.append(_make_follow_on_action(
                    f"Trend {top_value} over time",
                    f"Show a timechart for {dimension_field}={top_value} in index={remembered_index} over {time_window_label}.",
                    "trend_dimension_value",
                ))
        if dimension_field and len(top_values) > 1:
            actions.append(_make_follow_on_action(
                f"Compare the top {dimension_field} values",
                f"Compare the top {dimension_field} values from the last result ({', '.join(top_values[:3])}){index_clause} and summarize what separates them.",
                "compare_dimension_values",
            ))
    elif query_shape == "event_sample":
        if remembered_host:
            actions.append(_make_follow_on_action(
                f"Show surrounding events for host={remembered_host}",
                f"Show surrounding events for host={remembered_host}{index_clause} over {time_window_label} and highlight the most relevant patterns.",
                "surrounding_events_host",
            ))
        if "sourcetype" in sample_fields or "host" in sample_fields:
            actions.append(_make_follow_on_action(
                "Summarize the event pattern",
                f"Group the last result by sourcetype and host{index_clause} over {time_window_label} so the main event pattern is easier to interpret.",
                "summarize_event_pattern",
            ))
        if any(field in sample_fields for field in ["user", "src", "src_ip", "dest", "dest_ip", "action", "status", "signature"]):
            actions.append(_make_follow_on_action(
                "Pivot on the key entities",
                f"Pivot on the most important entities from the last result{index_clause} over {time_window_label} and show the strongest outliers.",
                "pivot_key_entities",
            ))
    elif dimension_field and top_value:
        actions.append(_make_follow_on_action(
            f"Filter on {dimension_field}={top_value}",
            f"Filter the last query on {dimension_field}={top_value}{index_clause} over {time_window_label} and explain what changes.",
            "filter_dimension_value",
        ))

    for pivot in next_pivots[:2]:
        lowered_pivot = pivot.lower()
        if lowered_pivot.startswith("filter on ") and "=" in pivot:
            filter_target = pivot[len("Filter on "):].strip()
            actions.append(_make_follow_on_action(
                f"Filter on {filter_target}",
                f"Filter the last query on {filter_target}{index_clause} over {time_window_label} and explain what changes.",
                "filter_dimension_value",
            ))
        elif "compare adjacent time buckets" in lowered_pivot and remembered_index:
            actions.append(_make_follow_on_action(
                "Compare adjacent time buckets",
                f"Compare adjacent time buckets for index={remembered_index} over {time_window_label} and explain the biggest changes.",
                "compare_time_buckets",
            ))
        elif "aggregate by one dimension" in lowered_pivot:
            actions.append(_make_follow_on_action(
                "Aggregate by one dimension",
                f"Aggregate the last query{index_clause} by one dimension over {time_window_label} so the result is easier to explain.",
                "aggregate_one_dimension",
            ))

    if "large result set" in findings_text or row_count > 100:
        actions.append(_make_follow_on_action(
            "Tighten the result set",
            f"Tighten the last query{index_clause} by one dimension or a narrower time window so the result is easier to explain.",
            "tighten_result_set",
        ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _compact_memory_text(text: Any, limit: int = 280) -> str:
    if not isinstance(text, str):
        return ""
    cleaned = re.sub(r'\s+', ' ', text).strip()
    return cleaned[:limit]


def _append_recent_turn(memory: Dict[str, Any], role: str, content: str, limit: int = 8) -> None:
    if not isinstance(memory, dict):
        return

    cleaned = _compact_memory_text(content, limit=320)
    if not cleaned:
        return

    turns = memory.get("recent_turns", []) if isinstance(memory.get("recent_turns", []), list) else []
    candidate = {
        "role": str(role or "user").strip().lower(),
        "content": cleaned,
    }
    if turns and isinstance(turns[-1], dict):
        if turns[-1].get("role") == candidate["role"] and turns[-1].get("content") == candidate["content"]:
            memory["recent_turns"] = turns[-limit:]
            return

    turns.append(candidate)
    memory["recent_turns"] = turns[-limit:]


def _build_conversation_focus_text(
    user_message: str,
    memory: Dict[str, Any],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: str = "",
) -> str:
    parts = [
        str(user_message or ""),
        str(assistant_response or ""),
        str(memory.get("primary_intent", "") if isinstance(memory, dict) else ""),
        str(memory.get("current_focus", "") if isinstance(memory, dict) else ""),
        str(memory.get("last_user_message", "") if isinstance(memory, dict) else ""),
        str(memory.get("last_assistant_response", "") if isinstance(memory, dict) else ""),
    ]

    if isinstance(memory, dict):
        last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
        for key in ["query", "index", "host", "sourcetype"]:
            value = last_result.get(key)
            if isinstance(value, str):
                parts.append(value)
        for finding in last_result.get("findings", []) if isinstance(last_result.get("findings", []), list) else []:
            if isinstance(finding, str):
                parts.append(finding)
        for pivot in last_result.get("next_pivots", []) if isinstance(last_result.get("next_pivots", []), list) else []:
            if isinstance(pivot, str):
                parts.append(pivot)

        for turn in memory.get("recent_turns", [])[-4:] if isinstance(memory.get("recent_turns", []), list) else []:
            if isinstance(turn, dict) and isinstance(turn.get("content"), str):
                parts.append(turn.get("content", ""))

    if tool_calls:
        last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), None)
        if isinstance(last_call, dict):
            args = last_call.get("args", {}) if isinstance(last_call.get("args", {}), dict) else {}
            summary = last_call.get("summary", {}) if isinstance(last_call.get("summary", {}), dict) else {}
            if isinstance(args.get("query"), str):
                parts.append(args.get("query", ""))
            for finding in summary.get("findings", [])[:4] if isinstance(summary.get("findings", []), list) else []:
                if isinstance(finding, str):
                    parts.append(finding)

    return " ".join(part for part in parts if isinstance(part, str) and part.strip()).lower()


def _detect_conversation_focus(
    user_message: str,
    memory: Dict[str, Any],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: str = "",
    report_intent: Optional[str] = None,
) -> str:
    if report_intent:
        return str(report_intent).strip().lower()

    focus_text = _build_conversation_focus_text(user_message, memory, tool_calls, assistant_response)
    last_result = memory.get("last_result", {}) if isinstance(memory, dict) and isinstance(memory.get("last_result", {}), dict) else {}
    query_text = str(last_result.get("query", "") or "").lower()

    if any(token in focus_text for token in ["windows security", "failed logon", "failed login", "authentication", "lockout", "privilege", "wineventlog:security"]):
        return "security"
    if any(token in focus_text for token in ["platform health", "_internal", "_audit", "_introspection", "ingestion", "license", "scheduler", "search failure", "splunk health"]):
        return "platform_health"
    if any(token in focus_text for token in ["wmata", "api availability", "collector", "latency spike", "feed health"]):
        return "wmata"
    if any(token in focus_text for token in ["network", "latency", "packet loss", "connectivity", "ping"]):
        return "network"
    if any(token in focus_text for token in ["compliance", "audit", "governance", "admin action", "privileged action"]):
        return "compliance"
    if any(token in focus_text for token in ["recommendation", "recommend", "improve", "next step", "priority action"]):
        return "recommendations"
    if any(token in focus_text for token in ["risk", "exposure", "blind spot", "weak spot"]):
        return "top_risks"
    if any(token in focus_text for token in ["coverage gap", "coverage gaps", "missing coverage", "what is missing"]):
        return "coverage_gaps"
    if any(token in focus_text for token in ["use case", "use cases", "what should we build", "monitoring opportunity"]):
        return "use_cases"
    if any(token in focus_text for token in ["readiness", "maturity", "posture", "how ready"]):
        return "readiness"
    if "timechart" in focus_text or "timechart" in query_text:
        return "trend_analysis"
    if any(token in focus_text for token in ["break down", "breakdown", "by sourcetype", "by host"]) or any(token in query_text for token in [" by sourcetype", " by host"]):
        return "breakdown_analysis"
    if any(token in focus_text for token in ["last seen", "latest event", "surrounding events", "host investigation", "pivot on host"]) or memory.get("last_result", {}).get("host"):
        if memory.get("last_result", {}).get("host"):
            return "host_analysis"
    if memory.get("last_result", {}).get("index"):
        return "index_analysis"
    return str(memory.get("primary_intent", "") or "general").strip().lower() or "general"


def _dedupe_follow_on_actions(actions: List[Dict[str, Any]], limit: int = 3) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        key = (str(action.get("kind", "")).strip().lower(), str(action.get("prompt", "")).strip().lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)
        if len(deduped) >= limit:
            break
    return deduped


def _build_focus_follow_on_actions(
    focus: str,
    remembered_index: Optional[str],
    remembered_host: Optional[str],
    time_window_label: str,
) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    index_clause = f" in index={remembered_index}" if remembered_index else ""

    if focus == "security":
        actions.extend([
            _make_follow_on_action(
                "Validate failed logons",
                f"Validate failed logons{index_clause} over {time_window_label} and show the top users, hosts, and source IPs.",
                "validate_failed_logons",
            ),
            _make_follow_on_action(
                "Check privilege changes",
                f"Check privilege changes, account lockouts, and group membership changes{index_clause} over {time_window_label}.",
                "validate_privilege_changes",
            ),
        ])
    elif focus == "platform_health":
        actions.extend([
            _make_follow_on_action(
                "Check Splunk platform health",
                "Check platform health in _internal, _audit, and _introspection over the last 24 hours and summarize ingestion issues, search failures, and license signals.",
                "validate_platform_health",
            ),
            _make_follow_on_action(
                "Inspect ingestion failures",
                "Show ingestion errors, queue pressure, and blocked pipelines from _internal over the last 24 hours.",
                "inspect_ingestion_failures",
            ),
        ])
    elif focus == "wmata":
        actions.extend([
            _make_follow_on_action(
                "Review WMATA feed health",
                "Check WMATA API and collector data over the last 24 hours for outages, elevated errors, and latency spikes.",
                "validate_wmata_health",
            ),
            _make_follow_on_action(
                "Compare WMATA sources",
                "Compare WMATA sources or collectors by error rate and response time over the last 24 hours.",
                "compare_wmata_sources",
            ),
        ])
    elif focus == "network":
        actions.extend([
            _make_follow_on_action(
                "Inspect network connectivity",
                "Show connectivity, latency, and packet-loss trends from ping or network telemetry over the last 24 hours.",
                "validate_network_health",
            ),
            _make_follow_on_action(
                "Compare noisy hosts",
                "Compare the noisiest network hosts over the last 24 hours and highlight packet-loss or latency outliers.",
                "compare_network_hosts",
            ),
        ])
    elif focus == "compliance":
        actions.extend([
            _make_follow_on_action(
                "Review audit activity",
                "Show privileged actions, configuration changes, and audit failures over the last 7 days.",
                "review_audit_activity",
            ),
            _make_follow_on_action(
                "Check admin changes",
                "Summarize admin changes and notable governance events over the last 7 days.",
                "review_admin_changes",
            ),
        ])
    elif focus == "trend_analysis" and remembered_index:
        actions.extend([
            _make_follow_on_action(
                f"Explain spikes in index={remembered_index}",
                f"Break down the biggest spikes in index={remembered_index} by sourcetype and host over {time_window_label}.",
                "explain_trend_spikes",
            ),
            _make_follow_on_action(
                f"Compare trend windows for index={remembered_index}",
                f"Compare event volume for index={remembered_index} in {time_window_label} versus the previous equivalent window.",
                "compare_trend_windows",
            ),
        ])
    elif focus == "breakdown_analysis" and remembered_index:
        actions.extend([
            _make_follow_on_action(
                f"Trend the top sourcetype in index={remembered_index}",
                f"Show a timechart for the top sourcetype in index={remembered_index} over {time_window_label}.",
                "trend_top_sourcetype",
            ),
            _make_follow_on_action(
                f"Inspect top host in index={remembered_index}",
                f"Inspect the busiest host in index={remembered_index} and show representative events over {time_window_label}.",
                "inspect_top_host",
            ),
        ])
    elif focus == "host_analysis" and remembered_host:
        actions.extend([
            _make_follow_on_action(
                f"Show surrounding events for host={remembered_host}",
                f"Show surrounding events for host={remembered_host}{index_clause} over {time_window_label} with sourcetype breakdown.",
                "surrounding_events_host",
            ),
            _make_follow_on_action(
                f"Check last seen for host={remembered_host}",
                f"When was host={remembered_host} last seen in Splunk, and what sourcetypes did it report most recently?",
                "last_seen_host",
            ),
        ])
    elif focus in {"recommendations", "top_risks", "coverage_gaps", "use_cases", "readiness"}:
        actions.append(_make_follow_on_action(
            "Validate the top issue live",
            "Validate the top recommendation, risk, or coverage gap with a live query and summarize current drift from the report snapshot.",
            "validate_top_gap",
        ))

    return actions


def update_chat_memory(
    chat_session_id: str,
    user_message: str,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: Optional[str] = None,
    report_intent: Optional[str] = None,
    record_user_turn: bool = True,
    update_focus: bool = True,
) -> Dict[str, Any]:
    """Update chat memory with latest user message, optional tool activity, and optional assistant response."""
    memory = load_chat_memory(chat_session_id)
    signals = _extract_memory_signals(user_message)

    if isinstance(user_message, str) and user_message.strip():
        memory["last_user_message"] = _compact_memory_text(user_message, limit=320)
        if record_user_turn:
            _append_recent_turn(memory, "user", user_message)

    if signals.get("intent"):
        memory["primary_intent"] = signals["intent"]
        _append_unique(memory["recent_intents"], [signals["intent"]], limit=8)
    if report_intent:
        _append_unique(memory["recent_intents"], [str(report_intent).strip().lower()], limit=8)

    _append_unique(memory["tracked_terms"], signals.get("terms", []), limit=30)
    _append_unique(memory["time_preferences"], signals.get("time_preferences", []), limit=10)

    entities = memory.get("entities", {})
    _append_unique(entities.setdefault("indexes", []), signals.get("indexes", []), limit=25)
    _append_unique(entities.setdefault("sourcetypes", []), signals.get("sourcetypes", []), limit=25)
    _append_unique(entities.setdefault("hosts", []), signals.get("hosts", []), limit=25)
    _append_unique(entities.setdefault("sources", []), signals.get("sources", []), limit=25)

    _append_unique(memory["locations"], signals.get("indexes", []) + signals.get("hosts", []) + signals.get("sources", []), limit=25)

    if tool_calls:
        recent_tools = [tc.get("tool", "") for tc in tool_calls if isinstance(tc, dict) and tc.get("tool")]
        _append_unique(memory["last_tools_used"], recent_tools, limit=15)

        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            args = tc.get("args", {}) or {}
            if isinstance(args, dict) and args.get("query"):
                query_signals = _extract_memory_signals(args.get("query", ""))
                _append_unique(entities.setdefault("indexes", []), query_signals.get("indexes", []), limit=25)
                _append_unique(entities.setdefault("sourcetypes", []), query_signals.get("sourcetypes", []), limit=25)
                _append_unique(entities.setdefault("hosts", []), query_signals.get("hosts", []), limit=25)
                _append_unique(entities.setdefault("sources", []), query_signals.get("sources", []), limit=25)

        last_result_context = _extract_last_result_context(tool_calls)
        if last_result_context:
            memory["last_result"] = last_result_context

    if isinstance(assistant_response, str) and assistant_response.strip():
        memory["last_assistant_response"] = _compact_memory_text(assistant_response, limit=400)
        _append_recent_turn(memory, "assistant", assistant_response)

    if update_focus:
        focus = _detect_conversation_focus(
            user_message,
            memory,
            tool_calls=tool_calls,
            assistant_response=assistant_response or "",
            report_intent=report_intent,
        )
        if focus:
            memory["current_focus"] = focus

    memory["entities"] = entities
    save_chat_memory(chat_session_id, memory)
    return memory


def build_chat_memory_context(memory: Dict[str, Any]) -> str:
    """Render concise memory context for system prompt injection."""
    if not memory:
        return ""

    entities = memory.get("entities", {})
    lines = ["🧠 SESSION MEMORY:"]
    if memory.get("primary_intent"):
        lines.append(f"- Primary intent: {memory['primary_intent']}")
    if memory.get("current_focus"):
        lines.append(f"- Current focus: {memory['current_focus']}")
    if memory.get("recent_intents"):
        lines.append(f"- Recent intents: {', '.join(memory['recent_intents'][-3:])}")
    if memory.get("tracked_terms"):
        lines.append(f"- Tracked terms: {', '.join(memory['tracked_terms'][-6:])}")
    if entities.get("indexes"):
        lines.append(f"- Remembered indexes: {', '.join(entities['indexes'][-6:])}")
    if entities.get("hosts"):
        lines.append(f"- Remembered hosts: {', '.join(entities['hosts'][-4:])}")
    if entities.get("sourcetypes"):
        lines.append(f"- Remembered sourcetypes: {', '.join(entities['sourcetypes'][-4:])}")
    if memory.get("time_preferences"):
        lines.append(f"- Preferred time ranges: {', '.join(memory['time_preferences'][-4:])}")
    if memory.get("last_tools_used"):
        lines.append(f"- Last tools used: {', '.join(memory['last_tools_used'][-5:])}")
    last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
    if last_result:
        last_context_parts = []
        if last_result.get("index"):
            last_context_parts.append(f"index={last_result['index']}")
        if last_result.get("host"):
            last_context_parts.append(f"host={last_result['host']}")
        if last_result.get("row_count") is not None:
            last_context_parts.append(f"row_count={last_result.get('row_count', 0)}")
        if last_result.get("earliest_time"):
            last_context_parts.append(
                f"window={last_result.get('earliest_time', '')} to {last_result.get('latest_time', 'now') or 'now'}"
            )
        if last_context_parts:
            lines.append(f"- Last result context: {', '.join(last_context_parts)}")
    if memory.get("recent_turns"):
        turn_snapshot = []
        for turn in memory.get("recent_turns", [])[-3:]:
            if not isinstance(turn, dict):
                continue
            role = str(turn.get("role", "user")).strip().capitalize()
            content = _compact_memory_text(turn.get("content", ""), limit=80)
            if content:
                turn_snapshot.append(f"{role}: {content}")
        if turn_snapshot:
            lines.append(f"- Recent turns: {' | '.join(turn_snapshot)}")

    return "\n".join(lines)


def _format_last_result_context_for_prompt(memory: Dict[str, Any]) -> str:
    """Render the last result context in a compact single-line form for prompt continuity."""
    if not isinstance(memory, dict):
        return ""

    last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
    if not last_result:
        return ""

    parts: List[str] = []
    for key in ("index", "host", "sourcetype", "source"):
        value = str(last_result.get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")

    if last_result.get("row_count") is not None:
        parts.append(f"row_count={_safe_int(last_result.get('row_count'))}")

    earliest_time = str(last_result.get("earliest_time") or "").strip()
    latest_time = str(last_result.get("latest_time") or "now").strip() or "now"
    if earliest_time:
        parts.append(f"window={earliest_time} to {latest_time}")

    query = _compact_memory_text(last_result.get("query", ""), limit=140)
    if query:
        parts.append(f"query={query}")

    findings = [
        _compact_memory_text(finding, limit=90)
        for finding in (last_result.get("findings", []) if isinstance(last_result.get("findings", []), list) else [])[:3]
        if isinstance(finding, str) and finding.strip()
    ]
    if findings:
        parts.append(f"findings={'; '.join(findings)}")

    return ", ".join(parts)


def _build_llm_recent_context_turns(
    history: Any,
    memory: Dict[str, Any],
    limit: int = 6,
) -> List[Dict[str, str]]:
    """Return recent turns for LLM continuity, preferring normalized live history over persisted memory."""
    recent_history = _compact_chat_role_history(history, limit=limit, include_system=False)
    if recent_history:
        return [
            {
                "role": entry.get("role", "user"),
                "content": _compact_memory_text(entry.get("content", ""), limit=180),
            }
            for entry in recent_history
            if isinstance(entry, dict) and _compact_memory_text(entry.get("content", ""), limit=180)
        ]

    turns = memory.get("recent_turns", []) if isinstance(memory, dict) and isinstance(memory.get("recent_turns", []), list) else []
    normalized: List[Dict[str, str]] = []
    for turn in turns[-limit:]:
        if not isinstance(turn, dict):
            continue
        role = str(turn.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = _compact_memory_text(turn.get("content", ""), limit=180)
        if not content:
            continue
        normalized.append({"role": role, "content": content})
    return normalized


def build_llm_continuity_context(
    user_message: str,
    history: Any,
    memory: Dict[str, Any],
    limit: int = 6,
) -> str:
    """Build a provider-agnostic continuity gate so the LLM sees the live session state on every turn."""
    memory = memory if isinstance(memory, dict) else {}
    recent_turns = _build_llm_recent_context_turns(history, memory, limit=limit)
    user_text = _compact_memory_text(user_message, limit=320)
    last_result_context = _format_last_result_context_for_prompt(memory)
    entities = memory.get("entities", {}) if isinstance(memory.get("entities", {}), dict) else {}

    state_lines: List[str] = []
    primary_intent = str(memory.get("primary_intent") or "").strip()
    if primary_intent:
        state_lines.append(f"- Primary intent: {primary_intent}")

    current_focus = str(memory.get("current_focus") or "").strip()
    if current_focus:
        state_lines.append(f"- Active focus: {current_focus}")

    remembered_indexes = [str(item).strip() for item in entities.get("indexes", [])[-6:] if isinstance(item, str) and item.strip()]
    if remembered_indexes:
        state_lines.append(f"- Remembered indexes: {', '.join(remembered_indexes)}")

    remembered_hosts = [str(item).strip() for item in entities.get("hosts", [])[-4:] if isinstance(item, str) and item.strip()]
    if remembered_hosts:
        state_lines.append(f"- Remembered hosts: {', '.join(remembered_hosts)}")

    remembered_sourcetypes = [str(item).strip() for item in entities.get("sourcetypes", [])[-4:] if isinstance(item, str) and item.strip()]
    if remembered_sourcetypes:
        state_lines.append(f"- Remembered sourcetypes: {', '.join(remembered_sourcetypes)}")

    if last_result_context:
        state_lines.append(f"- Last result context: {last_result_context}")

    last_assistant_response = _compact_memory_text(memory.get("last_assistant_response", ""), limit=200)
    if last_assistant_response:
        state_lines.append(f"- Last assistant response: {last_assistant_response}")

    if not state_lines and not recent_turns and not user_text:
        return ""

    lines = [
        "SESSION CONTINUITY GATE:",
        "- Treat the current user message as a continuation of the active investigation unless the user clearly changes topic.",
        "- Resolve pronouns, shorthand, omitted nouns, and aliases using the active focus, remembered entities, last result, and recent turns before answering.",
        "- Prefer the current Splunk/DT4SMS session context over generic interpretations when the request is ambiguous.",
    ]

    if state_lines:
        lines.append("Active session state:")
        lines.extend(state_lines)

    if recent_turns:
        lines.append("Recent conversation:")
        for turn in recent_turns[-4:]:
            role = str(turn.get("role") or "user").strip().capitalize()
            content = _compact_memory_text(turn.get("content", ""), limit=180)
            if content:
                lines.append(f"- {role}: {content}")

    if user_text:
        lines.append(f"Current request to interpret in-session: {user_text}")

    return "\n".join(lines)


def _compact_chat_role_history(
    history: Any,
    limit: int = 12,
    include_system: bool = False,
) -> List[Dict[str, str]]:
    """Normalize chat history into compact role/content pairs for safe follow-up reuse."""
    if not isinstance(history, list):
        return []

    normalized: List[Dict[str, str]] = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        role = str(entry.get("role") or "").strip().lower()
        if role not in {"user", "assistant", "system"}:
            continue
        if role == "system" and not include_system:
            continue
        content = str(entry.get("content") or "").strip()
        if not content:
            continue
        normalized.append({"role": role, "content": content})

    if include_system:
        system_entries = [item for item in normalized if item.get("role") == "system"][:1]
        non_system_entries = [item for item in normalized if item.get("role") != "system"]
        return system_entries + (non_system_entries[-limit:] if limit > 0 else non_system_entries)

    return normalized[-limit:] if limit > 0 else normalized


def _build_follow_up_conversation_history(
    history: Any,
    user_message: str,
    assistant_response: str,
    limit: int = 12,
) -> List[Dict[str, str]]:
    """Return compact user/assistant history for deterministic and report-backed chat turns."""
    compact_history = _compact_chat_role_history(history, limit=limit, include_system=False)

    cleaned_user_message = str(user_message or "").strip()
    if cleaned_user_message:
        compact_history.append({"role": "user", "content": cleaned_user_message})

    cleaned_response = sanitize_llm_response_text(str(assistant_response or ""))
    if cleaned_response:
        compact_history.append({"role": "assistant", "content": cleaned_response})

    return _compact_chat_role_history(compact_history, limit=limit, include_system=False)


def build_follow_on_actions(
    user_message: str,
    memory: Dict[str, Any],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: str = "",
) -> List[Dict[str, Any]]:
    """Generate executable, context-aware follow-on action suggestions."""
    actions: List[Dict[str, Any]] = []
    remembered_index = _remembered_entity(memory, "index")
    remembered_host = _remembered_entity(memory, "host")
    last_result = memory.get("last_result", {}) if isinstance(memory, dict) and isinstance(memory.get("last_result", {}), dict) else {}
    earliest_time = str(last_result.get("earliest_time") or "").strip() or "-24h"
    latest_time = str(last_result.get("latest_time") or "").strip() or "now"
    time_window_label = _describe_time_window(earliest_time, latest_time)
    row_count = _safe_int(last_result.get("row_count"))
    effective_assistant_response = str(assistant_response or memory.get("last_assistant_response", ""))
    focus = _detect_conversation_focus(user_message, memory, tool_calls=tool_calls, assistant_response=effective_assistant_response)
    latest_summary = {}
    if tool_calls:
        last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), {})
        latest_summary = last_call.get("summary", {}) if isinstance(last_call.get("summary", {}), dict) else {}

    response_actions = _extract_response_follow_on_actions(effective_assistant_response)
    output_actions = _build_output_follow_on_actions(latest_summary, remembered_index, remembered_host, time_window_label)
    focus_actions = _build_focus_follow_on_actions(focus, remembered_index, remembered_host, time_window_label)

    actions.extend(response_actions)

    if output_actions:
        actions.extend(output_actions)
        if focus in {"security", "platform_health", "wmata", "network", "compliance", "recommendations", "top_risks", "coverage_gaps", "use_cases", "readiness"}:
            actions.extend(focus_actions[:1])
    else:
        actions.extend(focus_actions)

    if tool_calls:
        last_call = tool_calls[-1] if tool_calls else {}
        summary = last_call.get("summary", {}) if isinstance(last_call, dict) else {}
        row_count = _safe_int(summary.get("row_count"))

        if row_count == 0:
            broaden_prompt = "Retry the last search over the last 7 days and tell me whether any relevant data exists."
            if remembered_index:
                broaden_prompt = f"Retry the last search for index={remembered_index} over the last 7 days and tell me whether any relevant data exists."
            actions.append(_make_follow_on_action("Broaden the time range", broaden_prompt, "broaden_time"))
            if remembered_index:
                actions.append(_make_follow_on_action(
                    f"Baseline index={remembered_index}",
                    f"Run a baseline count check for index={remembered_index} and confirm whether data is available over the last 7 days.",
                    "baseline_index",
                ))
            if remembered_host:
                actions.append(_make_follow_on_action(
                    f"Check last seen for host={remembered_host}",
                    f"When was host={remembered_host} last seen in Splunk?",
                    "last_seen_host",
                ))
        elif row_count > 0 and not actions:
            if remembered_index:
                actions.append(_make_follow_on_action(
                    f"Trend index={remembered_index}",
                    f"Show a timechart of event volume for index={remembered_index} over {time_window_label}.",
                    "timechart_index",
                ))
                actions.append(_make_follow_on_action(
                    f"Break down index={remembered_index}",
                    f"Break down index={remembered_index} by sourcetype and host for {time_window_label}.",
                    "breakdown_index",
                ))
            if remembered_host:
                host_scope = f" within index={remembered_index}" if remembered_index else ""
                actions.append(_make_follow_on_action(
                    f"Investigate host={remembered_host}",
                    f"Pivot on host={remembered_host}{host_scope} and identify related anomalies for {time_window_label}.",
                    "host_pivot",
                ))

    if not actions:
        if remembered_index:
            actions.append(_make_follow_on_action(
                "Investigate unusual events",
                f"Show me unusual events in index={remembered_index} over the last 24 hours.",
                "unusual_events",
            ))
        else:
            actions.append(_make_follow_on_action(
                "Ask a focused follow-up",
                "Ask a focused plain-language question about one index, host, or sourcetype for deeper analysis.",
                "generic_follow_up",
            ))

    return _dedupe_follow_on_actions(actions, limit=3)


def resolve_tool_name(tool_name: str, available_tools: Optional[set] = None) -> str:
    """Resolve a logical/legacy tool name to the best available MCP tool name."""
    available = available_tools or set()
    if tool_name in available:
        return tool_name

    for canonical_name, aliases in MCP_TOOL_ALIASES.items():
        if tool_name == canonical_name or tool_name in aliases:
            for candidate in aliases:
                if candidate in available:
                    return candidate
            return aliases[0]

    return tool_name


def normalize_tool_arguments(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize tool arguments for GA tool signatures while preserving compatibility."""
    normalized = dict(args or {})

    if tool_name in {"splunk_get_info", "get_splunk_info", "splunk_get_user_info", "splunk_get_user_list", "get_user_list"}:
        return {}

    if tool_name in {"splunk_get_index_info", "get_index_info"}:
        if "index_name" in normalized and "index" not in normalized:
            normalized["index"] = normalized.pop("index_name")

    if tool_name in {"splunk_get_knowledge_objects", "get_knowledge_objects"}:
        if "type" in normalized and "object_type" not in normalized:
            normalized["object_type"] = normalized["type"]

    return normalized


def extract_results_from_mcp_response(tool_response: Dict[str, Any]) -> Dict[str, Any]:
    """Extract normalized result payload from MCP response across GA and legacy shapes."""
    normalized = {
        "results": [],
        "status_code": None,
        "error_message": ""
    }

    if not isinstance(tool_response, dict):
        return normalized

    result_obj = tool_response.get("result", {})
    if not isinstance(result_obj, dict):
        return normalized

    structured = result_obj.get("structuredContent", {})
    if isinstance(structured, dict):
        status_code = structured.get("status_code")
        if isinstance(status_code, int):
            normalized["status_code"] = status_code
        if isinstance(structured.get("content"), str):
            normalized["error_message"] = structured.get("content", "")
        if isinstance(structured.get("results"), list):
            normalized["results"] = structured.get("results", [])
            return normalized

    if isinstance(result_obj.get("results"), list):
        normalized["results"] = result_obj.get("results", [])
        return normalized

    content_items = result_obj.get("content", []) if isinstance(result_obj.get("content", []), list) else []
    if content_items:
        first_item = content_items[0]
        if isinstance(first_item, dict) and isinstance(first_item.get("text"), str):
            text = first_item.get("text", "")
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
                    normalized["results"] = parsed.get("results", [])
                elif isinstance(parsed, list):
                    normalized["results"] = parsed
            except json.JSONDecodeError:
                pass

    return normalized


def extract_primary_spl_query(tool_calls: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    """Return the most relevant executed SPL query from a tool-call history."""
    if not isinstance(tool_calls, list):
        return None

    for tool_call in reversed(tool_calls):
        if not isinstance(tool_call, dict):
            continue

        spl_query = tool_call.get("spl_query")
        if isinstance(spl_query, str) and spl_query.strip():
            return spl_query.strip()

        args = tool_call.get("args", {})
        if isinstance(args, dict):
            query = args.get("query")
            if isinstance(query, str) and query.strip():
                return query.strip()

    return None


def _capability_is_ready(capability_name: str) -> bool:
    """Return True when an optional capability is installed, enabled, and healthy."""
    try:
        capability_state = capability_manager.get_capability_state(capability_name)
    except Exception:
        return False

    return (
        bool(capability_state.get("installed"))
        and bool(capability_state.get("enabled"))
        and not bool(capability_state.get("restart_required"))
        and str(capability_state.get("health_status") or "").lower() == "ready"
    )


def build_visualization_capability_usage(visualization_spec: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Describe visualization-preview contribution in the normalized capability-usage format."""
    if not isinstance(visualization_spec, dict) or not visualization_spec.get("chart_type"):
        return []

    definition = capability_registry.get_definition("visualization_tools")
    point_count = _safe_int(visualization_spec.get("point_count"))
    chart_type = str(visualization_spec.get("chart_type") or "chart").strip()
    summary_text = str(visualization_spec.get("summary_text") or "").strip()
    if not summary_text:
        summary_text = f"Generated a {chart_type} preview from {point_count or 'several'} plotted values."

    return [
        {
            "name": "visualization_tools",
            "title": definition.title if definition else "Visualization Tools",
            "category": definition.category if definition else "tool_pack",
            "used_in": "chat_preview",
            "contribution": summary_text,
            "chunks": [
                {
                    "source": "Splunk query results",
                    "score": 100,
                    "snippet": summary_text,
                    "source_type": "query_result_preview",
                }
            ],
        }
    ]


def extract_primary_visualization(tool_calls: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Build or recover the most relevant visualization preview from recent tool calls."""
    if not isinstance(tool_calls, list) or not _capability_is_ready("visualization_tools"):
        return None

    for tool_call in reversed(tool_calls):
        if not isinstance(tool_call, dict):
            continue

        summary = tool_call.get("summary", {}) if isinstance(tool_call.get("summary", {}), dict) else {}
        existing_preview = summary.get("visualization_spec")
        if isinstance(existing_preview, dict) and existing_preview.get("chart_type"):
            return existing_preview

        rows = summary.get("actual_results", []) if isinstance(summary.get("actual_results", []), list) else []
        if not rows:
            continue

        visualization_result = capability_manager.build_visualization(
            "visualization_tools",
            {
                "rows": rows,
                "spl_query": tool_call.get("spl_query") or (tool_call.get("args", {}) if isinstance(tool_call.get("args", {}), dict) else {}).get("query"),
                "query_shape": summary.get("query_shape"),
                "sample_fields": summary.get("sample_fields"),
                "time_bounds": summary.get("time_bounds"),
                "top_dimensions": summary.get("top_dimensions"),
                "numeric_fields": summary.get("numeric_fields"),
                "row_count": summary.get("row_count"),
                "findings": summary.get("findings"),
            },
        )

        if visualization_result.ok:
            visualization_spec = visualization_result.details.get("visualization")
            if isinstance(visualization_spec, dict) and visualization_spec.get("chart_type"):
                summary["visualization_spec"] = visualization_spec
                return visualization_spec

    return None


def augment_capability_usage_with_visualization(
    tool_calls: Optional[List[Dict[str, Any]]],
    capability_usage: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Attach visualization contribution metadata when the preview capability contributes."""
    visualization_spec = extract_primary_visualization(tool_calls)
    enriched_usage = list(capability_usage or [])
    if not visualization_spec:
        return None, enriched_usage

    existing_names = {
        str(item.get("name") or "").strip().lower()
        for item in enriched_usage
        if isinstance(item, dict)
    }
    if "visualization_tools" not in existing_names:
        enriched_usage.extend(build_visualization_capability_usage(visualization_spec))

    return visualization_spec, enriched_usage


def detect_latest_entry_index_request(user_message: str) -> Optional[str]:
    """Detect user intent asking for latest/newest entry in a specific index."""
    if not isinstance(user_message, str):
        return None

    message = user_message.strip().lower()
    patterns = [
        r"latest\s+(?:entry|event|record|log\s*entry)\s+(?:in|from)\s+the\s+([a-zA-Z0-9_\-\.]+)\s+index",
        r"latest\s+(?:entry|event|record|log\s*entry)\s+(?:in|from)\s+([a-zA-Z0-9_\-\.]+)\s+index",
        r"newest\s+(?:entry|event|record)\s+(?:in|from)\s+the\s+([a-zA-Z0-9_\-\.]+)\s+index",
        r"what\s+is\s+the\s+latest\s+(?:entry|event|record)\s+(?:in|from)\s+([a-zA-Z0-9_\-\.]+)\s+index"
    ]

    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return None


def detect_edge_processor_template_request(user_message: str) -> bool:
    """Detect user intent asking for edge processor templates."""
    if not isinstance(user_message, str):
        return False
    message = user_message.lower()
    has_template_intent = any(token in message for token in ["template", "templates"])
    has_edge_processor_intent = (
        "edge processor" in message
        or "edge_processor" in message
        or ("edge" in message and "processor" in message)
    )
    return has_template_intent and has_edge_processor_intent


def detect_last_offline_target(user_message: str) -> Optional[str]:
    """Detect user intent asking when an entity (IP/host) was last offline."""
    if not isinstance(user_message, str):
        return None

    message = user_message.strip().lower()
    if "offline" not in message and "down" not in message:
        return None

    patterns = [
        r"last\s+time\s+that\s+([a-zA-Z0-9_\-\.]+)\s+was\s+reported\s+offline",
        r"when\s+was\s+the\s+last\s+time\s+([a-zA-Z0-9_\-\.]+)\s+was\s+offline",
        r"when\s+was\s+([a-zA-Z0-9_\-\.]+)\s+last\s+(?:reported\s+)?offline",
        r"last\s+offline\s+(?:event|time)\s+for\s+([a-zA-Z0-9_\-\.]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", message)
    if ip_match and ("offline" in message or "down" in message):
        return ip_match.group(1)

    return None


def _extract_query_terms_for_rag(user_message: str) -> List[str]:
    tokens = re.findall(r"[a-zA-Z0-9_\-\.]{3,}", user_message.lower())
    stopwords = {
        "what", "when", "where", "which", "that", "this", "with", "from", "have", "used",
        "show", "list", "last", "time", "were", "been", "into", "does", "about", "splunk"
    }
    unique = []
    seen = set()
    for token in tokens:
        if token in stopwords:
            continue
        if token not in seen:
            seen.add(token)
            unique.append(token)
    return unique[:10]


def build_lightweight_rag_context(user_message: str, max_chunks: int = 3) -> str:
    """Return optional RAG context through the capability framework."""
    rag_context, _ = get_optional_rag_context(user_message=user_message, max_chunks=max_chunks)
    return rag_context


def build_capability_usage_from_rag_result(rag_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize capability contribution details for UI and persistence."""
    if not isinstance(rag_result, dict):
        return []

    capability_name = str(rag_result.get("capability") or rag_result.get("provider") or "").strip()
    context_text = str(rag_result.get("context_text") or "")
    if not capability_name or not context_text:
        return []

    definition = capability_registry.get_definition(capability_name)
    chunks = rag_result.get("chunks", []) if isinstance(rag_result.get("chunks", []), list) else []
    normalized_chunks = []
    for chunk in chunks[:6]:
        if not isinstance(chunk, dict):
            continue
        source_name = str(chunk.get("source") or chunk.get("file") or "artifact").strip() or "artifact"
        snippet = str(chunk.get("snippet") or "").strip()
        metadata = chunk.get("metadata", {}) if isinstance(chunk.get("metadata", {}), dict) else {}
        normalized_chunks.append(
            {
                "source": source_name,
                "score": _safe_int(chunk.get("score", 0)),
                "snippet": snippet,
                "source_type": str(metadata.get("source_type") or "").strip() or None,
            }
        )

    chunk_count = len(normalized_chunks)
    contribution = (
        f"Added {chunk_count} matching artifact snippet{'s' if chunk_count != 1 else ''} to the LLM prompt context."
        if chunk_count > 0
        else "Added optional capability context to the LLM prompt."
    )

    return [
        {
            "name": capability_name,
            "title": definition.title if definition else capability_name,
            "category": definition.category if definition else "capability",
            "used_in": "llm_prompt",
            "contribution": contribution,
            "chunks": normalized_chunks,
        }
    ]


def build_capability_usage_brief(capability_usage: Optional[List[Dict[str, Any]]], limit: int = 2) -> str:
    """Render a brief retrieved-context section for report-backed responses."""
    if not isinstance(capability_usage, list):
        return ""

    lines: List[str] = []
    for usage in capability_usage:
        if not isinstance(usage, dict):
            continue
        chunks = usage.get("chunks", []) if isinstance(usage.get("chunks", []), list) else []
        for chunk in chunks[:limit]:
            if not isinstance(chunk, dict):
                continue
            source = Path(str(chunk.get("source") or "artifact")).name or "artifact"
            snippet = _compact_memory_text(chunk.get("snippet"), limit=180)
            if snippet:
                lines.append(f"- {source}: {snippet}")
        if lines:
            break

    if not lines:
        return ""

    return "Indexed context signals:\n" + "\n".join(lines)


def get_optional_rag_context(user_message: str, max_chunks: int = 3) -> Tuple[str, List[Dict[str, Any]]]:
    """Return optional RAG context and normalized capability usage details."""
    rag_result = capability_manager.get_rag_context(user_message=user_message, max_chunks=max_chunks)
    context_text = str(rag_result.get("context_text") or "") if isinstance(rag_result, dict) else ""
    capability_usage = build_capability_usage_from_rag_result(rag_result)
    return context_text, capability_usage


def detect_basic_inventory_intent(user_message: str, memory: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Detect common simple or memory-anchored intents that should not rely on LLM tool formatting."""
    if not isinstance(user_message, str):
        return None
    message = user_message.lower()
    remembered_index = extract_index_from_message(user_message) or _remembered_entity(memory or {}, "index")
    remembered_host = extract_host_or_ip_from_message(user_message) or _remembered_entity(memory or {}, "host")

    if remembered_index and any(token in message for token in ["timechart", "trend over time", "volume over time", "show trend"]):
        return "timechart_index_trend"
    if remembered_index and any(token in message for token in ["break it down", "breakdown", "by sourcetype", "by host"]):
        return "breakdown_index"
    if remembered_index and any(token in message for token in ["baseline count", "baseline check", "confirm data availability", "data availability"]):
        return "baseline_index_check"
    if remembered_host and any(token in message for token in ["pivot on host", "investigate host", "related anomalies", "host anomalies"]):
        return "host_pivot"

    if any(token in message for token in ["list indexes", "show indexes", "what indexes", "available indexes"]):
        return "list_indexes"
    if any(token in message for token in ["top indexes", "largest indexes", "most active indexes", "indexes by volume"]):
        return "top_indexes"
    if any(token in message for token in ["events by index", "event count by index", "count by index"]):
        return "top_indexes"
    if any(token in message for token in ["top errors", "most errors", "error summary", "error breakdown"]):
        return "top_errors"
    if any(token in message for token in ["auth failures", "authentication failures", "failed logins", "login failures"]):
        return "latest_auth_failures"
    if any(token in message for token in ["how many events in index", "event count for index", "count events in index", "events in index"]):
        if extract_index_from_message(user_message):
            return "count_index_events"
    if any(token in message for token in ["list sourcetypes", "show sourcetypes", "what sourcetypes"]):
        return "list_sourcetypes"
    if any(token in message for token in ["list hosts", "show hosts", "what hosts", "active hosts"]):
        return "list_hosts"
    if any(token in message for token in ["last seen", "latest heartbeat", "last heartbeat", "last event for host", "latest event for host"]):
        if extract_host_or_ip_from_message(user_message):
            return "latest_host_heartbeat"
    if "template" in message and "splunk" in message and "edge processor" not in message:
        return "list_templates"
    return None


def should_bypass_basic_inventory_intent(request: Optional[Dict[str, Any]]) -> bool:
    """Allow specialized chat launches to bypass short deterministic inventory routes."""
    if not isinstance(request, dict):
        return False

    investigation_mode = str(request.get("investigation_mode") or "").strip().lower()
    return investigation_mode in {"unknown_entity_context_builder", "context_explorer"}


def extract_index_from_message(user_message: str) -> Optional[str]:
    """Extract index target from natural language."""
    if not isinstance(user_message, str):
        return None
    quoted_name = r"['\"]?([a-zA-Z0-9_][a-zA-Z0-9_.-]*)['\"]?"
    patterns = [
        rf"\bindex\s*[=:]\s*{quoted_name}\b",
        rf"\bindex\s+{quoted_name}(?=\s*(?:\||earliest\s*=|latest\s*=|$))",
        rf"\bin\s+index\s+{quoted_name}\b",
        rf"\bfor\s+index\s+{quoted_name}\b",
        rf"\bin(?:\s+the)?\s+{quoted_name}\s+index\b",
        rf"\bfor(?:\s+the)?\s+{quoted_name}\s+index\b",
        rf"\bfrom(?:\s+the)?\s+{quoted_name}\s+index\b",
        rf"\bthe\s+{quoted_name}\s+index\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, user_message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def extract_host_or_ip_from_message(user_message: str) -> Optional[str]:
    """Extract host or IPv4 target from natural language."""
    if not isinstance(user_message, str):
        return None
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", user_message)
    if ip_match:
        return ip_match.group(0)
    host_match = re.search(r"host\s*[=:]?\s*([a-zA-Z0-9_\-.]+)", user_message, flags=re.IGNORECASE)
    if host_match:
        return host_match.group(1).strip()
    return None


def extract_time_range_from_message(user_message: str) -> Tuple[str, str]:
    """Extract a simple relative time range from plain language follow-on prompts."""
    if not isinstance(user_message, str):
        return "", ""

    message = user_message.lower()
    if any(token in message for token in ["last 24 hours", "past 24 hours", "-24h"]):
        return "-24h", "now"
    if any(token in message for token in ["last 7 days", "past 7 days", "last week", "-7d"]):
        return "-7d", "now"
    if any(token in message for token in ["last 30 days", "past 30 days", "last month", "-30d"]):
        return "-30d", "now"
    return "", ""


def parse_tool_call_payload(raw_json: str) -> Optional[Dict[str, Any]]:
    """Parse tool-call payload robustly across JSON and python-like dict styles."""
    if not isinstance(raw_json, str) or not raw_json.strip():
        return None

    payload = raw_json.strip()
    try:
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    try:
        import ast
        parsed = ast.literal_eval(payload)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    cleaned = re.sub(r",\s*([}\]])", r"\1", payload)
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None

    return None


def sanitize_llm_response_text(text: str) -> str:
    """Remove control markup like TOOL_CALL/CONTEXT_REQUEST from user-facing text."""
    if not isinstance(text, str):
        return ""

    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<thinking>.*?</thinking>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<CONTEXT_REQUEST>.*?</CONTEXT_REQUEST>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<TOOL_CALL>.*$', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = cleaned.replace('</TOOL_CALL>', '')
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip()


DEFAULT_DIRECT_CHAT_RESPONSE = "I couldn't generate a complete answer for that request. Please try again."
DEFAULT_TOOL_INVESTIGATION_RESPONSE = "Investigation complete. See findings above."


def finalize_user_facing_response_text(text: Any, fallback: str) -> str:
    """Return sanitized assistant text, or a sanitized fallback if nothing user-visible remains."""
    cleaned = sanitize_llm_response_text(str(text or ""))
    if cleaned:
        return cleaned
    return sanitize_llm_response_text(str(fallback or ""))


def extract_tool_call_from_text(response_text: str) -> Optional[Dict[str, Any]]:
    """Extract and normalize tool call payload from tagged response text."""
    if not isinstance(response_text, str):
        return None
    if '<TOOL_CALL>' not in response_text or '</TOOL_CALL>' not in response_text:
        return None

    start = response_text.find('<TOOL_CALL>') + len('<TOOL_CALL>')
    end = response_text.find('</TOOL_CALL>', start)
    if end <= start:
        return None

    raw_json = response_text[start:end].strip()
    tool_data = parse_tool_call_payload(raw_json)
    if not isinstance(tool_data, dict):
        return None

    tool_name = tool_data.get('tool')
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None

    tool_args = tool_data.get('args', {})
    if not isinstance(tool_args, dict):
        tool_args = {}

    return {
        "method": "tools/call",
        "params": {
            "name": tool_name.strip(),
            "arguments": tool_args
        }
    }


def _decode_inline_json_string(value: str) -> str:
    """Best-effort decode for partially escaped JSON fragments."""
    if not isinstance(value, str):
        return ""
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except Exception:
        return value


def extract_spl_from_response_text(response_text: str) -> Optional[str]:
    """Recover an SPL query from fenced code or simple inline query text."""
    if not isinstance(response_text, str) or not response_text.strip():
        return None

    patterns = [
        r'```spl\s*\n(.*?)```',
        r'```splunk\s*\n(.*?)```',
        r'```(?:\w+)?\s*\n((?:search\s+)?index=.*?)```',
        r'(?mi)^\s*(\|\s*tstats[^\n`]+)\s*$',
        r'(?mi)^\s*((?:search\s+)?index=[^\n`]+(?:\|\s*[^\n`]+)*)\s*$',
        r'(?mi)^\s*(search\s+[^\n`]+(?:\|\s*[^\n`]+)*)\s*$',
        r'(?is)\b(?:spl|query)\s*:\s*((?:search\s+)?index=.*?)(?:\n|$)',
    ]

    for pattern in patterns:
        match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1).strip().strip('"').strip("'")
        if candidate:
            return candidate

    return None


def user_requested_spl_explanation(user_message: str) -> bool:
    """Return True when the user explicitly asks to explain or understand a query before/while running it."""
    if not isinstance(user_message, str) or not user_message.strip():
        return False

    message = user_message.lower()
    explicit_phrases = [
        "explain this query",
        "explain this spl",
        "understand this query",
        "understand this spl",
        "help me understand this query",
        "help me understand this spl",
        "walk me through this query",
        "walk me through this spl",
        "break down this query",
        "break down this spl",
        "what does this query do",
        "what does this spl do",
    ]
    if any(phrase in message for phrase in explicit_phrases):
        return True

    asks_for_explanation = any(
        phrase in message
        for phrase in ["explain", "understand", "walk me through", "break down", "what does"]
    )
    references_query = any(token in message for token in [" query", " spl", "search ", "|"])
    return asks_for_explanation and references_query


def response_addresses_spl_explanation(response_text: str) -> bool:
    """Heuristic check for whether a response actually explains what the SPL is doing."""
    if not isinstance(response_text, str) or not response_text.strip():
        return False

    text = response_text.lower()
    explanation_anchors = [
        "this query",
        "this spl",
        "the query",
        "the spl",
    ]
    explanation_actions = [
        "searches",
        "filters",
        "limits",
        "groups",
        "counts",
        "calculates",
        "uses",
        "looks for",
        "narrows",
        "aggregates",
        "then it",
        "the first part",
        "the next part",
        "the final part",
        "in plain english",
    ]

    return (
        any(phrase in text for phrase in explanation_anchors)
        and any(phrase in text for phrase in explanation_actions)
    )


def build_spl_explanation_requirement(require_spl_explanation: bool) -> str:
    """Return extra guidance for chat turns that must explain an SPL query."""
    if not require_spl_explanation:
        return ""

    return """\nEXPLANATION REQUIREMENT:
- The user explicitly asked you to explain or help them understand the SPL.
- Your final answer must start with a plain-English explanation of what the SPL is doing.
- Call out the major search terms, filters, pipes, and transforming commands.
- Then summarize what happened when it ran, even if it returned no data or hit an error.
"""


def build_final_user_answer_prompt(
    user_message: str,
    insights_summary: str,
    require_spl_explanation: bool = False,
) -> str:
    """Build the final user-facing answer prompt for post-tool chat responses."""
    if require_spl_explanation:
        instructions = """1. Start by explaining in plain English what the SPL is doing step by step.
2. Call out the major search terms, filters, pipes, and transforming commands.
3. Then summarize what happened when it ran, including specific data/numbers if available.
4. End with any relevant context, caveats, or recommendations."""
    else:
        instructions = """1. Direct answer to their question with specific data/numbers
2. Key findings and patterns you discovered
3. Any relevant context or recommendations"""

    return f"""You successfully investigated the user's question: \"{user_message}\"

ACCUMULATED FINDINGS:
{insights_summary}

Now provide a COMPLETE, USER-FACING answer that includes:
{instructions}

Write as if speaking directly to the user (avoid phrases like \"I investigated\", \"I found\", \"I will\", etc.)."""


def _recover_tool_call_from_tagged_payload(
    response_text: str,
    query_tool_name: str,
    default_earliest: str = "-24h",
    default_latest: str = "now",
) -> Optional[Dict[str, Any]]:
    """Recover a tool call when the tagged JSON payload is malformed but structurally recognizable."""
    if not isinstance(response_text, str) or '<TOOL_CALL>' not in response_text or '</TOOL_CALL>' not in response_text:
        return None

    start = response_text.find('<TOOL_CALL>') + len('<TOOL_CALL>')
    end = response_text.find('</TOOL_CALL>', start)
    if end <= start:
        return None

    raw_payload = response_text[start:end].strip()
    if not raw_payload:
        return None

    tool_match = re.search(r'"tool"\s*:\s*"([^"]+)"', raw_payload)
    tool_name = tool_match.group(1).strip() if tool_match else query_tool_name

    query = None
    query_patterns = [
        r'"query"\s*:\s*"(?P<query>.*?)(?="\s*,\s*"(?:earliest_time|latest_time|row_limit|limit|count)|"\s*\}\s*\}|"\s*\})',
        r"'query'\s*:\s*'(?P<query>.*?)(?='\s*,\s*'(?:earliest_time|latest_time|row_limit|limit|count)|'\s*\}\s*\}|'\s*\})",
    ]
    for pattern in query_patterns:
        query_match = re.search(pattern, raw_payload, re.DOTALL)
        if query_match:
            query = _decode_inline_json_string(query_match.group('query').strip())
            break

    if not query:
        query = extract_spl_from_response_text(raw_payload)

    if not query:
        return None

    earliest_match = re.search(r'"earliest_time"\s*:\s*"([^"]+)"', raw_payload)
    latest_match = re.search(r'"latest_time"\s*:\s*"([^"]+)"', raw_payload)
    row_limit_match = re.search(r'"row_limit"\s*:\s*(\d+)', raw_payload)

    arguments: Dict[str, Any] = {
        "query": query,
        "earliest_time": earliest_match.group(1).strip() if earliest_match else default_earliest,
        "latest_time": latest_match.group(1).strip() if latest_match else default_latest,
    }
    if row_limit_match:
        arguments["row_limit"] = int(row_limit_match.group(1))

    return {
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        }
    }


def extract_recoverable_tool_call(
    response_text: str,
    query_tool_name: str,
    default_earliest: str = "-24h",
    default_latest: str = "now",
) -> Optional[Dict[str, Any]]:
    """Recover the next tool call from tagged JSON, malformed tags, bare JSON, or SPL text."""
    if not isinstance(response_text, str) or not response_text.strip():
        return None

    extracted = extract_tool_call_from_text(response_text)
    if extracted:
        return extracted

    recovered = _recover_tool_call_from_tagged_payload(
        response_text,
        query_tool_name,
        default_earliest=default_earliest,
        default_latest=default_latest,
    )
    if recovered:
        return recovered

    stripped = response_text.strip()
    if stripped.startswith("{") and 'tool' in stripped:
        payload = parse_tool_call_payload(stripped)
        if isinstance(payload, dict) and isinstance(payload.get('tool'), str):
            args = payload.get('args', {}) if isinstance(payload.get('args', {}), dict) else {}
            if 'query' in args and 'earliest_time' not in args:
                args['earliest_time'] = default_earliest
            if 'query' in args and 'latest_time' not in args:
                args['latest_time'] = default_latest
            return {
                "method": "tools/call",
                "params": {
                    "name": str(payload.get('tool')).strip(),
                    "arguments": args,
                }
            }

    spl_query = extract_spl_from_response_text(response_text)
    if spl_query:
        return {
            "method": "tools/call",
            "params": {
                "name": query_tool_name,
                "arguments": {
                    "query": spl_query,
                    "earliest_time": default_earliest,
                    "latest_time": default_latest,
                }
            }
        }

    return None


def has_continuation_intent(response_text: str) -> bool:
    """Detect when the model says it will run another step/query but omitted tool-call markup."""
    if not isinstance(response_text, str):
        return False

    lowered = response_text.lower()
    keyword_hits = [
        "let me run a query",
        "let me run",
        "let me query",
        "let me calculate",
        "let me check",
        "i will run",
        "i'll run",
        "i will query",
        "i'll query",
        "i will execute",
        "i'll execute",
        "i will calculate",
        "i'll calculate",
        "i need to calculate",
        "i will first",
        "i'll first",
        "next step"
    ]
    if any(token in lowered for token in keyword_hits):
        return True

    patterns = [
        r"\blet me\s+(run|execute|query|check|calculate|retrieve|search|analyze)\b",
        r"\bi\s+(will|need to)\s+(run|execute|query|check|calculate|retrieve|search|analyze)\b",
        r"\bi(?:'ll)\s+(run|execute|query|check|calculate|retrieve|search|analyze)\b"
    ]
    return any(re.search(pattern, lowered) for pattern in patterns)


def build_compact_chat_prompt(
    query_tool_name: str,
    discovery_context: str,
    rag_context: str,
    memory_context: str,
    available_tools_text: str,
    discovery_age_warning: Optional[str]
) -> str:
    """Compact, deterministic-first prompt for reliable Splunk chat behavior."""
    return f"""You are a precise Splunk assistant. Prioritize correctness over creativity.

Context:
{discovery_context}
{rag_context}
{discovery_age_warning or ''}
{memory_context}

Available tools:
{available_tools_text}

Rules:
1) Your primary expertise is DT4SMS, Splunk, discovery outputs, optional capabilities, and RAG context.
2) You may answer broader questions directly, but do not claim tool-backed or environment-specific evidence unless it comes from the provided context or executed tools.
3) When a session continuity gate is present, treat the current request as a follow-up unless the user clearly changes topic.
4) For data requests, execute tools rather than guessing.
5) If one query returns no data, broaden time range once and try a nearby index.
6) If still no data, explicitly say no data found and show what was tried.
7) Keep answers concise and factual.

Tool call format (required when querying):
<TOOL_CALL>{{"tool": "{query_tool_name}", "args": {{"query": "search index=main | head 5", "earliest_time": "-24h", "latest_time": "now"}}}}</TOOL_CALL>
"""


BASIC_UTILITY_UNIT_TOKENS = (
    "kb",
    "mb",
    "gb",
    "tb",
    "kib",
    "mib",
    "gib",
    "tib",
    "byte",
    "bytes",
    "second",
    "seconds",
    "sec",
    "secs",
    "minute",
    "minutes",
    "min",
    "mins",
    "hour",
    "hours",
    "hr",
    "hrs",
    "day",
    "days",
    "week",
    "weeks",
    "month",
    "months",
    "year",
    "years",
    "percent",
    "percentage",
)

CHAT_SCOPE_PATTERNS = (
    r"\bsplunk\b",
    r"\bdt4sms\b",
    r"\bmcp\b",
    r"\brag\b",
    r"\bartifact(?:s)?\b",
    r"\bknowledge asset(?:s)?\b",
    r"\bcontext preview\b",
    r"\bcapabilit(?:y|ies)\b",
    r"\bdeeplink(?:s)?\b",
    r"\bvisualization(?: tools)?\b",
    r"\bexport(?: tools| bundle| package)?\b",
    r"\bdiscovery(?: artifact| artifacts| report| reports| finding| findings| summary| session| sessions)?\b",
    r"\brunbook(?:s)?\b",
    r"\boperator runbook\b",
    r"\bsearch head\b",
    r"\bforwarder(?:s)?\b",
    r"\bindexer(?:s)?\b",
    r"\bkv store\b",
    r"\bsaved search(?:es)?\b",
    r"\bdata model(?:s)?\b",
    r"\bsourcetype(?:s)?\b",
    r"\blookups?\b",
    r"\bmacros?\b",
    r"\bingestion\b",
    r"\bscheduler\b",
    r"\blicense\b",
    r"\b_internal\b",
    r"\b_audit\b",
    r"\b_introspection\b",
    r"\bwhat can (?:this tool|you) do\b",
    r"\bwhat is (?:this tool|dt4sms) for\b",
    r"\bwhat are you for\b",
    r"\byour purpose\b",
)

CONTEXTUAL_ANALYSIS_TOKENS = (
    "retention",
    "disk",
    "size",
    "status",
    "temperature",
    "temp",
    "alert",
    "alerts",
    "drift",
    "sensor",
    "healthy",
    "online",
    "offline",
    "device",
    "current",
    "right now",
    "volume",
    "count",
    "trend",
    "breakdown",
    "compare",
    "query",
    "search",
    "event",
    "events",
    "host",
    "index",
    "sourcetype",
    "latency",
    "queue",
    "queues",
    "error",
    "errors",
    "failure",
    "failures",
    "exact",
    "estimate",
    "estimated",
    "last seen",
    "spike",
    "spikes",
)

CONTEXTUAL_FOLLOW_UP_PATTERNS = (
    r"\bwhat about\b",
    r"\bhow about\b",
    r"\btell me more\b",
    r"\bgo deeper\b",
    r"\bexpand that\b",
    r"\bdrill into\b",
    r"\bbreak that down\b",
    r"\b(?:that|this|same)\s+(?:index|host|sourcetype|query|search|retention|disk|size|volume|count|trend|breakdown|window)\b",
    r"\b(?:its|their|that|this)\s+(?:retention|disk|size|volume|count|trend|breakdown|last seen|latency|errors|failures)\b",
    r"\b(?:7|14|30|60|90)-?day\b",
)


def is_basic_utility_chat_request(user_message: str) -> bool:
    """Allow simple utility requests without turning chat into a general-purpose assistant."""
    if not isinstance(user_message, str):
        return False

    lowered = re.sub(r"\s+", " ", user_message.lower()).strip()
    if not lowered:
        return False

    if any(token in lowered for token in (
        "splunk",
        "dt4sms",
        "rag",
        "_internal",
        "_audit",
        "_introspection",
        "index=",
        "sourcetype",
        "host=",
        "knowledge asset",
        "capability",
        "ingestion",
    )):
        return False

    expression_candidate = lowered.rstrip(" ?")
    if re.fullmatch(r"(?:what(?:'s| is)\s+)?[-+/*().,%x=0-9\s]+", expression_candidate) and re.search(r"\d", expression_candidate):
        return True

    numeric_count = len(re.findall(r"\b\d+(?:\.\d+)?\b", lowered))
    has_unit_token = any(token in lowered for token in BASIC_UTILITY_UNIT_TOKENS)
    has_utility_keyword = any(re.search(pattern, lowered) for pattern in (
        r"^what(?:'s| is)\b",
        r"\bconvert\b",
        r"\bconversion\b",
        r"\bcalculate\b",
        r"\bmath\b",
        r"\bpercentage\b",
        r"\bpercent\b",
        r"\bdifference\b",
        r"\bsum\b",
        r"\baverage\b",
        r"\bmean\b",
        r"\bmedian\b",
        r"\bmultiply\b",
        r"\bdivide\b",
        r"\bplus\b",
        r"\bminus\b",
        r"\btimes\b",
        r"\bhow many\b",
    ))

    if numeric_count >= 2 and has_utility_keyword:
        return True
    if numeric_count >= 1 and has_unit_token and has_utility_keyword:
        return True
    if has_unit_token and re.match(r"^(what(?:'s| is)?|how many)\b", lowered):
        return True
    return False


def is_contextual_follow_up_for_active_scope(user_message: str, memory: Optional[Dict[str, Any]] = None) -> bool:
    """Allow ambiguous follow-ups to reach the LLM when an active Splunk investigation is already in progress."""
    if not isinstance(user_message, str) or not isinstance(memory, dict):
        return False

    lowered = re.sub(r"\s+", " ", user_message.lower()).strip()
    if not lowered:
        return False

    active_focus = str(memory.get("current_focus") or memory.get("primary_intent") or "").strip().lower()
    entities = memory.get("entities", {}) if isinstance(memory.get("entities", {}), dict) else {}
    has_scope_anchor = (
        active_focus not in {"", "general"}
        or any(entities.get(key) for key in ("indexes", "hosts", "sourcetypes", "sources"))
        or bool(memory.get("last_result"))
    )
    if not has_scope_anchor:
        return False

    has_follow_up_shape = any(re.search(pattern, lowered) for pattern in CONTEXTUAL_FOLLOW_UP_PATTERNS)
    has_analysis_token = any(token in lowered for token in CONTEXTUAL_ANALYSIS_TOKENS)
    memory_anchor_candidates: List[str] = []
    memory_anchor_candidates.extend(
        item for item in memory.get("locations", [])[-6:]
        if isinstance(item, str) and item.strip()
    )
    entities = memory.get("entities", {}) if isinstance(memory.get("entities", {}), dict) else {}
    for key in ("indexes", "hosts", "sourcetypes", "sources"):
        memory_anchor_candidates.extend(
            item for item in entities.get(key, [])[-6:]
            if isinstance(item, str) and item.strip()
        )
    memory_anchor_match = any(
        candidate.lower() in lowered
        for candidate in memory_anchor_candidates
        if isinstance(candidate, str) and len(candidate.strip()) >= 3
    )

    if has_follow_up_shape and has_analysis_token:
        return True

    if memory_anchor_match and (has_analysis_token or len(lowered.split()) <= 10):
        return True

    # Very short analytic follow-ups often omit the noun entirely after a scoped turn.
    if len(lowered.split()) <= 8 and active_focus not in {"", "general"} and has_analysis_token:
        return True

    return False


def is_scope_relevant_chat_request(
    user_message: str,
    report_knowledge: Optional[Dict[str, Any]] = None,
    memory: Optional[Dict[str, Any]] = None,
    report_intent: Optional[str] = None,
) -> bool:
    """Return True when a chat request is within DT4SMS/Splunk scope."""
    if not isinstance(user_message, str):
        return False

    if report_intent:
        return True
    if detect_basic_inventory_intent(user_message, memory):
        return True
    if is_contextual_follow_up_for_active_scope(user_message, memory):
        return True
    if detect_latest_entry_index_request(user_message) or detect_last_offline_target(user_message) or detect_edge_processor_template_request(user_message):
        return True
    if extract_index_from_message(user_message) or extract_host_or_ip_from_message(user_message):
        return True

    lowered = user_message.lower()
    if any(re.search(pattern, lowered) for pattern in CHAT_SCOPE_PATTERNS):
        return True

    if isinstance(report_knowledge, dict):
        known_entities = report_knowledge.get("known_entities", {}) if isinstance(report_knowledge.get("known_entities", {}), dict) else {}
        for key in ("indexes", "sourcetypes", "hosts", "sources"):
            if _known_entity_matches(user_message, known_entities.get(key, []), limit=1):
                return True

    return False


def build_scope_redirect_response() -> str:
    """Return a concise reminder that chat is scoped to DT4SMS and Splunk work."""
    return (
        "I'm here to help with DT4SMS, Splunk investigations, discovery findings, optional capabilities, RAG context, and related operational questions. "
        "Small utility asks like basic math or unit conversions are fine, but this chat is not meant to be a general-purpose AI resource. "
        "Ask me about searches, indexes, sourcetypes, platform health, discovery recommendations, RAG assets, or capability configuration."
    )


def build_scope_redirect_follow_on_actions() -> List[Dict[str, str]]:
    """Provide a few in-scope prompts when chat redirects an unrelated request."""
    return [
        _make_follow_on_action(
            "Explain DT4SMS scope",
            "What can this tool help me do across Splunk, discovery outputs, capabilities, and the RAG workspace?",
            "scope_redirect",
        ),
        _make_follow_on_action(
            "Check platform health",
            "Check Splunk platform health in _internal, _audit, and _introspection over the last 24 hours and summarize ingestion issues, search failures, and license signals.",
            "scope_redirect",
        ),
        _make_follow_on_action(
            "List available indexes",
            "List the Splunk indexes available in this environment.",
            "scope_redirect",
        ),
    ]


def _discovery_session_manifest_path() -> Path:
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir / "discovery_sessions.json"


def _summary_infographic_dir() -> Path:
    return Path("output") / SUMMARY_INFOGRAPHIC_DIRNAME


def _extract_session_timestamp_from_artifact_name(filename: str) -> Optional[str]:
    safe_name = Path(str(filename or "")).name
    infographic_match = re.match(
        rf"^{SUMMARY_INFOGRAPHIC_PREFIX}(\d{{8}}_\d{{6}})(?:_\d{{8}}_\d{{6}})?\.[A-Za-z0-9]+$",
        safe_name,
    )
    if infographic_match:
        return infographic_match.group(1)

    if safe_name.startswith(SUMMARY_INFOGRAPHIC_PREFIX):
        return None

    generic_matches = re.findall(r"(\d{8}_\d{6})", safe_name)
    if generic_matches:
        return generic_matches[0]
    return None


def _build_artifact_metadata(file_path: Path) -> Dict[str, Any]:
    modified_iso = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
    size_bytes = file_path.stat().st_size
    artifact_name = file_path.name
    artifact_suffix = file_path.suffix[1:].lower() if file_path.suffix else "unknown"
    artifact_kind = "infographic" if artifact_name.startswith(SUMMARY_INFOGRAPHIC_PREFIX) else "report"
    return {
        "name": artifact_name,
        "path": str(file_path),
        "size": size_bytes,
        "size_bytes": size_bytes,
        "modified": modified_iso,
        "modified_at": modified_iso,
        "type": artifact_suffix,
        "artifact_kind": artifact_kind,
        "session_timestamp": _extract_session_timestamp_from_artifact_name(artifact_name),
    }


def _iter_catalog_artifact_paths() -> List[Path]:
    output_dir = Path("output")
    artifact_paths: List[Path] = []
    if output_dir.exists():
        artifact_paths.extend(path for path in output_dir.glob("v2_*") if path.is_file())

    infographic_dir = _summary_infographic_dir()
    if infographic_dir.exists():
        artifact_paths.extend(
            path
            for path in infographic_dir.glob(f"{SUMMARY_INFOGRAPHIC_PREFIX}*")
            if path.is_file()
            and path.suffix.lower() in IMAGE_ARTIFACT_EXTENSIONS
            and _extract_session_timestamp_from_artifact_name(path.name)
        )

    return sorted(artifact_paths, key=lambda path: path.stat().st_mtime, reverse=True)


def _resolve_output_artifact_path(filename: str) -> Path:
    safe_filename = sanitize_filename(filename)
    output_dir = Path("output").resolve()
    candidate_paths = [
        (Path("output") / safe_filename).resolve(),
        (_summary_infographic_dir() / safe_filename).resolve(),
    ]
    for candidate in candidate_paths:
        if not candidate.is_relative_to(output_dir):
            continue
        if candidate.exists() and candidate.is_file():
            return candidate
    raise HTTPException(status_code=404, detail="Report not found")


def _find_existing_summary_infographic(timestamp: str) -> Optional[Path]:
    safe_timestamp = str(timestamp or "").strip()
    if not safe_timestamp:
        return None

    infographic_dir = _summary_infographic_dir()
    if not infographic_dir.exists():
        return None

    matches = sorted(
        infographic_dir.glob(f"{SUMMARY_INFOGRAPHIC_PREFIX}{safe_timestamp}_*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for match in matches:
        if match.is_file() and match.suffix.lower() in IMAGE_ARTIFACT_EXTENSIONS:
            return match
    return None


def _ensure_session_artifact_registered(timestamp: str, artifact_name: str) -> None:
    safe_timestamp = str(timestamp or "").strip()
    safe_artifact_name = Path(str(artifact_name or "")).name
    if not safe_timestamp or not safe_artifact_name:
        return
    if _extract_session_timestamp_from_artifact_name(safe_artifact_name) != safe_timestamp:
        return

    sessions = load_discovery_sessions()
    changed = False
    session_record = next((session for session in sessions if str(session.get("timestamp") or "") == safe_timestamp), None)
    if session_record is None:
        session_record = {
            "timestamp": safe_timestamp,
            "created_at": datetime.now().isoformat(),
            "overview": {},
            "report_paths": [],
            "mcp_capabilities": {},
            "stats": {
                "discovery_steps": 0,
                "classification_groups": 0,
                "recommendation_count": 0,
                "suggested_use_case_count": 0,
            },
        }
        sessions.append(session_record)
        changed = True

    report_paths = session_record.setdefault("report_paths", [])
    if safe_artifact_name not in report_paths:
        report_paths.append(safe_artifact_name)
        changed = True

    if changed:
        sessions = sorted(sessions, key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        save_discovery_sessions(sessions[:100])


def _session_has_meaningful_discovery_data(session: Dict[str, Any]) -> bool:
    if not isinstance(session, dict):
        return False

    overview = session.get("overview", {})
    if isinstance(overview, dict) and any(value not in (None, "", [], {}, 0) for value in overview.values()):
        return True

    personas = session.get("personas", {})
    if isinstance(personas, dict) and any(personas.values()):
        return True

    mcp_capabilities = session.get("mcp_capabilities", {})
    if isinstance(mcp_capabilities, dict) and any(mcp_capabilities.values()):
        return True

    readiness_score = session.get("readiness_score")
    if readiness_score not in (None, "", 0):
        return True

    stats = session.get("stats", {})
    if isinstance(stats, dict):
        for value in stats.values():
            try:
                if int(value) > 0:
                    return True
            except (TypeError, ValueError):
                continue

    return False


def _normalize_discovery_sessions(sessions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    normalized_sessions: List[Dict[str, Any]] = []
    changed = False

    for session in sessions:
        if not isinstance(session, dict):
            changed = True
            continue

        timestamp = str(session.get("timestamp") or "").strip()
        if not timestamp:
            changed = True
            continue

        raw_report_paths = session.get("report_paths", [])
        report_paths = raw_report_paths if isinstance(raw_report_paths, list) else []
        clean_report_paths: List[str] = []

        for report_name in report_paths:
            safe_report_name = Path(str(report_name or "")).name
            if not safe_report_name:
                changed = True
                continue
            if _extract_session_timestamp_from_artifact_name(safe_report_name) != timestamp:
                changed = True
                continue
            try:
                _resolve_output_artifact_path(safe_report_name)
            except HTTPException:
                changed = True
                continue
            if safe_report_name not in clean_report_paths:
                clean_report_paths.append(safe_report_name)
            else:
                changed = True

        normalized_session = dict(session)
        if clean_report_paths != report_paths:
            normalized_session["report_paths"] = clean_report_paths
            changed = True

        if not clean_report_paths and not _session_has_meaningful_discovery_data(normalized_session):
            changed = True
            continue

        normalized_sessions.append(normalized_session)

    normalized_sessions.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    if len(normalized_sessions) > 100:
        changed = True
    return normalized_sessions[:100], changed


def _augment_sessions_with_catalog_artifacts(sessions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    sessions, changed = _normalize_discovery_sessions(sessions)
    sessions_by_timestamp: Dict[str, Dict[str, Any]] = {
        str(session.get("timestamp") or ""): session
        for session in sessions
        if isinstance(session, dict) and str(session.get("timestamp") or "").strip()
    }

    for artifact_path in _iter_catalog_artifact_paths():
        timestamp = _extract_session_timestamp_from_artifact_name(artifact_path.name)
        if not timestamp:
            continue
        session_entry = sessions_by_timestamp.get(timestamp)
        if session_entry is None:
            session_entry = {
                "timestamp": timestamp,
                "created_at": datetime.fromtimestamp(artifact_path.stat().st_mtime).isoformat(),
                "overview": {},
                "report_paths": [],
                "mcp_capabilities": {},
                "stats": {
                    "discovery_steps": 0,
                    "classification_groups": 0,
                    "recommendation_count": 0,
                    "suggested_use_case_count": 0,
                },
            }
            sessions.append(session_entry)
            sessions_by_timestamp[timestamp] = session_entry
            changed = True

        report_paths = session_entry.setdefault("report_paths", [])
        if artifact_path.name not in report_paths:
            report_paths.append(artifact_path.name)
            changed = True

    sessions.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return sessions[:100], changed


def load_discovery_sessions() -> List[Dict[str, Any]]:
    """Load persisted discovery session catalog."""
    manifest_path = _discovery_session_manifest_path()
    if not manifest_path.exists():
        # Backfill from existing report files for legacy runs
        if not Path("output").exists():
            return []

        sessions_by_timestamp: Dict[str, Dict[str, Any]] = {}
        for file_path in _iter_catalog_artifact_paths():
            timestamp = _extract_session_timestamp_from_artifact_name(file_path.name)
            if not timestamp:
                continue
            entry = sessions_by_timestamp.setdefault(timestamp, {
                "timestamp": timestamp,
                "created_at": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                "overview": {},
                "report_paths": [],
                "mcp_capabilities": {},
                "stats": {
                    "discovery_steps": 0,
                    "classification_groups": 0,
                    "recommendation_count": 0,
                    "suggested_use_case_count": 0
                }
            })
            entry["report_paths"].append(file_path.name)

        reconstructed, changed = _augment_sessions_with_catalog_artifacts(
            sorted(sessions_by_timestamp.values(), key=lambda x: x.get("timestamp", ""), reverse=True)
        )
        if reconstructed:
            save_discovery_sessions(reconstructed)
        return reconstructed

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            augmented_sessions, changed = _augment_sessions_with_catalog_artifacts(data)
            if changed:
                save_discovery_sessions(augmented_sessions)
            return augmented_sessions
    except Exception:
        pass

    return []


def save_discovery_sessions(sessions: List[Dict[str, Any]]) -> None:
    """Persist discovery session catalog."""
    manifest_path = _discovery_session_manifest_path()
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2)
    except Exception:
        pass


def register_discovery_session(
    timestamp: str,
    overview: Any,
    report_paths: List[str],
    mcp_capabilities: Dict[str, Any],
    classifications: Dict[str, Any],
    recommendations: List[Dict[str, Any]],
    suggested_use_cases: List[Dict[str, Any]],
    discovery_step_count: int,
    personas: Optional[Dict[str, Any]] = None,
    readiness_score: Optional[int] = None
) -> Dict[str, Any]:
    """Register a discovery session in manifest for retrieval and UI history."""
    sessions = load_discovery_sessions()

    session_record = {
        "timestamp": timestamp,
        "created_at": datetime.now().isoformat(),
        "overview": {
            "total_indexes": getattr(overview, "total_indexes", 0),
            "total_sourcetypes": getattr(overview, "total_sourcetypes", 0),
            "total_hosts": getattr(overview, "total_hosts", 0),
            "total_users": getattr(overview, "total_users", 0),
            "data_volume_24h": getattr(overview, "data_volume_24h", "unknown"),
            "splunk_version": getattr(overview, "splunk_version", "unknown")
        },
        "report_paths": report_paths,
        "mcp_capabilities": mcp_capabilities,
        "personas": personas or {},
        "readiness_score": readiness_score if isinstance(readiness_score, int) else 0,
        "stats": {
            "discovery_steps": discovery_step_count,
            "classification_groups": len(classifications) if isinstance(classifications, dict) else 0,
            "recommendation_count": len(recommendations) if isinstance(recommendations, list) else 0,
            "suggested_use_case_count": len(suggested_use_cases) if isinstance(suggested_use_cases, list) else 0
        }
    }

    # Replace if same timestamp exists
    sessions = [s for s in sessions if s.get("timestamp") != timestamp]
    sessions.insert(0, session_record)
    sessions = sorted(sessions, key=lambda x: x.get("timestamp", ""), reverse=True)
    save_discovery_sessions(sessions[:100])
    return session_record


def _safe_int(value: Any) -> int:
    """Convert scalar-like values to int without raising."""
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            cleaned = value.replace(",", "").strip()
            return int(float(cleaned))
    except Exception:
        pass
    return 0


def compute_discovery_readiness_score(
    overview: Any,
    recommendations: List[Dict[str, Any]],
    suggested_use_cases: List[Dict[str, Any]],
    mcp_capabilities: Dict[str, Any]
) -> int:
    """Compute a practical readiness score for platform maturity (0-100)."""
    score = 0
    total_indexes = _safe_int(getattr(overview, "total_indexes", 0))
    total_sourcetypes = _safe_int(getattr(overview, "total_sourcetypes", 0))
    total_hosts = _safe_int(getattr(overview, "total_hosts", 0))
    tool_count = _safe_int((mcp_capabilities or {}).get("tool_count", 0))
    recommendation_count = len(recommendations) if isinstance(recommendations, list) else 0
    use_case_count = len(suggested_use_cases) if isinstance(suggested_use_cases, list) else 0

    score += min(25, total_indexes)
    score += min(20, total_sourcetypes // 2)
    score += min(10, total_hosts // 2)
    score += min(20, tool_count * 2)
    score += min(15, recommendation_count * 2)
    score += min(10, use_case_count * 2)
    return max(0, min(100, score))


def build_context_explorer_payload(
    discovery_data: Optional[Dict[str, Any]],
    unknown_questions: Optional[List[Dict[str, Any]]] = None,
    admin_tasks: Optional[List[Dict[str, Any]]] = None,
    coverage_gaps: Optional[List[Dict[str, Any]]] = None,
    risk_register: Optional[List[Dict[str, Any]]] = None,
    readiness_score: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a session-scoped context explorer payload from discovery artifacts."""
    if not isinstance(discovery_data, dict):
        return {
            "overview": {},
            "anchors": {"indexes": [], "sourcetypes": [], "hosts": []},
            "patterns": [],
            "lanes": {
                "unknown_entities": [],
                "coverage_gaps": [],
                "risks": [],
                "priority_tasks": [],
            },
        }

    overview = discovery_data.get("overview", {}) if isinstance(discovery_data.get("overview", {}), dict) else {}
    finding_ledger = discovery_data.get("finding_ledger", []) if isinstance(discovery_data.get("finding_ledger", []), list) else []

    indexes: List[Dict[str, Any]] = []
    sourcetypes: List[Dict[str, Any]] = []
    hosts: List[Dict[str, Any]] = []
    seen_index_names: set[str] = set()
    seen_sourcetype_names: set[str] = set()
    seen_host_names: set[str] = set()

    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue

        data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
        if not data:
            continue

        index_name = str(data.get("title", "")).strip()
        if index_name and "totalEventCount" in data and str(data.get("disabled", "0")) != "1":
            lowered_index = index_name.lower()
            if lowered_index not in seen_index_names:
                seen_index_names.add(lowered_index)
                indexes.append({
                    "name": index_name,
                    "events": _safe_int(data.get("totalEventCount", 0)),
                    "size_mb": float(data.get("currentDBSizeMB", 0) or 0),
                    "datatype": str(data.get("datatype", "event") or "event"),
                    "max_time": data.get("maxTime") or data.get("lastTimeIso") or "",
                })

        sourcetype_name = data.get("sourcetype")
        if not sourcetype_name and str(data.get("type", "")).lower() in {"sourcetypes", "source_types"}:
            sourcetype_name = data.get("title")
        if isinstance(sourcetype_name, str) and sourcetype_name.strip():
            normalized_sourcetype = sourcetype_name.strip()
            lowered_sourcetype = normalized_sourcetype.lower()
            if lowered_sourcetype not in seen_sourcetype_names:
                seen_sourcetype_names.add(lowered_sourcetype)
                sourcetypes.append({
                    "name": normalized_sourcetype,
                    "events": _safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount")),
                    "recent_time": data.get("recentTimeIso") or data.get("lastTimeIso") or "",
                })

        host_name = data.get("host") or data.get("hostname")
        descriptor = str(entry.get("title") or entry.get("description") or "")
        if not host_name and "Analyzing host:" in descriptor:
            host_name = data.get("title")
        if isinstance(host_name, str) and host_name.strip():
            normalized_host = host_name.strip()
            lowered_host = normalized_host.lower()
            if lowered_host not in seen_host_names:
                seen_host_names.add(lowered_host)
                hosts.append({
                    "name": normalized_host,
                    "events": _safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount")),
                })

    indexes.sort(key=lambda item: item.get("events", 0), reverse=True)
    sourcetypes.sort(key=lambda item: item.get("events", 0), reverse=True)
    hosts.sort(key=lambda item: item.get("events", 0), reverse=True)

    normalized_patterns: List[Dict[str, str]] = []
    raw_patterns = overview.get("notable_patterns", []) if isinstance(overview.get("notable_patterns", []), list) else []
    seen_pattern_titles = set()
    for raw_pattern in raw_patterns:
        payload = raw_pattern
        if isinstance(raw_pattern, str):
            try:
                payload = json.loads(raw_pattern)
            except Exception:
                payload = {"patterns": [{"title": raw_pattern}]}

        if isinstance(payload, dict) and isinstance(payload.get("patterns"), list):
            pattern_items = payload.get("patterns", [])
        else:
            pattern_items = [payload]

        for pattern in pattern_items:
            title = ""
            description = ""
            signal = ""
            if isinstance(pattern, dict):
                title = str(pattern.get("title") or pattern.get("name") or pattern.get("pattern") or pattern.get("signal") or "").strip()
                description = str(pattern.get("description") or pattern.get("summary") or pattern.get("insight") or "").strip()
                evidence = pattern.get("evidence")
                if isinstance(evidence, list):
                    signal = ", ".join([str(item).strip() for item in evidence[:2] if str(item).strip()])
                elif isinstance(evidence, str):
                    signal = evidence.strip()
            elif isinstance(pattern, str):
                title = pattern.strip()

            if not title:
                continue

            lowered_title = title.lower()
            if lowered_title in seen_pattern_titles:
                continue
            seen_pattern_titles.add(lowered_title)
            normalized_patterns.append({
                "title": title,
                "description": description,
                "signal": signal,
            })
            if len(normalized_patterns) >= 6:
                break
        if len(normalized_patterns) >= 6:
            break

    safe_unknowns = [item for item in (unknown_questions or []) if isinstance(item, dict)]
    safe_gaps = [item for item in (coverage_gaps or discovery_data.get("coverage_gaps", []) or []) if isinstance(item, dict)]
    safe_risks = [item for item in (risk_register or discovery_data.get("risk_register", []) or []) if isinstance(item, dict)]
    safe_tasks = [item for item in (admin_tasks or []) if isinstance(item, dict)]

    return {
        "overview": {
            "readiness_score": _safe_int(readiness_score if readiness_score is not None else discovery_data.get("readiness_score")),
            "total_indexes": _safe_int(overview.get("total_indexes", len(indexes))),
            "total_sourcetypes": _safe_int(overview.get("total_sourcetypes", len(sourcetypes))),
            "total_hosts": _safe_int(overview.get("total_hosts", len(hosts))),
            "data_volume_24h": str(overview.get("data_volume_24h", "unknown") or "unknown"),
            "license_state": str(overview.get("license_state", "unknown") or "unknown"),
        },
        "anchors": {
            "indexes": indexes[:8],
            "sourcetypes": sourcetypes[:8],
            "hosts": hosts[:8],
        },
        "patterns": normalized_patterns[:6],
        "lanes": {
            "unknown_entities": safe_unknowns[:6],
            "coverage_gaps": safe_gaps[:6],
            "risks": safe_risks[:6],
            "priority_tasks": [
                {
                    "title": str(task.get("title") or "Untitled task"),
                    "priority": str(task.get("priority") or "MEDIUM"),
                    "category": str(task.get("category") or "General"),
                    "finding_reference": str(task.get("finding_reference") or ""),
                }
                for task in safe_tasks[:6]
            ],
        },
    }


def build_persona_playbooks(
    overview: Any,
    recommendations: List[Dict[str, Any]],
    suggested_use_cases: List[Dict[str, Any]],
    mcp_capabilities: Dict[str, Any]
) -> Dict[str, Any]:
    """Build persona-specific outputs for admins, analysts, and executives."""
    recs = recommendations if isinstance(recommendations, list) else []
    use_cases = suggested_use_cases if isinstance(suggested_use_cases, list) else []

    high_priority = [r for r in recs if isinstance(r, dict) and str(r.get("priority", "")).lower() == "high"]
    top_recs = (high_priority or recs)[:5]
    top_use_cases = [u for u in use_cases if isinstance(u, dict)][:4]

    admin_actions = []
    for rec in top_recs:
        title = rec.get("title", "Recommendation")
        complexity = rec.get("complexity", "unknown")
        admin_actions.append({
            "title": title,
            "why": rec.get("description", "No description"),
            "effort": complexity,
            "owner": "Splunk Admin",
            "next_step": f"Create implementation task for: {title}"
        })

    analyst_hypotheses = []
    for use_case in top_use_cases:
        analyst_hypotheses.append({
            "title": use_case.get("title", "Use Case"),
            "question": use_case.get("description", ""),
            "data_sources": use_case.get("data_sources", []),
            "success_metric": (use_case.get("success_metrics", ["Actionable detection uplift"]) or ["Actionable detection uplift"])[0]
        })

    readiness_score = compute_discovery_readiness_score(overview, recs, use_cases, mcp_capabilities)
    exec_brief = {
        "platform_readiness_score": readiness_score,
        "headline": "Splunk discovery indicates strong baseline with clear optimization opportunities.",
        "business_value_themes": [
            "Risk reduction through improved coverage and detection fidelity",
            "Operational efficiency via standardization and automation",
            "Faster decision-making with cross-functional analytics"
        ],
        "next_90_day_focus": [
            "Execute top high-priority recommendations",
            "Productize at least 2 cross-functional use cases",
            "Track measurable KPIs for detection quality and MTTR"
        ],
        "environment_snapshot": {
            "indexes": _safe_int(getattr(overview, "total_indexes", 0)),
            "sourcetypes": _safe_int(getattr(overview, "total_sourcetypes", 0)),
            "hosts": _safe_int(getattr(overview, "total_hosts", 0)),
            "tooling_capability_count": _safe_int((mcp_capabilities or {}).get("tool_count", 0))
        }
    }

    return {
        "admin": {
            "title": "Admin Action Queue",
            "actions": admin_actions[:6]
        },
        "analyst": {
            "title": "Analyst Investigation Tracks",
            "hypotheses": analyst_hypotheses[:6]
        },
        "executive": exec_brief
    }


def hydrate_discovery_session(session: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Hydrate a session with readiness/personas when legacy records are missing those fields."""
    if not isinstance(session, dict):
        return session

    hydrated = dict(session)
    if hydrated.get("readiness_score") and hydrated.get("personas"):
        return hydrated

    timestamp = hydrated.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return hydrated

    export_path = Path("output") / f"discovery_export_{timestamp}.json"
    if not export_path.exists():
        return hydrated

    try:
        with open(export_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        overview_data = payload.get("overview", {}) if isinstance(payload, dict) else {}
        recommendations_data = payload.get("recommendations", []) if isinstance(payload, dict) else []
        use_cases_data = payload.get("suggested_use_cases", []) if isinstance(payload, dict) else []
        mcp_data = payload.get("mcp_capabilities", {}) if isinstance(payload, dict) else {}

        class _OverviewProxy:
            def __init__(self, values: Dict[str, Any]):
                for k, v in values.items():
                    setattr(self, k, v)

        overview_proxy = _OverviewProxy(overview_data if isinstance(overview_data, dict) else {})
        hydrated["readiness_score"] = compute_discovery_readiness_score(
            overview_proxy,
            recommendations_data if isinstance(recommendations_data, list) else [],
            use_cases_data if isinstance(use_cases_data, list) else [],
            mcp_data if isinstance(mcp_data, dict) else {}
        )
        hydrated["personas"] = build_persona_playbooks(
            overview_proxy,
            recommendations_data if isinstance(recommendations_data, list) else [],
            use_cases_data if isinstance(use_cases_data, list) else [],
            mcp_data if isinstance(mcp_data, dict) else {}
        )
    except Exception:
        return hydrated

    return hydrated


def _resolve_session_selection(
    sessions: List[Dict[str, Any]],
    selection: Optional[str],
    default_index: int
) -> Optional[Dict[str, Any]]:
    """Resolve a session selector (latest/previous/timestamp) to a concrete session."""
    if not sessions:
        return None

    token = (selection or "").strip().lower()
    if token in {"", "latest"}:
        return sessions[0]
    if token == "previous":
        return sessions[1] if len(sessions) > 1 else None

    matched = next((s for s in sessions if s.get("timestamp") == selection), None)
    if matched:
        return matched

    return sessions[default_index] if len(sessions) > default_index else sessions[0]


def build_discovery_compare_payload(
    current_selection: Optional[str] = None,
    baseline_selection: Optional[str] = None
) -> Dict[str, Any]:
    """Build compare payload across two discovery sessions."""
    sessions = load_discovery_sessions()
    if len(sessions) < 2:
        return {
            "has_data": False,
            "message": "At least two discovery sessions are required for compare.",
            "sessions": sessions[:20]
        }

    current = hydrate_discovery_session(_resolve_session_selection(sessions, current_selection, 0))
    baseline = hydrate_discovery_session(_resolve_session_selection(sessions, baseline_selection, 1))

    if not current or not baseline:
        return {
            "has_data": False,
            "message": "Unable to resolve selected sessions for compare.",
            "sessions": sessions[:20]
        }

    if current.get("timestamp") == baseline.get("timestamp"):
        return {
            "has_data": False,
            "message": "Choose two different sessions to compare.",
            "sessions": sessions[:20],
            "current": current,
            "baseline": baseline
        }

    def _metric(session: Dict[str, Any], path: List[str]) -> int:
        value: Any = session
        for key in path:
            value = value.get(key, {}) if isinstance(value, dict) else {}
        return _safe_int(value)

    metrics = {
        "readiness": {
            "current": _metric(current, ["readiness_score"]),
            "baseline": _metric(baseline, ["readiness_score"])
        },
        "indexes": {
            "current": _metric(current, ["overview", "total_indexes"]),
            "baseline": _metric(baseline, ["overview", "total_indexes"])
        },
        "sourcetypes": {
            "current": _metric(current, ["overview", "total_sourcetypes"]),
            "baseline": _metric(baseline, ["overview", "total_sourcetypes"])
        },
        "recommendations": {
            "current": _metric(current, ["stats", "recommendation_count"]),
            "baseline": _metric(baseline, ["stats", "recommendation_count"])
        },
        "tools": {
            "current": _metric(current, ["mcp_capabilities", "tool_count"]),
            "baseline": _metric(baseline, ["mcp_capabilities", "tool_count"])
        }
    }

    for metric in metrics.values():
        metric["delta"] = metric["current"] - metric["baseline"]

    admin_current = (current.get("personas", {}).get("admin", {}).get("actions", [])
                     if isinstance(current.get("personas", {}), dict) else [])
    admin_baseline = (baseline.get("personas", {}).get("admin", {}).get("actions", [])
                      if isinstance(baseline.get("personas", {}), dict) else [])

    analyst_current = (current.get("personas", {}).get("analyst", {}).get("hypotheses", [])
                       if isinstance(current.get("personas", {}), dict) else [])
    analyst_baseline = (baseline.get("personas", {}).get("analyst", {}).get("hypotheses", [])
                        if isinstance(baseline.get("personas", {}), dict) else [])

    return {
        "has_data": True,
        "current": current,
        "baseline": baseline,
        "metrics": metrics,
        "persona_deltas": {
            "admin_actions_delta": len(admin_current) - len(admin_baseline),
            "analyst_tracks_delta": len(analyst_current) - len(analyst_baseline)
        },
        "sessions": sessions[:20]
    }


def build_session_runbook_payload(
    timestamp: Optional[str] = None,
    persona: str = "admin"
) -> Dict[str, Any]:
    """Build one-click operational runbook payload for a selected persona and session."""
    sessions = load_discovery_sessions()
    if not sessions:
        return {
            "has_data": False,
            "message": "No discovery sessions available.",
            "sessions": []
        }

    selected = hydrate_discovery_session(_resolve_session_selection(sessions, timestamp, 0))
    if not selected:
        return {
            "has_data": False,
            "message": "Discovery session not found.",
            "sessions": sessions[:20]
        }

    persona_key = str(persona or "admin").strip().lower()
    if persona_key not in {"admin", "analyst", "executive"}:
        persona_key = "admin"

    ts = selected.get("timestamp", "unknown")
    personas = selected.get("personas", {}) if isinstance(selected.get("personas", {}), dict) else {}
    steps: List[Dict[str, Any]] = []
    markdown_lines = [
        "# Discovery Operational Runbook",
        "",
        f"**Session:** {ts}",
        f"**Persona:** {persona_key.title()}",
        f"**Readiness Score:** {_safe_int(selected.get('readiness_score', 0))}/100",
        ""
    ]

    if persona_key == "admin":
        actions = personas.get("admin", {}).get("actions", []) if isinstance(personas.get("admin", {}), dict) else []
        for idx, action in enumerate(actions[:8], 1):
            title = action.get("title", f"Admin Action {idx}") if isinstance(action, dict) else f"Admin Action {idx}"
            why = action.get("why", "") if isinstance(action, dict) else ""
            effort = action.get("effort", "unknown") if isinstance(action, dict) else "unknown"
            next_step = action.get("next_step", "") if isinstance(action, dict) else ""
            steps.append({
                "step": idx,
                "title": title,
                "owner": "Splunk Admin",
                "effort": effort,
                "details": why,
                "next_step": next_step
            })
            markdown_lines.extend([
                f"## {idx}. {title}",
                f"- Owner: Splunk Admin",
                f"- Effort: {effort}",
                f"- Why: {why}",
                f"- Next Step: {next_step}",
                ""
            ])

    elif persona_key == "analyst":
        tracks = personas.get("analyst", {}).get("hypotheses", []) if isinstance(personas.get("analyst", {}), dict) else []
        for idx, track in enumerate(tracks[:8], 1):
            title = track.get("title", f"Investigation Track {idx}") if isinstance(track, dict) else f"Investigation Track {idx}"
            question = track.get("question", "") if isinstance(track, dict) else ""
            metric = track.get("success_metric", "") if isinstance(track, dict) else ""
            sources = track.get("data_sources", []) if isinstance(track, dict) else []
            source_text = ", ".join([str(s) for s in sources[:6]]) if isinstance(sources, list) else ""
            steps.append({
                "step": idx,
                "title": title,
                "owner": "Security Analyst",
                "effort": "medium",
                "details": question,
                "next_step": f"Validate with metric: {metric}"
            })
            markdown_lines.extend([
                f"## {idx}. {title}",
                f"- Owner: Security Analyst",
                f"- Question: {question}",
                f"- Success Metric: {metric}",
                f"- Data Sources: {source_text}",
                ""
            ])

    else:
        executive = personas.get("executive", {}) if isinstance(personas.get("executive", {}), dict) else {}
        headline = executive.get("headline", "")
        themes = executive.get("business_value_themes", []) if isinstance(executive.get("business_value_themes", []), list) else []
        focus_items = executive.get("next_90_day_focus", []) if isinstance(executive.get("next_90_day_focus", []), list) else []

        for idx, item in enumerate(focus_items[:8], 1):
            steps.append({
                "step": idx,
                "title": f"90-Day Focus {idx}",
                "owner": "Leadership",
                "effort": "strategic",
                "details": item,
                "next_step": "Assign sponsor and KPI"
            })

        markdown_lines.extend([
            "## Executive Headline",
            f"{headline}",
            "",
            "## Business Value Themes"
        ])
        for theme in themes[:6]:
            markdown_lines.append(f"- {theme}")
        markdown_lines.extend(["", "## Next 90 Days"])
        for item in focus_items[:8]:
            markdown_lines.append(f"- {item}")
        markdown_lines.append("")

    filename = f"runbook_{persona_key}_{ts}.md"
    return {
        "has_data": True,
        "session": selected,
        "persona": persona_key,
        "title": f"{persona_key.title()} Operational Runbook",
        "filename": filename,
        "markdown": "\n".join(markdown_lines),
        "steps": steps,
        "sessions": sessions[:20]
    }


def build_discovery_dashboard_payload() -> Dict[str, Any]:
    """Build dashboard payload from persisted discovery sessions with simple trend analysis."""
    sessions = load_discovery_sessions()
    latest = sessions[0] if sessions else None
    previous = sessions[1] if len(sessions) > 1 else None

    latest = hydrate_discovery_session(latest)
    previous = hydrate_discovery_session(previous)

    if not latest:
        return {
            "has_data": False,
            "message": "No discovery sessions available yet.",
            "sessions": []
        }

    def _delta(path: List[str]) -> int:
        if not previous:
            return 0
        current = latest
        prior = previous
        for key in path:
            current = current.get(key, {}) if isinstance(current, dict) else {}
            prior = prior.get(key, {}) if isinstance(prior, dict) else {}
        return _safe_int(current) - _safe_int(prior)

    kpis = {
        "readiness_score": latest.get("readiness_score", 0),
        "total_indexes": _safe_int(latest.get("overview", {}).get("total_indexes", 0)),
        "total_sourcetypes": _safe_int(latest.get("overview", {}).get("total_sourcetypes", 0)),
        "recommendation_count": _safe_int(latest.get("stats", {}).get("recommendation_count", 0)),
        "tool_count": _safe_int(latest.get("mcp_capabilities", {}).get("tool_count", 0))
    }

    trends = {
        "indexes_delta": _delta(["overview", "total_indexes"]),
        "sourcetypes_delta": _delta(["overview", "total_sourcetypes"]),
        "recommendations_delta": _delta(["stats", "recommendation_count"]),
        "readiness_delta": _delta(["readiness_score"])
    }

    return {
        "has_data": True,
        "latest": latest,
        "previous": previous,
        "kpis": kpis,
        "trends": trends,
        "sessions": sessions[:20]
    }


def load_latest_v2_blueprint() -> Optional[Dict[str, Any]]:
    """Load latest v2 intelligence blueprint artifact if available."""
    output_dir = Path("output")
    if not output_dir.exists():
        return None

    candidates = sorted(output_dir.glob("v2_intelligence_blueprint_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        return None

    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            payload["_artifact"] = {
                "name": latest.name,
                "modified": datetime.fromtimestamp(latest.stat().st_mtime).isoformat(),
                "size": latest.stat().st_size
            }
            return payload
    except Exception:
        return None
    return None


def build_v2_artifact_catalog() -> Dict[str, Any]:
    """Build catalog for V2 artifacts for the Artifacts workspace tab."""
    output_dir = Path("output")
    if not output_dir.exists():
        return {"has_data": False, "artifacts": []}

    artifacts = [_build_artifact_metadata(file_path) for file_path in _iter_catalog_artifact_paths()]

    return {
        "has_data": len(artifacts) > 0,
        "artifacts": artifacts,
        "count": len(artifacts)
    }


async def discover_mcp_tools(config, force_refresh: bool = False) -> set:
    """Discover and cache available MCP tools from the connected Splunk MCP server."""
    cache_ttl_seconds = 60
    now = time.time()
    current_url = getattr(config.mcp, "url", None)

    if (
        not force_refresh
        and _cached_mcp_tools["tools"]
        and _cached_mcp_tools["url"] == current_url
        and (now - _cached_mcp_tools["timestamp"]) < cache_ttl_seconds
    ):
        return _cached_mcp_tools["tools"]

    if not current_url:
        return _cached_mcp_tools["tools"]

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    if config.mcp.token:
        headers["Authorization"] = f"Bearer {config.mcp.token}"

    verify_ssl = config.mcp.verify_ssl
    ca_bundle = getattr(config.mcp, 'ca_bundle_path', None)
    if ca_bundle and verify_ssl:
        ssl_verify = ca_bundle
    elif verify_ssl:
        ssl_verify = True
    else:
        ssl_verify = False

    payload = {
        "method": "tools/list",
        "params": {}
    }

    discovered = set()

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=15.0) as client:
            response = await client.post(current_url, json=payload, headers=headers)
            if response.status_code != 200:
                return _cached_mcp_tools["tools"]

            data = response.json()
            result_obj = data.get("result", {}) if isinstance(data, dict) else {}

            if isinstance(result_obj.get("tools"), list):
                for tool in result_obj.get("tools", []):
                    if isinstance(tool, dict) and tool.get("name"):
                        discovered.add(tool["name"])

            content = result_obj.get("content", []) if isinstance(result_obj, dict) else []
            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    text = item.get("text")
                    if not isinstance(text, str) or not text.strip():
                        continue
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        continue

                    if isinstance(parsed, dict) and isinstance(parsed.get("tools"), list):
                        for tool in parsed["tools"]:
                            if isinstance(tool, dict) and tool.get("name"):
                                discovered.add(tool["name"])

        if discovered:
            _cached_mcp_tools["url"] = current_url
            _cached_mcp_tools["tools"] = discovered
            _cached_mcp_tools["timestamp"] = now

        return _cached_mcp_tools["tools"]
    except Exception as e:
        debug_log(f"MCP tool discovery failed: {str(e)}", "warning")
        return _cached_mcp_tools["tools"]

def debug_log(message: str, category: str = "info", data: Any = None):
    """
    Log debug message to terminal and optionally to debug WebSocket clients.
    Automatically sanitizes secrets before sending to clients.
    """
    config = config_manager.get()
    
    # Always print to terminal
    print(message)
    
    # If debug mode enabled, also send to WebSocket clients
    if config.server.debug_mode and debug_connections:
        # Sanitize sensitive data
        sanitized_data = None
        if data:
            sanitized_data = _sanitize_debug_data(data)
        
        debug_msg = {
            "type": "debug",
            "category": category,  # info, warning, error, query, response
            "message": _sanitize_secrets(message),
            "data": sanitized_data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Queue for WebSocket send
        try:
            debug_log_queue.put_nowait(debug_msg)
        except:
            pass  # Queue full, skip this message


def _sanitize_secrets(text: str) -> str:
    """Remove or mask sensitive information from text."""
    import re
    
    # Mask API keys (keep first/last 4 chars)
    text = re.sub(r'(api[_-]?key["\s:=]+)([a-zA-Z0-9\-_]{8,})', 
                  lambda m: f"{m.group(1)}{m.group(2)[:4]}***{m.group(2)[-4:]}", 
                  text, flags=re.IGNORECASE)
    
    # Mask tokens
    text = re.sub(r'(token["\s:=]+)([a-zA-Z0-9\-_]{16,})', 
                  lambda m: f"{m.group(1)}{m.group(2)[:4]}***{m.group(2)[-4:]}", 
                  text, flags=re.IGNORECASE)
    
    # Mask passwords
    text = re.sub(r'(password["\s:=]+)([^\s\'"]+)', 
                  lambda m: f"{m.group(1)}***REDACTED***", 
                  text, flags=re.IGNORECASE)
    
    return text


def _sanitize_debug_data(data: Any) -> Any:
    """Recursively sanitize sensitive data from objects."""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Skip or mask sensitive keys
            if any(secret in key.lower() for secret in ['api_key', 'apikey', 'token', 'password', 'secret', 'credential']):
                if isinstance(value, str) and len(value) > 8:
                    sanitized[key] = f"{value[:4]}***{value[-4:]}"
                else:
                    sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = _sanitize_debug_data(value)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_debug_data(item) for item in data]
    elif isinstance(data, str):
        return _sanitize_secrets(data)
    else:
        return data


# Security: Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


# Security: Input validation helpers
def sanitize_filename(filename: str) -> str:
    """Validate and sanitize filename to prevent path traversal."""
    # Get just the filename, removing any directory components
    filename = Path(filename).name
    
    # Whitelist alphanumeric, dash, underscore, dot
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename format")
    
    # Validate file extension
    allowed_extensions = ['.md', '.json', '.txt', '.png', '.jpg', '.jpeg', '.webp', '.gif']
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(status_code=400, detail="Invalid file extension")
    
    return filename


def validate_session_id(session_id: str) -> str:
    """Validate session ID format to prevent injection."""
    # Format: YYYYMMDD_HHMMSS (e.g., 20251027_120653)
    if not re.match(r'^\d{8}_\d{6}$', session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    return session_id


class WebSocketDisplayManager:
    """Display manager that sends updates via WebSocket."""
    
    def __init__(self):
        self.verbose = True
        self.start_time = datetime.now()
    
    async def send_to_clients(self, message_type: str, data: Dict[str, Any]):
        """Send message to all connected WebSocket clients."""
        message = {
            "type": message_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        
        disconnected = []
        for connection in active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            if conn in active_connections:
                active_connections.remove(conn)
    
    async def show_banner(self):
        await self.send_to_clients("banner", {
            "title": "Splunk MCP Use Case Discovery Tool",
            "subtitle": "Intelligent Environment Analysis & Recommendation Engine",
            "start_time": self.start_time.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    def phase(self, title: str):
        asyncio.create_task(self.send_to_clients("phase", {"title": title}))
    
    def success(self, message: str):
        asyncio.create_task(self.send_to_clients("success", {"message": message}))
    
    def error(self, message: str):
        asyncio.create_task(self.send_to_clients("error", {"message": message}))
    
    def warning(self, message: str):
        asyncio.create_task(self.send_to_clients("warning", {"message": message}))
    
    def info(self, message: str):
        asyncio.create_task(self.send_to_clients("info", {"message": message}))
    
    def show_overview_summary(self, overview):
        asyncio.create_task(self.send_to_clients("overview", {
            "total_indexes": overview.total_indexes,
            "total_sourcetypes": overview.total_sourcetypes,
            "data_volume_24h": overview.data_volume_24h,
            "active_sources": overview.active_sources,
            "estimated_time": overview.estimated_time,
            "notable_patterns": overview.notable_patterns
        }))
    
    def show_classification_summary(self, classifications: Dict[str, Any]):
        asyncio.create_task(self.send_to_clients("classification", classifications))
    
    def show_recommendations_preview(self, recommendations: List):
        asyncio.create_task(self.send_to_clients("recommendations", {
            "count": len(recommendations),
            "top_recommendations": recommendations[:5]  # Show top 5
        }))
    
    def show_suggested_use_cases_preview(self, use_cases: List):
        asyncio.create_task(self.send_to_clients("use_cases", {
            "count": len(use_cases),
            "preview": use_cases[:3]  # Show top 3
        }))
    
    def show_final_summary(self, report_paths: List[str]):
        elapsed = datetime.now() - self.start_time
        asyncio.create_task(self.send_to_clients("completion", {
            "duration": str(elapsed),
            "report_paths": report_paths
        }))
    
    async def handle_rate_limit_callback(self, event_type: str, data: Dict[str, Any]):
        await self.send_to_clients("rate_limit", {
            "event": event_type,
            "details": data
        })


class ProgressTracker:
    """Enhanced progress tracking with WebSocket updates."""
    
    def __init__(self):
        self.total_steps = 0
        self.current_step = 0
        self.current_phase = ""
        self.current_description = ""
        self.start_time = None
    
    def set_total_steps(self, total: int):
        self.total_steps = total
        self.start_time = datetime.now()
    
    async def update_progress(self, step: int, description: str = ""):
        self.current_step = step
        self.current_description = description
        
        if self.total_steps > 0:
            percentage = (step / self.total_steps) * 100
            elapsed = datetime.now() - self.start_time if self.start_time else None
            
            # Calculate ETA
            eta_seconds = None
            if elapsed and step > 0:
                avg_time_per_step = elapsed.total_seconds() / step
                remaining_steps = self.total_steps - step
                eta_seconds = remaining_steps * avg_time_per_step
            
            # Send WebSocket update
            for connection in active_connections:
                try:
                    await connection.send_text(json.dumps({
                        "type": "progress",
                        "data": {
                            "percentage": percentage,
                            "current_step": step,
                            "total_steps": self.total_steps,
                            "description": description,
                            "eta_seconds": eta_seconds
                        },
                        "timestamp": datetime.now().isoformat()
                    }))
                except:
                    pass


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


@app.websocket("/ws/debug")
async def debug_websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for debug log streaming (only if debug_mode enabled)."""
    config = config_manager.get()
    
    if not config.server.debug_mode:
        await websocket.close(code=1008, reason="Debug mode not enabled")
        return
    
    await websocket.accept()
    debug_connections.append(websocket)
    
    # Send initial connection message
    await websocket.send_json({
        "type": "connected",
        "message": "🐛 Debug mode active - streaming logs in real-time",
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        while True:
            # Keep connection alive and handle incoming pings
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
            except asyncio.TimeoutError:
                # Check for queued debug messages
                try:
                    debug_msg = debug_log_queue.get_nowait()
                    await websocket.send_json(debug_msg)
                except asyncio.QueueEmpty:
                    pass
    except WebSocketDisconnect:
        if websocket in debug_connections:
            debug_connections.remove(websocket)


@app.post("/start-discovery")
async def start_discovery(background_tasks: BackgroundTasks):
    """Start the discovery process in the background."""
    global current_discovery_session
    
    if current_discovery_session and not current_discovery_session.done():
        return {"error": "Discovery already in progress"}
    
    # Start discovery task
    current_discovery_session = asyncio.create_task(run_discovery())
    
    return {"status": "Discovery started", "session_id": id(current_discovery_session)}


@app.post("/abort-discovery")
async def abort_discovery():
    """Abort the current discovery process."""
    global current_discovery_session
    
    if not current_discovery_session or current_discovery_session.done():
        return {"error": "No discovery in progress"}
    
    # Cancel the task
    current_discovery_session.cancel()
    
    # Notify via WebSocket
    message = {
        "type": "error",
        "data": {"message": "⚠️ Discovery aborted by user"},
        "timestamp": datetime.now().isoformat()
    }
    
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_text(json.dumps(message))
        except:
            disconnected.append(connection)
    
    # Remove disconnected clients
    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)
    
    return {"status": "Discovery aborted"}


async def run_discovery():
    """Run the complete discovery process with WebSocket updates."""
    display = None
    try:
        # Load configuration
        config = config_manager.get()
        
        # Initialize display manager with WebSocket support
        display = WebSocketDisplayManager()
        await display.show_banner()
        
        # Validate MCP configuration
        if not config.mcp.url:
            display.error("❌ MCP Server URL not configured. Please configure your Splunk MCP server in Settings.")
            raise Exception("MCP Server URL not configured")
        
        if not config.mcp.token:
            display.error("❌ MCP Server token not configured. Please configure your Splunk authentication token in Settings.")
            raise Exception("MCP Server token not configured")
        
        # Debug: Check if API key is loaded
        debug_log(f"Config loaded - provider: {config.llm.provider}, model: {config.llm.model}", "info")
        debug_log(f"API key present: {bool(config.llm.api_key)}, length: {len(config.llm.api_key) if config.llm.api_key else 0}", "info")

        available_mcp_tools = await discover_mcp_tools(config)
        if not available_mcp_tools:
            available_mcp_tools = {
                "splunk_run_query",
                "splunk_get_info",
                "splunk_get_indexes",
                "splunk_get_index_info",
                "splunk_get_metadata",
                "splunk_get_user_info",
                "splunk_get_knowledge_objects"
            }
        available_mcp_tools_sorted = sorted(list(available_mcp_tools))
        
        # Initialize LLM client (cached for performance)
        llm_client = get_or_create_llm_client(config)
        display.success("✅ LLM client initialized")
        
        # Initialize discovery engine
        discovery_engine = DiscoveryEngine(
            mcp_url=config.mcp.url,
            mcp_token=config.mcp.token,
            llm_client=llm_client,
            verify_ssl=config.mcp.verify_ssl,
            ca_bundle_path=config.mcp.ca_bundle_path
        )
        display.success("✅ Discovery engine initialized")
        
        # Initialize progress tracker
        progress = ProgressTracker()

        if DISCOVERY_PIPELINE_VERSION == "v2":
            display.phase("🚀 V2 Discovery Pipeline")
            v2_pipeline = DiscoveryV2Pipeline(discovery_engine)
            v2_result = await v2_pipeline.run(display, progress)

            overview = v2_result.get("overview")
            classifications = v2_result.get("classifications", {})
            recommendations = v2_result.get("recommendations", [])
            suggested_use_cases = v2_result.get("suggested_use_cases", [])
            report_paths = v2_result.get("report_paths", [])
            timestamp = v2_result.get("timestamp") or datetime.now().strftime("%Y%m%d_%H%M%S")
            discovery_step_count = _safe_int(v2_result.get("discovery_step_count", 0))

            readiness_score = compute_discovery_readiness_score(
                overview,
                recommendations if isinstance(recommendations, list) else [],
                suggested_use_cases if isinstance(suggested_use_cases, list) else [],
                {
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                }
            )
            persona_playbooks = build_persona_playbooks(
                overview,
                recommendations if isinstance(recommendations, list) else [],
                suggested_use_cases if isinstance(suggested_use_cases, list) else [],
                {
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                }
            )

            session_record = register_discovery_session(
                timestamp=timestamp,
                overview=overview,
                report_paths=report_paths,
                mcp_capabilities={
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                },
                classifications=classifications if isinstance(classifications, dict) else {},
                recommendations=recommendations if isinstance(recommendations, list) else [],
                suggested_use_cases=suggested_use_cases if isinstance(suggested_use_cases, list) else [],
                discovery_step_count=discovery_step_count,
                personas=persona_playbooks,
                readiness_score=readiness_score
            )

            display.success("✅ V2 discovery artifact bundle generated")
            display.show_final_summary(report_paths)

            return {
                "status": "success",
                "overview": overview.__dict__ if hasattr(overview, '__dict__') else overview,
                "classifications": classifications,
                "recommendations": recommendations,
                "suggested_use_cases": suggested_use_cases,
                "session": session_record,
                "readiness_score": readiness_score,
                "persona_playbooks": persona_playbooks,
                "mcp_capabilities": {
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                },
                "report_paths": report_paths,
                "timestamp": timestamp
            }
        
        # Phase 1: Quick Overview
        display.phase("🔍 Phase 1: Quick Architecture Overview")
        display.info("🔄 Getting initial environment overview...")
        
        overview = await discovery_engine.get_quick_overview()
        progress.set_total_steps(overview.estimated_discovery_steps)
        
        display.success("✅ Getting initial environment overview... - completed")
        display.show_overview_summary(overview)
        
        # Phase 2: Detailed Discovery
        display.phase("🕵️ Phase 2: Detailed Environment Discovery")
        
        step = 0
        async for result in discovery_engine.discover_environment():
            step += 1
            await progress.update_progress(step, result.description)
        
        # Phase 3: Classification
        display.phase("🏷️ Phase 3: Data Classification and Analysis")
        display.info("🔄 Classifying discovered data...")
        
        classifications = await discovery_engine.classify_data()
        display.success("✅ Classifying discovered data... - completed")
        display.show_classification_summary(classifications)
        
        # Phase 4: Recommendations
        display.phase("💡 Phase 4: Generating Use Case Recommendations")
        display.info("🔄 Generating intelligent recommendations...")
        
        recommendations = await discovery_engine.generate_recommendations()
        display.success("✅ Generating intelligent recommendations... - completed")
        display.show_recommendations_preview(recommendations)
        
        # Phase 5: Cross-functional Use Cases
        display.phase("💡 Phase 5: Generating Cross-Functional Use Case Suggestions")
        display.info("🔄 Analyzing data source combinations for creative use cases...")
        
        try:
            suggested_use_cases = await discovery_engine.generate_suggested_use_cases()
            display.success("✅ Analyzing data source combinations for creative use cases... - completed")
            display.show_suggested_use_cases_preview(suggested_use_cases)
        except Exception as e:
            display.error(f"❌ Suggested use case generation failed: {str(e)}")
            display.info("🔄 Continuing with available analysis...")
            suggested_use_cases = []
        
        # Phase 6: Export Reports
        display.phase("📝 Phase 6: Exporting Discovery Reports")
        display.info("🔄 Generating report files...")
        
        # Generate timestamp for this session
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        report_paths = []
        readiness_score = compute_discovery_readiness_score(
            overview,
            recommendations if isinstance(recommendations, list) else [],
            suggested_use_cases if isinstance(suggested_use_cases, list) else [],
            {
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            }
        )
        persona_playbooks = build_persona_playbooks(
            overview,
            recommendations if isinstance(recommendations, list) else [],
            suggested_use_cases if isinstance(suggested_use_cases, list) else [],
            {
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            }
        )
        
        # Export JSON data
        try:
            # Get raw discovery results for SPL generation
            discovery_results = discovery_engine.get_all_results()
            discovery_results_dict = [
                {
                    "step": r.step,
                    "description": r.description,
                    "data": r.data,
                    "interesting_findings": r.interesting_findings,
                    "timestamp": r.timestamp.isoformat() if hasattr(r.timestamp, 'isoformat') else str(r.timestamp)
                }
                for r in discovery_results
            ]
            
            json_export_path = output_dir / f"discovery_export_{timestamp}.json"
            with open(json_export_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "overview": overview.__dict__ if hasattr(overview, '__dict__') else overview,
                    "classifications": classifications,
                    "recommendations": recommendations,
                    "suggested_use_cases": suggested_use_cases,
                    "readiness_score": readiness_score,
                    "persona_playbooks": persona_playbooks,
                    "mcp_capabilities": {
                        "tool_count": len(available_mcp_tools_sorted),
                        "tools": available_mcp_tools_sorted
                    },
                    "discovery_results": discovery_results_dict,
                    "timestamp": timestamp
                }, f, indent=2, default=str)
            report_paths.append(str(json_export_path.name))
            display.info(f"   ✓ {json_export_path.name} (includes {len(discovery_results_dict)} discovery items)")
        except Exception as e:
            display.error(f"   ✗ Failed to export JSON: {str(e)}")
        
        # Export Executive Summary
        try:
            mcp_capability_path = output_dir / f"mcp_capabilities_{timestamp}.md"
            with open(mcp_capability_path, 'w', encoding='utf-8') as f:
                f.write(f"# MCP Capability Snapshot\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Discovered Tool Count:** {len(available_mcp_tools_sorted)}\n\n")
                f.write("## Available Tools\n\n")
                for tool_name in available_mcp_tools_sorted:
                    description = MCP_TOOL_DESCRIPTIONS.get(tool_name, "MCP tool available for Splunk operations.")
                    f.write(f"- **{tool_name}**: {description}\n")
            report_paths.append(str(mcp_capability_path.name))
            display.info(f"   ✓ {mcp_capability_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export MCP capabilities snapshot: {str(e)}")

        # Export persona playbooks for admins/analysts/executives
        try:
            persona_json_path = output_dir / f"persona_playbooks_{timestamp}.json"
            with open(persona_json_path, 'w', encoding='utf-8') as f:
                json.dump(persona_playbooks, f, indent=2, default=str)
            report_paths.append(str(persona_json_path.name))
            display.info(f"   ✓ {persona_json_path.name}")

            persona_md_path = output_dir / f"persona_playbooks_{timestamp}.md"
            with open(persona_md_path, 'w', encoding='utf-8') as f:
                f.write("# Persona Playbooks\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Readiness Score:** {readiness_score}/100\n\n")

                admin_actions = persona_playbooks.get("admin", {}).get("actions", [])
                analyst_hypotheses = persona_playbooks.get("analyst", {}).get("hypotheses", [])
                executive = persona_playbooks.get("executive", {})

                f.write("## Admin Action Queue\n\n")
                for idx, action in enumerate(admin_actions[:6], 1):
                    f.write(f"{idx}. **{action.get('title', 'Action')}**\n")
                    f.write(f"   - Why: {action.get('why', '')}\n")
                    f.write(f"   - Effort: {action.get('effort', 'unknown')}\n")
                    f.write(f"   - Next Step: {action.get('next_step', '')}\n\n")

                f.write("## Analyst Investigation Tracks\n\n")
                for idx, hypothesis in enumerate(analyst_hypotheses[:6], 1):
                    f.write(f"{idx}. **{hypothesis.get('title', 'Track')}**\n")
                    f.write(f"   - Question: {hypothesis.get('question', '')}\n")
                    f.write(f"   - Metric: {hypothesis.get('success_metric', '')}\n")
                    data_sources = hypothesis.get('data_sources', [])
                    if isinstance(data_sources, list) and data_sources:
                        f.write(f"   - Data Sources: {', '.join(str(s) for s in data_sources[:6])}\n")
                    f.write("\n")

                f.write("## Executive Brief\n\n")
                f.write(f"- **Readiness Score:** {executive.get('platform_readiness_score', readiness_score)}/100\n")
                f.write(f"- **Headline:** {executive.get('headline', '')}\n")
                for theme in executive.get('business_value_themes', []):
                    f.write(f"  - Value Theme: {theme}\n")
                f.write("\n")
                f.write("### Next 90 Days\n\n")
                for item in executive.get('next_90_day_focus', []):
                    f.write(f"- {item}\n")
            report_paths.append(str(persona_md_path.name))
            display.info(f"   ✓ {persona_md_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export persona playbooks: {str(e)}")

        # Export Executive Summary
        try:
            exec_summary_path = output_dir / f"executive_summary_{timestamp}.md"
            with open(exec_summary_path, 'w', encoding='utf-8') as f:
                f.write(f"# Splunk Environment Discovery - Executive Summary\n\n")
                f.write(f"**Discovery Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                f.write(f"## MCP Capability Snapshot\n\n")
                f.write(f"- **Discovered Tools:** {len(available_mcp_tools_sorted)}\n")
                for tool_name in available_mcp_tools_sorted:
                    f.write(f"  - `{tool_name}`\n")
                f.write(f"\n")
                
                # Environment Overview
                f.write(f"## Environment Overview\n\n")
                if hasattr(overview, 'total_indexes'):
                    f.write(f"- **Total Indexes:** {overview.total_indexes}\n")
                    f.write(f"- **Total Source Types:** {overview.total_sourcetypes}\n")
                    f.write(f"- **Total Hosts:** {overview.total_hosts}\n")
                    f.write(f"- **Total Sources:** {overview.total_sources}\n")
                    if overview.data_volume_24h:
                        f.write(f"- **24h Data Volume:** {overview.data_volume_24h}\n")
                    if overview.splunk_version:
                        f.write(f"- **Splunk Version:** {overview.splunk_version} (Build: {overview.splunk_build})\n")
                    if overview.license_state:
                        f.write(f"- **License State:** {overview.license_state}\n")
                    if overview.server_roles:
                        f.write(f"- **Server Roles:** {', '.join(overview.server_roles)}\n")
                    f.write(f"\n")
                
                # Top Priority Recommendations
                f.write(f"## Top Priority Recommendations\n\n")
                high_priority = [r for r in recommendations if isinstance(r, dict) and r.get('priority') == 'high'][:5]
                if high_priority:
                    for idx, rec in enumerate(high_priority, 1):
                        f.write(f"### {idx}. {rec.get('title', 'Recommendation')}\n\n")
                        f.write(f"**Priority:** {rec.get('priority', 'N/A')} | ")
                        f.write(f"**Category:** {rec.get('category', 'N/A')} | ")
                        f.write(f"**Complexity:** {rec.get('complexity', 'N/A')}\n\n")
                        f.write(f"{rec.get('description', '')}\n\n")
                else:
                    f.write("_No high-priority recommendations identified._\n\n")
                
                # Data Classification Summary
                f.write(f"## Data Classification Summary\n\n")
                if isinstance(classifications, dict):
                    for category, items in classifications.items():
                        if items and len(items) > 0:
                            f.write(f"**{category.replace('_', ' ').title()}:** {len(items)} items\n")
                    f.write(f"\n")
                
                # Cross-Functional Use Cases
                if suggested_use_cases:
                    f.write(f"## Recommended Cross-Functional Use Cases\n\n")
                    for idx, use_case in enumerate(suggested_use_cases[:3], 1):
                        if isinstance(use_case, dict):
                            f.write(f"### {idx}. {use_case.get('title', 'Use Case')}\n\n")
                            f.write(f"**Category:** {use_case.get('category', 'N/A')} | ")
                            f.write(f"**Complexity:** {use_case.get('complexity', 'N/A')}\n\n")
                            f.write(f"{use_case.get('description', '')}\n\n")
                            if use_case.get('data_sources'):
                                f.write(f"**Data Sources:** {', '.join(use_case['data_sources'])}\n\n")
                
                # Discovery Statistics
                discovery_results = discovery_engine.get_all_results()
                f.write(f"## Discovery Statistics\n\n")
                f.write(f"- **Total Discovery Steps:** {len(discovery_results)}\n")
                f.write(f"- **Analysis Time:** {overview.estimated_time if hasattr(overview, 'estimated_time') else 'N/A'}\n")
                f.write(f"- **Notable Patterns:** {len(overview.notable_patterns) if hasattr(overview, 'notable_patterns') else 0}\n\n")
                
            report_paths.append(str(exec_summary_path.name))
            display.info(f"   ✓ {exec_summary_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export executive summary: {str(e)}")
        
        # Export Detailed Discovery
        try:
            detailed_path = output_dir / f"detailed_discovery_{timestamp}.md"
            with open(detailed_path, 'w', encoding='utf-8') as f:
                f.write(f"# Detailed Discovery Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Get discovery results
                discovery_results = discovery_engine.get_all_results()
                
                f.write(f"## Discovery Overview\n\n")
                f.write(f"Total discovery steps completed: {len(discovery_results)}\n\n")
                
                # Write each discovery step
                for result in discovery_results:
                    f.write(f"### Step {result.step}: {result.description}\n\n")
                    f.write(f"**Timestamp:** {result.timestamp}\n\n")
                    
                    # Interesting findings
                    if result.interesting_findings:
                        f.write(f"**Key Findings:**\n")
                        for finding in result.interesting_findings:
                            f.write(f"- {finding}\n")
                        f.write(f"\n")
                    
                    # Data details (formatted)
                    if result.data:
                        f.write(f"**Data Details:**\n\n")
                        if isinstance(result.data, dict):
                            for key, value in result.data.items():
                                if isinstance(value, (list, dict)):
                                    f.write(f"- **{key}:** {len(value)} items\n")
                                else:
                                    f.write(f"- **{key}:** {value}\n")
                        f.write(f"\n")
                    
                    f.write(f"---\n\n")
                
            report_paths.append(str(detailed_path.name))
            display.info(f"   ✓ {detailed_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export detailed discovery: {str(e)}")
        
        # Export Data Classification
        try:
            classification_path = output_dir / f"data_classification_{timestamp}.md"
            with open(classification_path, 'w', encoding='utf-8') as f:
                f.write(f"# Data Classification Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                if isinstance(classifications, dict):
                    for category, items in classifications.items():
                        f.write(f"## {category.replace('_', ' ').title()}\n\n")
                        if items and len(items) > 0:
                            f.write(f"**Total Items:** {len(items)}\n\n")
                            for item in items:
                                if isinstance(item, dict):
                                    f.write(f"### {item.get('name', item.get('title', 'Item'))}\n\n")
                                    for key, value in item.items():
                                        if key not in ['name', 'title'] and value:
                                            f.write(f"- **{key.replace('_', ' ').title()}:** {value}\n")
                                    f.write(f"\n")
                                elif isinstance(item, str):
                                    f.write(f"- {item}\n")
                            f.write(f"\n")
                        else:
                            f.write("_No items classified in this category._\n\n")
                else:
                    f.write("_Classification data not available._\n\n")
                    
            report_paths.append(str(classification_path.name))
            display.info(f"   ✓ {classification_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export classifications: {str(e)}")
        
        # Export Recommendations
        try:
            recommendations_path = output_dir / f"recommendations_{timestamp}.md"
            with open(recommendations_path, 'w', encoding='utf-8') as f:
                f.write(f"# Recommendations Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for idx, rec in enumerate(recommendations[:10], 1):
                    if isinstance(rec, dict):
                        f.write(f"## {idx}. {rec.get('title', 'Recommendation')}\n\n")
                        f.write(f"**Priority:** {rec.get('priority', 'N/A')}\n\n")
                        f.write(f"{rec.get('description', '')}\n\n")
            report_paths.append(str(recommendations_path.name))
            display.info(f"   ✓ {recommendations_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export recommendations: {str(e)}")
        
        # Export Suggested Use Cases
        try:
            use_cases_path = output_dir / f"suggested_use_cases_{timestamp}.md"
            with open(use_cases_path, 'w', encoding='utf-8') as f:
                f.write(f"# Suggested Use Cases\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for idx, uc in enumerate(suggested_use_cases[:10], 1):
                    if isinstance(uc, dict):
                        f.write(f"## {idx}. {uc.get('title', 'Use Case')}\n\n")
                        f.write(f"{uc.get('description', '')}\n\n")
            report_paths.append(str(use_cases_path.name))
            display.info(f"   ✓ {use_cases_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export use cases: {str(e)}")
        
        # Export Implementation Guide
        try:
            impl_guide_path = output_dir / f"implementation_guide_{timestamp}.md"
            with open(impl_guide_path, 'w', encoding='utf-8') as f:
                f.write(f"# Implementation Guide\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"## Quick Start\n\n")
                f.write(f"This guide provides implementation steps for the recommended use cases.\n\n")
                f.write(f"## Priority Recommendations\n\n")
                for idx, rec in enumerate([r for r in recommendations if isinstance(r, dict) and r.get('priority') == 'high'][:5], 1):
                    f.write(f"### {idx}. {rec.get('title', 'Recommendation')}\n\n")
                    f.write(f"{rec.get('description', '')}\n\n")
            report_paths.append(str(impl_guide_path.name))
            display.info(f"   ✓ {impl_guide_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export implementation guide: {str(e)}")
        
        display.success(f"✅ Generated {len(report_paths)} report files")

        discovery_results = discovery_engine.get_all_results()
        session_record = register_discovery_session(
            timestamp=timestamp,
            overview=overview,
            report_paths=report_paths,
            mcp_capabilities={
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            },
            classifications=classifications if isinstance(classifications, dict) else {},
            recommendations=recommendations if isinstance(recommendations, list) else [],
            suggested_use_cases=suggested_use_cases if isinstance(suggested_use_cases, list) else [],
            discovery_step_count=len(discovery_results),
            personas=persona_playbooks,
            readiness_score=readiness_score
        )
        
        # Phase 7: Complete Discovery
        display.phase("✅ Discovery Complete")
        display.success("✅ All discovery phases completed successfully")
        
        # Send completion message to frontend
        await display.send_to_clients("completion", {
            "message": "Discovery completed successfully",
            "report_count": len(report_paths),
            "timestamp": timestamp
        })
        
        # Return completion status
        return {
            "status": "completed",
            "overview": overview,
            "classifications": classifications,
            "recommendations": recommendations,
            "suggested_use_cases": suggested_use_cases,
            "session": session_record,
            "readiness_score": readiness_score,
            "persona_playbooks": persona_playbooks,
            "mcp_capabilities": {
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            },
            "report_paths": report_paths,
            "timestamp": timestamp
        }
        
    except asyncio.CancelledError:
        # User aborted the discovery
        print("Discovery cancelled by user")
        if display:
            await display.send_to_clients("warning", {
                "message": "⚠️ Discovery aborted by user",
                "type": "user_abort"
            })
        raise  # Re-raise to properly cancel the task
    
    except Exception as e:
        import traceback
        error_message = f"Discovery failed: {str(e)}"
        traceback_str = traceback.format_exc()
        print(f"ERROR in run_discovery: {error_message}")
        print(f"Traceback: {traceback_str}")
        
        if display:
            await display.send_to_clients("error", {
                "message": error_message,
                "type": "fatal_error"
            })
        else:
            # Fallback if display is not initialized
            for connection in active_connections:
                try:
                    await connection.send_json({
                        "type": "error",
                        "data": {"message": error_message}
                    })
                except:
                    pass
        return {"status": "error", "message": str(e)}


@app.get("/reports")
async def list_reports():
    """Get list of available V2 reports only."""
    output_dir = Path("output")
    if not output_dir.exists():
        return {"reports": [], "sessions": []}
    
    reports = [_build_artifact_metadata(file_path) for file_path in _iter_catalog_artifact_paths()]
    
    sessions = load_discovery_sessions()
    return {
        "reports": sorted(reports, key=lambda x: x["modified"], reverse=True),
        "sessions": sessions
    }


@app.get("/api/discovery/sessions")
async def get_discovery_sessions():
    """Return persisted discovery sessions for history UI and retrieval."""
    sessions = load_discovery_sessions()
    return {
        "sessions": sessions,
        "count": len(sessions)
    }


@app.get("/api/discovery/sessions/{timestamp}")
async def get_discovery_session(timestamp: str):
    """Return a specific discovery session and resolved report metadata."""
    sessions = load_discovery_sessions()
    session = next((s for s in sessions if s.get("timestamp") == timestamp), None)
    if not session:
        raise HTTPException(status_code=404, detail="Discovery session not found")

    files = []
    for report_name in session.get("report_paths", []):
        try:
            report_path = _resolve_output_artifact_path(report_name)
        except HTTPException:
            report_path = None
        files.append({
            "name": report_name,
            "exists": report_path.exists() if report_path else False,
            "size": report_path.stat().st_size if report_path and report_path.exists() else 0,
            "modified": datetime.fromtimestamp(report_path.stat().st_mtime).isoformat() if report_path and report_path.exists() else None,
            "type": report_path.suffix[1:].lower() if report_path and report_path.suffix else "unknown",
            "artifact_kind": "infographic" if report_name.startswith(SUMMARY_INFOGRAPHIC_PREFIX) else "report",
        })

    return {
        "session": session,
        "files": files
    }


@app.get("/api/discovery/dashboard")
async def get_discovery_dashboard():
    """Return latest discovery intelligence dashboard payload for UI hub."""
    return build_discovery_dashboard_payload()


@app.get("/api/v2/intelligence")
async def get_v2_intelligence():
    """Return latest V2 intelligence blueprint for V2 workspace UI."""
    payload = load_latest_v2_blueprint()
    if not payload:
        return {"has_data": False, "message": "No V2 intelligence blueprint found."}
    return {
        "has_data": True,
        "blueprint": payload,
        "artifact": payload.get("_artifact", {})
    }


@app.get("/api/v2/artifacts")
async def get_v2_artifacts():
    """Return V2 artifact catalog for artifact workspace view."""
    return build_v2_artifact_catalog()


@app.get("/api/discovery/compare")
async def get_discovery_compare(current: Optional[str] = None, baseline: Optional[str] = None):
    """Return comparative metrics between two discovery sessions."""
    return build_discovery_compare_payload(current, baseline)


@app.get("/api/discovery/runbook")
async def get_discovery_runbook(timestamp: Optional[str] = None, persona: str = "admin"):
    """Return persona-scoped operational runbook for a selected discovery session."""
    return build_session_runbook_payload(timestamp, persona)


@app.get("/api/discovery/results")
async def get_discovery_results():
    """
    Discovery results summary endpoint for latest session.
    """
    sessions = load_discovery_sessions()
    latest = sessions[0] if sessions else None
    return {
        "message": "V2 discovery sessions are persisted and available via /api/discovery/sessions.",
        "reports_endpoint": "/reports",
        "sessions_endpoint": "/api/discovery/sessions",
        "latest_session": latest
    }


@app.get("/reports/{filename}")
async def get_report(filename: str):
    """Get a specific report file with security validation."""
    try:
        file_path = _resolve_output_artifact_path(filename)
        
        if file_path.suffix.lower() == ".json":
            with open(file_path, 'r', encoding='utf-8') as f:
                content = json.load(f)
            return {"content": content, "type": "json"}
        if file_path.suffix.lower() in IMAGE_ARTIFACT_EXTENSIONS:
            image_format = 'jpeg' if file_path.suffix.lower() == '.jpg' else file_path.suffix[1:].lower()
            return {
                "type": "image",
                "mime_type": f"image/{image_format}",
                "content_base64": base64.b64encode(file_path.read_bytes()).decode('ascii'),
            }
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return {"content": content, "type": "text"}
    except HTTPException:
        raise
    except Exception as e:
        # Security: Don't leak file system details
        raise HTTPException(status_code=500, detail="Failed to read report")


@app.get("/connection-info")
async def get_connection_info():
    """Get current LLM and MCP server connection information (DT4SMS version)."""
    try:
        config = config_manager.get()
        
        # Get LLM info (no sensitive data)
        llm_provider = normalize_provider_name(config.llm.provider)
        
        # Determine endpoint display based on provider
        if llm_provider == "openai":
            llm_endpoint = "OpenAI API (api.openai.com)"
        elif llm_provider == "anthropic":
            llm_endpoint = config.llm.endpoint_url or "Anthropic API (api.anthropic.com)"
        elif llm_provider == "gemini":
            llm_endpoint = config.llm.endpoint_url or "Gemini API (generativelanguage.googleapis.com)"
        elif llm_provider == "azure":
            llm_endpoint = config.llm.endpoint_url or "Azure OpenAI endpoint"
        elif config.llm.endpoint_url:
            llm_endpoint = config.llm.endpoint_url
        else:
            llm_endpoint = f"{llm_provider} API"
        
        llm_info = {
            "provider": llm_provider.upper(),
            "model": config.llm.model,
            "endpoint": llm_endpoint
        }
        
        # Get MCP server info (no sensitive data)
        mcp_info = {
            "endpoint": config.mcp.url
        }
        
        return {
            "llm": llm_info,
            "mcp": mcp_info,
            "status": "connected"
        }
    except Exception as e:
        print(f"Error loading connection info: {e}")
        import traceback
        traceback.print_exc()
        return {
            "llm": {"provider": "ERROR", "model": "Check logs", "endpoint": str(e)},
            "mcp": {"endpoint": "Error loading config"},
            "status": "error"
        }

# DT4SMS: Configuration API Endpoints and Models
class MCPSettings(BaseModel):
    url: str
    token: Optional[str] = None
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None

class LLMSettings(BaseModel):
    provider: str
    api_key: Optional[str] = None
    model: str
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7

class ServerSettings(BaseModel):
    port: int
    host: str
    cors_origins: List[str]
    trusted_hosts: List[str]
    debug_mode: Optional[bool] = False

class ConfigUpdate(BaseModel):
    mcp: Optional[MCPSettings] = None
    llm: Optional[LLMSettings] = None
    server: Optional[ServerSettings] = None


class CapabilityConfigUpdate(BaseModel):
    config: Dict[str, Any]


class CapabilityDeeplinkBuildRequest(BaseModel):
    query: str
    earliest: Optional[str] = None
    latest: Optional[str] = None
    app: Optional[str] = None
    link_type: str = "search"


class CapabilityExportBuildRequest(BaseModel):
    timestamp: Optional[str] = None
    persona: str = "admin"
    artifact_names: List[str] = []
    title: Optional[str] = None
    runbook_markdown: Optional[str] = None
    runbook_filename: Optional[str] = None


class RAGKnowledgeAssetImportRequest(BaseModel):
    title: str
    content: str
    asset_type: str = "reference_document"
    source_label: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []


class RAGContextPreviewRequest(BaseModel):
    query: str
    limit: int = 4


class SummaryInfographicRequest(BaseModel):
    timestamp: str
    summary_data: Dict[str, Any] = {}


def _parse_knowledge_asset_tags(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in re.split(r"[,\n]", str(value or "")) if item.strip()]


def normalize_openai_api_base_url(endpoint_url: Optional[str]) -> str:
    """Normalize an OpenAI endpoint to a reusable API base path."""
    normalized_base = (endpoint_url or "https://api.openai.com/v1").rstrip("/")
    for suffix in ["/chat/completions", "/responses", "/models", "/images/generations"]:
        if normalized_base.endswith(suffix):
            normalized_base = normalized_base[:-len(suffix)]
    return normalized_base


def build_openai_api_url(endpoint_url: Optional[str], path: str) -> str:
    """Build a full OpenAI REST URL while tolerating base or full-path config values."""
    normalized_path = "/" + str(path or "").lstrip("/")
    base_url = normalize_openai_api_base_url(endpoint_url)
    if base_url.endswith("/v1"):
        return f"{base_url}{normalized_path}"
    return f"{base_url}/v1{normalized_path}"


def openai_model_ids_include(model_ids: Any, target_model: str) -> bool:
    """Return True when the target model ID exists in an OpenAI models payload."""
    target = str(target_model or "").strip().lower()
    if not target:
        return False

    for model_id in model_ids or []:
        if isinstance(model_id, str) and model_id.strip().lower() == target:
            return True
    return False


def _compact_summary_entries(items: Any, limit: int, keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
    compact_items: List[Dict[str, Any]] = []
    if not isinstance(items, list):
        return compact_items

    for item in items:
        if not isinstance(item, dict):
            continue
        compact_item: Dict[str, Any] = {}
        for key in keys:
            value = item.get(key)
            if value in (None, "", [], {}):
                continue
            compact_item[key] = value
        if compact_item:
            compact_items.append(compact_item)
        if len(compact_items) >= limit:
            break
    return compact_items


def truncate_prompt_text(value: str, max_chars: int, suffix: str = "\n... [truncated for API safety]") -> str:
    """Trim prompt fragments to a safe size while leaving a visible truncation marker."""
    text = str(value or "")
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= len(suffix):
        return text[:max_chars]
    return text[: max_chars - len(suffix)].rstrip() + suffix


def build_summary_infographic_brief(timestamp: str, summary_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Create a compact, image-oriented brief from the full summary payload."""
    payload = summary_data if isinstance(summary_data, dict) else {}
    v2_context = payload.get("v2_context") if isinstance(payload.get("v2_context"), dict) else {}
    context_explorer = payload.get("context_explorer") if isinstance(payload.get("context_explorer"), dict) else {}
    context_anchors = context_explorer.get("anchors") if isinstance(context_explorer.get("anchors"), dict) else {}
    context_lanes = context_explorer.get("lanes") if isinstance(context_explorer.get("lanes"), dict) else {}

    return {
        "session_id": timestamp,
        "report_title": "DT4SMS Executive Summary",
        "readiness_score": payload.get("readiness_score", v2_context.get("readiness_score")),
        "executive_summary": str(payload.get("ai_summary") or "").strip(),
        "stats": payload.get("stats") if isinstance(payload.get("stats"), dict) else {},
        "trend_signals": payload.get("trend_signals") if isinstance(payload.get("trend_signals"), dict) else {},
        "risk_register": _compact_summary_entries(payload.get("risk_register"), 6, ("severity", "domain", "risk", "impact", "mitigation")),
        "coverage_gaps": _compact_summary_entries(payload.get("coverage_gaps"), 6, ("priority", "domain", "gap", "recommended_action", "impact")),
        "priority_tasks": _compact_summary_entries(payload.get("admin_tasks"), 6, ("priority", "category", "title", "description", "impact")),
        "unknown_data": _compact_summary_entries(payload.get("unknown_data"), 8, ("type", "name", "question")),
        "spl_queries": _compact_summary_entries(payload.get("spl_queries"), 8, ("title", "category", "finding_reference", "query_source", "spl")),
        "context_explorer": {
            "overview": context_explorer.get("overview") if isinstance(context_explorer.get("overview"), dict) else {},
            "patterns": context_explorer.get("patterns", [])[:6] if isinstance(context_explorer.get("patterns"), list) else [],
            "anchors": {
                "indexes": _compact_summary_entries(context_anchors.get("indexes"), 8, ("name", "volume_category", "count", "reason")),
                "sourcetypes": _compact_summary_entries(context_anchors.get("sourcetypes"), 8, ("name", "volume_category", "count", "reason")),
                "hosts": _compact_summary_entries(context_anchors.get("hosts"), 8, ("name", "count", "reason")),
            },
            "lanes": {
                "unknown_entities": _compact_summary_entries(context_lanes.get("unknown_entities"), 6, ("type", "name", "question")),
                "coverage_gaps": _compact_summary_entries(context_lanes.get("coverage_gaps"), 6, ("priority", "gap", "recommended_action")),
                "risks": _compact_summary_entries(context_lanes.get("risks"), 6, ("severity", "risk", "impact")),
                "priority_tasks": _compact_summary_entries(context_lanes.get("priority_tasks"), 6, ("priority", "title", "category", "impact")),
            },
        },
    }


def build_summary_infographic_prompt(timestamp: str, summary_data: Optional[Dict[str, Any]]) -> str:
    """Build a rich prompt for turning the summary into a single infographic."""
    payload = summary_data if isinstance(summary_data, dict) else {}
    brief = build_summary_infographic_brief(timestamp, payload)
    brief_json = truncate_prompt_text(
        json.dumps(brief, indent=2, ensure_ascii=False),
        MAX_INFOGRAPHIC_BRIEF_CHARS,
    )
    prompt_prefix = f"""Create a polished single-page infographic poster for a Splunk discovery executive report.

Goal:
- Turn the supplied DT4SMS summary into an executive-ready infographic.
- Keep every fact anchored to the provided summary.
- Prefer clear sectioning, concise labels, and high information density.
- Do not invent vendors, data sources, metrics, logos, incident claims, or counts that are not in the source material.

Design direction:
- Modern enterprise operations and security briefing board
- One-page landscape infographic
- Strong title hierarchy, summary KPI band, risks, coverage gaps, action queue, and next review loop
- Mix cards, labeled callouts, a simple process band, and tasteful analytical visuals where useful
- Use a restrained palette with indigo, slate, amber, red, and emerald accents
- Make it visually impressive but operational, not playful
- Render all text cleanly and legibly in English

Must include when available:
- Session identifier
- Readiness score and top operating signals
- Priority actions and quick wins
- Risk register highlights
- Coverage gaps
- Priority tasks and action queue
- Context explorer anchors or patterns
- Recursive or next-loop guidance

Output constraints:
- Single image only
- No screenshots, browser chrome, or fake application UI
- No fabricated percentages or extra counts
- If an item is unclear, omit it rather than hallucinating
- Keep names of indexes, sourcetypes, tasks, and control areas exact

Session ID: {timestamp}

Curated brief:
{brief_json}

Full summary payload (truncated only if needed for API safety):
"""
    full_payload_budget = max(0, MAX_INFOGRAPHIC_SUMMARY_CHARS - len(prompt_prefix))
    full_payload = truncate_prompt_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        full_payload_budget,
        "\n... [summary payload truncated for API safety]",
    )
    return f"{prompt_prefix}{full_payload}"

@app.get("/api/config")
async def get_config():
    """Get current configuration (safe export with masked secrets)"""
    return config_manager.export_safe()

@app.post("/api/config")
async def update_config(config_update: ConfigUpdate):
    """Update configuration"""
    try:
        # Update MCP settings
        if config_update.mcp:
            try:
                update_data = config_update.mcp.dict(exclude_unset=True)
                if 'token' in update_data and not update_data['token']:
                    update_data.pop('token')
                if update_data:
                    success = config_manager.update_mcp(**update_data)
                    if not success:
                        raise HTTPException(status_code=500, detail="Failed to save MCP configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"MCP config error: {str(e)}")
        
        # Update LLM settings
        if config_update.llm:
            try:
                update_data = config_update.llm.dict(exclude_unset=True)
                if 'api_key' in update_data and not update_data['api_key']:
                    update_data.pop('api_key')
                if update_data:
                    success = config_manager.update_llm(**update_data)
                    if not success:
                        raise HTTPException(status_code=500, detail="Failed to save LLM configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"LLM config error: {str(e)}")
        
        # Update server settings
        if config_update.server:
            try:
                success = config_manager.update_server(**config_update.server.dict(exclude_unset=True))
                if not success:
                    raise HTTPException(status_code=500, detail="Failed to save server configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"Server config error: {str(e)}")
        
        # Reload config
        config_manager._config = config_manager.load()
        capability_manager.refresh()
        
        return {"status": "success", "message": "Configuration updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


def _raise_for_capability_result(result: Dict[str, Any]):
    if result.get("ok"):
        return
    detail = result.get("message") or "Capability operation failed"
    status_code = 404 if "unknown capability" in detail.lower() else 400
    raise HTTPException(status_code=status_code, detail=detail)


@app.get("/api/capabilities")
async def get_capabilities():
    """Get current capability registry state and persisted config."""
    return {
        "status": "success",
        "summary": capability_manager.get_summary(),
        "capabilities": capability_manager.list_capabilities(),
    }


@app.get("/api/capabilities/health")
async def get_capability_health():
    """Return current capability health snapshots."""
    capabilities = capability_manager.list_capabilities()
    return {
        "status": "success",
        "capabilities": {
            name: {
                "health_status": state.get("health_status"),
                "health_message": state.get("health_message"),
                "last_tested_at": state.get("last_tested_at"),
                "restart_required": state.get("restart_required"),
            }
            for name, state in capabilities.items()
        },
    }


@app.get("/api/capabilities/rag/assets")
async def list_rag_assets():
    """List user-managed knowledge assets for indexed retrieval."""
    result = capability_manager.list_rag_assets("rag_chromadb").to_dict()
    _raise_for_capability_result(result)
    return result


@app.get("/api/capabilities/rag/assets/{asset_id}")
async def get_rag_asset_detail(asset_id: str):
    """Load stored-section and chunk-browser detail for one managed knowledge asset."""
    result = capability_manager.get_rag_asset_detail("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/import/text")
async def import_rag_text_asset(import_request: RAGKnowledgeAssetImportRequest):
    """Import a pasted text asset into the managed RAG asset plane."""
    result = capability_manager.import_rag_text_asset(
        "rag_chromadb",
        {
            "title": import_request.title,
            "content": import_request.content,
            "asset_type": import_request.asset_type,
            "source_label": import_request.source_label,
            "description": import_request.description,
            "tags": list(import_request.tags or []),
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/import/file")
async def import_rag_file_asset(
    file: UploadFile = File(...),
    title: Optional[str] = Form(default=None),
    asset_type: str = Form(default="reference_document"),
    source_label: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    tags: str = Form(default=""),
):
    """Import a supported file as a managed RAG knowledge asset."""
    payload = await file.read()
    result = capability_manager.import_rag_file_asset(
        "rag_chromadb",
        filename=file.filename or "knowledge_asset.txt",
        content_bytes=payload,
        payload={
            "title": title,
            "asset_type": asset_type,
            "source_label": source_label,
            "description": description,
            "tags": _parse_knowledge_asset_tags(tags),
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/{asset_id}/delete")
async def delete_rag_asset(asset_id: str):
    """Delete a managed RAG knowledge asset and refresh the index when configured."""
    result = capability_manager.delete_rag_asset("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/{asset_id}/check-in")
async def check_in_rag_asset(asset_id: str):
    """Check a managed RAG knowledge asset into indexed library circulation."""
    result = capability_manager.check_in_rag_asset("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/{asset_id}/check-out")
async def check_out_rag_asset(asset_id: str):
    """Check a managed RAG knowledge asset out of indexed library circulation."""
    result = capability_manager.check_out_rag_asset("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/context/build")
async def build_rag_context_preview(build_request: RAGContextPreviewRequest):
    """Build a retrieval context preview from managed RAG knowledge assets."""
    result = capability_manager.build_rag_context_preview(
        "rag_chromadb",
        build_request.query,
        max_chunks=build_request.limit,
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/install")
async def install_capability(name: str):
    """Install or prepare an optional capability."""
    result = capability_manager.install_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/enable")
async def enable_capability(name: str):
    """Enable an installed optional capability."""
    result = capability_manager.enable_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/disable")
async def disable_capability(name: str):
    """Disable an optional capability without uninstalling it."""
    result = capability_manager.disable_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/test")
async def test_capability(name: str):
    """Run a health check for an optional capability."""
    result = capability_manager.test_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/reindex")
async def reindex_capability(name: str):
    """Run an index rebuild for capabilities that manage retrieval content."""
    result = capability_manager.reindex_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/config")
async def update_capability_config(name: str, config_update: CapabilityConfigUpdate):
    """Persist capability-specific configuration updates."""
    result = capability_manager.update_capability_config(name, config_update.config).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/deeplinks/build")
async def build_splunk_deeplink(build_request: CapabilityDeeplinkBuildRequest):
    """Build a Splunk deeplink using the optional deeplink capability pack."""
    result = capability_manager.build_deeplink(
        "splunk_deeplink_tools",
        build_request.link_type,
        {
            "query": build_request.query,
            "earliest": build_request.earliest,
            "latest": build_request.latest,
            "app": build_request.app,
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/exports/build")
async def build_capability_export(build_request: CapabilityExportBuildRequest):
    """Build a deterministic export bundle using the optional export capability pack."""
    result = capability_manager.build_export(
        "export_tools",
        {
            "timestamp": build_request.timestamp,
            "persona": build_request.persona,
            "artifact_names": list(build_request.artifact_names or []),
            "title": build_request.title,
            "runbook_markdown": build_request.runbook_markdown,
            "runbook_filename": build_request.runbook_filename,
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.get("/api/capabilities/exports/download/{filename}")
async def download_capability_export(filename: str):
    """Download a generated deterministic export bundle from output/exports."""
    safe_filename = Path(filename).name
    if not re.match(r"^[a-zA-Z0-9_\-.]+$", safe_filename) or not safe_filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Invalid report package filename")

    export_state = capability_manager.get_capability_state("export_tools")
    export_dir = Path(str(export_state.get("export_dir") or Path("output") / "exports"))
    file_path = export_dir / safe_filename
    if not file_path.resolve().is_relative_to(export_dir.resolve()):
        raise HTTPException(status_code=403, detail="Access denied")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report package not found")

    return FileResponse(path=file_path, filename=file_path.name, media_type="application/zip")

# ==================== Credential Vault API ====================

class CredentialCreate(BaseModel):
    """Request model for creating/updating a credential"""
    name: str
    provider: str
    api_key: str
    model: str
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7

@app.get("/api/credentials")
async def list_credentials():
    """Get all saved credentials (with masked API keys)"""
    credentials = config_manager.list_credentials()
    return {
        name: {
            'name': cred.name,
            'provider': cred.provider,
            'api_key': '***' if cred.api_key else '',
            'model': cred.model,
            'endpoint_url': cred.endpoint_url,
            'max_tokens': cred.max_tokens,
            'temperature': cred.temperature
        }
        for name, cred in credentials.items()
    }

@app.post("/api/credentials")
async def save_credential(credential: CredentialCreate):
    """Save a new credential"""
    try:
        success = config_manager.save_credential(
            name=credential.name,
            provider=credential.provider,
            api_key=credential.api_key,
            model=credential.model,
            endpoint_url=credential.endpoint_url,
            max_tokens=credential.max_tokens,
            temperature=credential.temperature
        )
        if success:
            return {"status": "success", "message": f"Credential '{credential.name}' saved"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save credential")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/credentials/{name}")
async def get_credential(name: str):
    """Get a specific credential (with masked API key)"""
    cred = config_manager.get_credential(name)
    if not cred:
        raise HTTPException(status_code=404, detail=f"Credential '{name}' not found")
    
    return {
        'name': cred.name,
        'provider': cred.provider,
        'api_key': '***' if cred.api_key else '',
        'model': cred.model,
        'endpoint_url': cred.endpoint_url,
        'max_tokens': cred.max_tokens,
        'temperature': cred.temperature
    }

@app.delete("/api/credentials/{name}")
async def delete_credential(name: str):
    """Delete a saved credential"""
    success = config_manager.delete_credential(name)
    if success:
        return {"status": "success", "message": f"Credential '{name}' deleted"}
    else:
        raise HTTPException(status_code=404, detail=f"Credential '{name}' not found")

@app.post("/api/credentials/{name}/load")
async def load_credential(name: str):
    """Load a saved credential into active configuration"""
    success = config_manager.load_credential(name)
    if success:
        # Reload config
        config_manager._config = config_manager.load()
        capability_manager.refresh()
        return {
            "status": "success", 
            "message": f"Credential '{name}' loaded",
            "config": config_manager.export_safe()
        }
    else:
        raise HTTPException(status_code=404, detail=f"Credential '{name}' not found")

# ==================== MCP Configuration Vault API ====================

class MCPConfigCreate(BaseModel):
    """Request model for creating/updating an MCP configuration"""
    name: str
    url: str
    token: str
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None
    description: Optional[str] = None

@app.get("/api/mcp-configs")
async def list_mcp_configs():
    """Get all saved MCP configurations (with masked tokens)"""
    mcp_configs = config_manager.list_mcp_configs()
    return {
        name: {
            'name': mcp_config.name,
            'url': mcp_config.url,
            'token': '***' if mcp_config.token else '',
            'verify_ssl': mcp_config.verify_ssl,
            'ca_bundle_path': mcp_config.ca_bundle_path,
            'description': mcp_config.description
        }
        for name, mcp_config in mcp_configs.items()
    }

@app.post("/api/mcp-configs")
async def save_mcp_config(mcp_config: MCPConfigCreate):
    """Save a new MCP configuration"""
    try:
        success = config_manager.save_mcp_config(
            name=mcp_config.name,
            url=mcp_config.url,
            token=mcp_config.token,
            verify_ssl=mcp_config.verify_ssl,
            ca_bundle_path=mcp_config.ca_bundle_path,
            description=mcp_config.description
        )
        if success:
            return {"status": "success", "message": f"MCP configuration '{mcp_config.name}' saved"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save MCP configuration")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mcp-configs/{name}")
async def get_mcp_config(name: str):
    """Get a specific MCP configuration (with masked token)"""
    mcp_config = config_manager.get_mcp_config(name)
    if not mcp_config:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")
    
    return {
        'name': mcp_config.name,
        'url': mcp_config.url,
        'token': '***' if mcp_config.token else '',
        'verify_ssl': mcp_config.verify_ssl,
        'ca_bundle_path': mcp_config.ca_bundle_path,
        'description': mcp_config.description
    }

@app.delete("/api/mcp-configs/{name}")
async def delete_mcp_config(name: str):
    """Delete a saved MCP configuration"""
    success = config_manager.delete_mcp_config(name)
    if success:
        return {"status": "success", "message": f"MCP configuration '{name}' deleted"}
    else:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")

@app.post("/api/mcp-configs/{name}/load")
async def load_mcp_config(name: str):
    """Load a saved MCP configuration into active configuration"""
    success = config_manager.load_mcp_config(name)
    if success:
        # Reload config
        config_manager._config = config_manager.load()
        capability_manager.refresh()
        return {
            "status": "success", 
            "message": f"MCP configuration '{name}' loaded",
            "config": config_manager.export_safe()
        }
    else:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")

@app.post("/api/mcp-configs/test")
async def test_mcp_connection(request: dict):
    """Test MCP connection with provided credentials"""
    try:
        import httpx
        
        url = request.get('url')
        token = request.get('token')
        verify_ssl = request.get('verify_ssl', False)
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Prepare headers
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        # Simple test payload - just check if server responds
        test_payload = {
            "method": "tools/list",
            "params": {}
        }
        
        # Determine SSL verification
        ssl_verify = False if not verify_ssl else True
        
        # Make the test request
        async with httpx.AsyncClient(verify=ssl_verify, timeout=10.0) as client:
            response = await client.post(
                url,
                json=test_payload,
                headers=headers
            )
            
            if response.status_code == 200:
                return {
                    "status": "success",
                    "message": "Connection successful! MCP server is responding.",
                    "server_response": response.status_code
                }
            elif response.status_code == 401:
                return {
                    "status": "error",
                    "message": "Authentication failed. Please check your token.",
                    "server_response": response.status_code
                }
            elif response.status_code == 403:
                return {
                    "status": "error",
                    "message": "Access forbidden. Token may lack permissions.",
                    "server_response": response.status_code
                }
            else:
                return {
                    "status": "warning",
                    "message": f"Server responded with status {response.status_code}. Connection works but there may be issues.",
                    "server_response": response.status_code
                }
                
    except httpx.ConnectError:
        return {
            "status": "error",
            "message": "Cannot connect to server. Check URL and network connectivity."
        }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "message": "Connection timeout. Server may be slow or unreachable."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Connection test failed: {str(e)}"
        }

@app.post("/api/mcp-configs/{name}/test")
async def test_saved_mcp_connection(name: str):
    """Test a saved MCP configuration"""
    mcp_config = config_manager.get_mcp_config(name)
    if not mcp_config:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")
    
    # Use the test endpoint with saved credentials
    return await test_mcp_connection({
        'url': mcp_config.url,
        'token': mcp_config.token,
        'verify_ssl': mcp_config.verify_ssl
    })

# ==================== Chat Settings API (Session-based) ====================

@app.get("/api/chat/settings")
async def get_chat_settings():
    """Get current chat session settings"""
    sync_chat_settings_with_capability_defaults()
    return chat_session_settings.copy()

@app.post("/api/chat/settings")
async def update_chat_settings(settings: Dict[str, Any]):
    """Update chat session settings (not persisted, resets on restart)"""
    global chat_session_settings
    
    # Validate and update only known settings
    valid_keys = set(chat_session_settings.keys())
    for key, value in settings.items():
        if key in valid_keys:
            chat_session_settings[key] = value
            if key == "enable_rag_context":
                chat_settings_explicit_overrides["enable_rag_context"] = True
    
    return {"status": "success", "settings": chat_session_settings.copy()}

@app.post("/api/chat/settings/reset")
async def reset_chat_settings():
    """Reset chat settings to defaults"""
    global chat_session_settings
    
    chat_settings_explicit_overrides["enable_rag_context"] = False
    chat_session_settings = build_default_chat_settings()
    
    return {"status": "success", "settings": chat_session_settings.copy()}

@app.post("/api/llm/list-models")
async def list_models(request: Request):
    """Fetch available models from OpenAI/Azure/Anthropic/Gemini/Custom endpoints."""
    try:
        data = await request.json()
        provider = normalize_provider_name(data.get('provider', 'openai'))
        api_key = data.get('api_key')
        endpoint_url = (data.get('endpoint_url') or '').strip() or None

        async with httpx.AsyncClient(timeout=12.0) as client:
            if provider == 'openai':
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for OpenAI")
                base = (endpoint_url or 'https://api.openai.com').rstrip('/')
                if base.endswith('/v1'):
                    models_url = f'{base}/models'
                elif base.endswith('/models'):
                    models_url = base
                else:
                    models_url = f'{base}/v1/models'
                response = await client.get(
                    models_url,
                    headers={'Authorization': f'Bearer {api_key}'},
                )
                response.raise_for_status()
                models_data = response.json()
                raw_models = sorted({m.get('id') for m in models_data.get('data', []) if isinstance(m, dict) and m.get('id')})
                filtered_models = filter_openai_generation_models([m for m in raw_models if isinstance(m, str)])
                return {
                    'models': filtered_models,
                    'filtered_out': max(0, len(raw_models) - len(filtered_models)),
                }

            if provider == 'azure':
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="Endpoint URL required for Azure provider")
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for Azure provider")

                base = endpoint_url.rstrip('/')
                if '/openai/deployments/' in base:
                    base = base.split('/openai/deployments/')[0]
                if base.endswith('/openai'):
                    base = base[:-len('/openai')]

                deployment_url = f"{base}/openai/deployments?api-version=2024-02-15-preview"
                models_url = f"{base}/openai/models?api-version=2024-02-15-preview"
                headers = {'api-key': api_key}

                deployments = []
                try:
                    response = await client.get(deployment_url, headers=headers)
                    if response.status_code == 200:
                        payload = response.json()
                        deployments = [
                            item.get('id')
                            for item in payload.get('data', [])
                            if isinstance(item, dict) and item.get('id')
                        ]
                except Exception:
                    deployments = []

                model_ids = []
                try:
                    response = await client.get(models_url, headers=headers)
                    if response.status_code == 200:
                        payload = response.json()
                        model_ids = [
                            item.get('id')
                            for item in payload.get('data', [])
                            if isinstance(item, dict) and item.get('id')
                        ]
                except Exception:
                    model_ids = []

                merged = sorted({m for m in deployments + model_ids if isinstance(m, str) and m.strip()})
                if not merged:
                    raise HTTPException(status_code=400, detail="Could not fetch Azure deployments/models from endpoint")
                return {'models': merged}

            if provider == 'anthropic':
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for Anthropic")
                base = (endpoint_url or 'https://api.anthropic.com').rstrip('/')
                response = await client.get(
                    f"{base}/v1/models",
                    headers={
                        'x-api-key': api_key,
                        'anthropic-version': '2023-06-01'
                    },
                )
                response.raise_for_status()
                payload = response.json()
                models = sorted({item.get('id') for item in payload.get('data', []) if isinstance(item, dict) and item.get('id')})
                return {'models': [m for m in models if isinstance(m, str)]}

            if provider == 'gemini':
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for Gemini")
                base = (endpoint_url or 'https://generativelanguage.googleapis.com').rstrip('/')
                response = await client.get(f"{base}/v1beta/models?key={quote(api_key)}")
                response.raise_for_status()
                payload = response.json()
                models = []
                for item in payload.get('models', []):
                    if not isinstance(item, dict):
                        continue
                    name = item.get('name')
                    if isinstance(name, str) and name.startswith('models/'):
                        name = name.split('/', 1)[1]
                    if isinstance(name, str) and name.strip():
                        models.append(name)
                return {'models': sorted({m for m in models if isinstance(m, str)})}

            if provider == 'custom':
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="Endpoint URL required for custom provider")

                base = endpoint_url.rstrip('/')
                endpoints_to_try = [
                    base if base.endswith('/v1/models') else f"{base}/v1/models",
                    base if base.endswith('/models') else f"{base}/models",
                    base if base.endswith('/api/tags') else f"{base}/api/tags",
                ]

                for url in endpoints_to_try:
                    try:
                        headers = {}
                        if api_key:
                            headers['Authorization'] = f'Bearer {api_key}'
                        response = await client.get(url, headers=headers)
                        response.raise_for_status()
                        payload = response.json()

                        if isinstance(payload, dict) and isinstance(payload.get('data'), list):
                            models = [m.get('id') for m in payload.get('data', []) if isinstance(m, dict) and m.get('id')]
                            return {'models': sorted({m for m in models if isinstance(m, str)})}

                        if isinstance(payload, dict) and isinstance(payload.get('models'), list):
                            models = []
                            for item in payload.get('models', []):
                                if isinstance(item, dict):
                                    model_name = item.get('name') or item.get('id')
                                else:
                                    model_name = item
                                if isinstance(model_name, str) and model_name.strip():
                                    models.append(model_name)
                            return {'models': sorted({m for m in models if isinstance(m, str)})}

                        if isinstance(payload, list):
                            models = []
                            for item in payload:
                                if isinstance(item, dict):
                                    model_name = item.get('id') or item.get('name')
                                else:
                                    model_name = item
                                if isinstance(model_name, str) and model_name.strip():
                                    models.append(model_name)
                            return {'models': sorted({m for m in models if isinstance(m, str)})}
                    except Exception:
                        continue

                raise HTTPException(status_code=400, detail="Could not fetch models from custom endpoint")

            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch models: {str(e)}")


@app.get("/api/summary/infographic-capability")
async def get_summary_infographic_capability(timestamp: Optional[str] = None):
    """Return whether the active OpenAI credential can access gpt-image-2."""
    existing_artifact = _find_existing_summary_infographic(timestamp) if timestamp else None
    config = config_manager.get()
    provider = normalize_provider_name(config.llm.provider)

    if provider != "openai":
        return {
            "available": existing_artifact is not None,
            "can_generate": False,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": False,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
            "reason": "Active provider is not OpenAI",
        }

    if not config.llm.api_key:
        return {
            "available": existing_artifact is not None,
            "can_generate": False,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": False,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
            "reason": "OpenAI API key is not configured",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                build_openai_api_url(config.llm.endpoint_url, "/models"),
                headers={"Authorization": f"Bearer {config.llm.api_key}"},
            )
            response.raise_for_status()
            payload = response.json()

        model_ids = [
            item.get("id")
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        ]
        can_generate = openai_model_ids_include(model_ids, OPENAI_IMAGE_MODEL)
        return {
            "available": can_generate or existing_artifact is not None,
            "can_generate": can_generate,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": True,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
        }
    except Exception as exc:
        return {
            "available": existing_artifact is not None,
            "can_generate": False,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": False,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
            "reason": f"Capability probe failed: {exc}",
        }


@app.post("/api/summary/generate-infographic")
async def generate_summary_infographic(request: SummaryInfographicRequest):
    """Generate an infographic image from the current summary using gpt-image-2."""
    config = config_manager.get()
    provider = normalize_provider_name(config.llm.provider)

    if provider != "openai":
        raise HTTPException(status_code=400, detail="Summary infographic generation requires the OpenAI provider")
    if not config.llm.api_key:
        raise HTTPException(status_code=400, detail="OpenAI API key is not configured")

    timestamp = str(request.timestamp or "").strip()
    if not timestamp:
        raise HTTPException(status_code=400, detail="timestamp is required")

    existing_infographic = _find_existing_summary_infographic(timestamp)
    if existing_infographic is not None:
        _ensure_session_artifact_registered(timestamp, existing_infographic.name)
        image_format = 'jpeg' if existing_infographic.suffix.lower() == '.jpg' else existing_infographic.suffix[1:].lower()
        return {
            "status": "success",
            "model": OPENAI_IMAGE_MODEL,
            "mime_type": f"image/{image_format}",
            "image_base64": base64.b64encode(existing_infographic.read_bytes()).decode("ascii"),
            "filename": existing_infographic.name,
            "artifact_path": str(existing_infographic),
            "reused_existing": True,
        }

    prompt = build_summary_infographic_prompt(timestamp, request.summary_data)
    payload = {
        "model": OPENAI_IMAGE_MODEL,
        "prompt": prompt,
        "size": "1536x1024",
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(420.0, connect=30.0)) as client:
            response = await client.post(
                build_openai_api_url(config.llm.endpoint_url, "/images/generations"),
                headers={
                    "Authorization": f"Bearer {config.llm.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            response_payload = response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="OpenAI image generation timed out while waiting for gpt-image-2 to finish")
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:500] if exc.response is not None else str(exc)
        raise HTTPException(status_code=exc.response.status_code if exc.response is not None else 502, detail=f"OpenAI image generation failed: {detail}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenAI image generation failed: {exc}")

    image_items = response_payload.get("data", []) if isinstance(response_payload, dict) else []
    first_image = image_items[0] if image_items and isinstance(image_items[0], dict) else {}
    image_base64 = first_image.get("b64_json") if isinstance(first_image.get("b64_json"), str) else ""
    image_url = first_image.get("url") if isinstance(first_image.get("url"), str) else ""

    if image_base64:
        output_dir = _summary_infographic_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_timestamp = re.sub(r"[^0-9A-Za-z_-]", "_", timestamp)
        filename = f"summary_infographic_{safe_timestamp}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        artifact_path = output_dir / filename
        artifact_path.write_bytes(base64.b64decode(image_base64))
        _ensure_session_artifact_registered(timestamp, filename)
        return {
            "status": "success",
            "model": OPENAI_IMAGE_MODEL,
            "mime_type": "image/png",
            "image_base64": image_base64,
            "filename": filename,
            "artifact_path": str(artifact_path),
            "reused_existing": False,
        }

    if image_url:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
                image_response = await client.get(image_url)
                image_response.raise_for_status()
            content_type = str(image_response.headers.get("content-type") or "image/png").split(";", 1)[0].strip().lower() or "image/png"
            extension = {
                "image/jpeg": ".jpg",
                "image/webp": ".webp",
                "image/gif": ".gif",
            }.get(content_type, ".png")
            output_dir = _summary_infographic_dir()
            output_dir.mkdir(parents=True, exist_ok=True)
            safe_timestamp = re.sub(r"[^0-9A-Za-z_-]", "_", timestamp)
            filename = f"summary_infographic_{safe_timestamp}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{extension}"
            artifact_path = output_dir / filename
            artifact_bytes = image_response.content
            artifact_path.write_bytes(artifact_bytes)
            _ensure_session_artifact_registered(timestamp, filename)
            return {
                "status": "success",
                "model": OPENAI_IMAGE_MODEL,
                "mime_type": content_type,
                "image_base64": base64.b64encode(artifact_bytes).decode("ascii"),
                "filename": filename,
                "artifact_path": str(artifact_path),
                "reused_existing": False,
            }
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"OpenAI image download failed: {exc}")
        return {
            "status": "success",
            "model": OPENAI_IMAGE_MODEL,
            "image_url": image_url,
        }

    raise HTTPException(status_code=502, detail="OpenAI image generation returned no image payload")

@app.get("/api/dependencies")
async def get_dependencies():
    """Get installed Python packages and their versions"""
    try:
        import subprocess
        import json as json_module
        
        # Run pip list --format=json
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        packages = json_module.loads(result.stdout)
        
        # Sort by name
        packages.sort(key=lambda x: x['name'].lower())

        return {
            "status": "success",
            "packages": packages,
            "total": len(packages)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dependencies: {str(e)}")

@app.post("/api/llm/assess-max-tokens")
async def assess_max_tokens(request: Request):
    """Assess the actual max_tokens limit by testing the LLM API"""
    try:
        payload = {}
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}

        config = config_manager.get()
        llm_payload = payload.get("llm", {}) if isinstance(payload.get("llm"), dict) else payload

        provider = normalize_provider_name(llm_payload.get("provider", config.llm.provider))
        api_key = llm_payload.get("api_key", config.llm.api_key)
        model = llm_payload.get("model", config.llm.model)
        endpoint_url = llm_payload.get("endpoint_url", config.llm.endpoint_url)
        
        if provider in {"openai", "azure", "anthropic", "gemini"} and not api_key:
            raise HTTPException(status_code=400, detail="LLM API key not configured")

        if provider == "openai" and is_openai_image_generation_model(model):
            return {
                "recommended_max_tokens": None,
                "applicable": False,
                "status": "info",
                "message": f"{model} uses the OpenAI images API. max_tokens is not required for summary infographic execution; output is limited by image size instead.",
            }

        if provider != "openai":
            defaults = {
                "azure": 8000,
                "anthropic": 8192,
                "gemini": 8192,
                "custom": 4000,
            }
            fallback = defaults.get(provider, 4000)
            return {
                "recommended_max_tokens": fallback,
                "status": "info",
                "message": f"Automatic max token probing is optimized for OpenAI. Using provider-safe default for {provider}: {fallback}"
            }
        
        llm_client = LLMClientFactory.create_client(
            provider=provider,
            custom_endpoint=endpoint_url,
            api_key=api_key,
            model=model,
        )
        
        # Try progressively larger max_tokens until we hit the limit
        test_values = [128000, 64000, 32000, 16000, 8000, 4000, 2000, 1000]
        
        for test_max in test_values:
            try:
                await llm_client.generate_response(
                    messages=[{"role": "user", "content": "Reply with exactly: ok"}],
                    max_tokens=test_max,
                    temperature=0.0,
                )
                
                return {
                    "recommended_max_tokens": test_max,
                    "status": "success",
                    "message": f"Model supports at least {test_max} tokens",
                    "tested_value": test_max
                }
                
            except Exception as e:
                error_str = str(e)
                import re
                match = re.search(r'supports at most (\d+)', error_str)
                if not match:
                    match = re.search(r'max(?:imum)?[^\d]{0,20}(\d+)', error_str, flags=re.IGNORECASE)
                if match:
                    actual_limit = int(match.group(1))
                    recommended = int(actual_limit * 0.9)
                    return {
                        "recommended_max_tokens": recommended,
                        "actual_limit": actual_limit,
                        "status": "success",
                        "message": f"Model supports {actual_limit} tokens, recommending {recommended} (90% of limit)"
                    }
                
                if 'max_tokens' in error_str.lower():
                    continue
                    
                raise HTTPException(status_code=500, detail=f"LLM test error: {error_str}")
        
        return {
            "recommended_max_tokens": 1000,
            "status": "fallback",
            "message": "Could not determine limit, using conservative fallback"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment error: {str(e)}")


@app.post("/api/llm/test-connection")
async def test_llm_connection(request: Request):
    """Test provider-specific LLM connectivity and generation using current or supplied settings."""
    try:
        payload = {}
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}

        current_config = config_manager.get()
        llm_payload = payload.get("llm", {}) if isinstance(payload.get("llm"), dict) else payload

        provider = normalize_provider_name(llm_payload.get("provider", current_config.llm.provider))
        api_key = llm_payload.get("api_key", current_config.llm.api_key)
        model = llm_payload.get("model", current_config.llm.model)
        endpoint_url = llm_payload.get("endpoint_url", current_config.llm.endpoint_url)
        max_tokens = int(llm_payload.get("max_tokens", current_config.llm.max_tokens or 1000))
        temperature = float(llm_payload.get("temperature", current_config.llm.temperature or 0.7))

        if provider in {"azure", "custom"} and not endpoint_url:
            return {
                "status": "error",
                "message": f"Provider '{provider}' requires endpoint_url",
                "tests": {
                    "connection": {
                        "status": "error",
                        "message": "Missing endpoint_url"
                    }
                }
            }

        if provider in {"openai", "azure", "anthropic", "gemini"} and not api_key:
            return {
                "status": "error",
                "message": f"Provider '{provider}' requires api_key",
                "tests": {
                    "connection": {
                        "status": "error",
                        "message": "Missing api_key"
                    }
                }
            }

        results = {
            "status": "testing",
            "provider": provider,
            "model": model,
            "endpoint": endpoint_url or {
                "openai": "https://api.openai.com",
                "anthropic": "https://api.anthropic.com",
                "gemini": "https://generativelanguage.googleapis.com",
            }.get(provider, "n/a"),
            "tests": {}
        }

        openai_model_capabilities = {}
        openai_model_ids = []
        if provider == "openai":
            openai_model_capabilities = get_openai_model_capabilities(model)
            results["model_capabilities"] = openai_model_capabilities

        uses_openai_image_generation = provider == "openai" and openai_model_capabilities.get("supports_image_generation", False)

        # Test 1: Connectivity probe
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                if provider == "openai":
                    base = (endpoint_url or "https://api.openai.com").rstrip('/')
                    if base.endswith('/v1'):
                        probe_url = f"{base}/models"
                    elif base.endswith('/models'):
                        probe_url = base
                    else:
                        probe_url = f"{base}/v1/models"
                    probe = await client.get(
                        probe_url,
                        headers={"Authorization": f"Bearer {api_key}"}
                    )
                    probe.raise_for_status()
                    probe_payload = probe.json() if hasattr(probe, "json") else {}
                    openai_model_ids = [
                        item.get("id")
                        for item in probe_payload.get("data", [])
                        if isinstance(item, dict) and item.get("id")
                    ]
                    results["tests"]["connection"] = {"status": "success", "message": "OpenAI models endpoint reachable"}

                elif provider == "azure":
                    base = endpoint_url.rstrip('/')
                    if '/openai/deployments/' in base:
                        base = base.split('/openai/deployments/')[0]
                    if base.endswith('/openai'):
                        base = base[:-len('/openai')]
                    probe = await client.get(
                        f"{base}/openai/deployments?api-version=2024-02-15-preview",
                        headers={"api-key": api_key}
                    )
                    if probe.status_code not in {200, 401, 403}:
                        probe.raise_for_status()
                    if probe.status_code in {401, 403}:
                        raise Exception("Azure endpoint reachable but API key/auth failed")
                    results["tests"]["connection"] = {"status": "success", "message": "Azure OpenAI endpoint reachable"}

                elif provider == "anthropic":
                    base = (endpoint_url or "https://api.anthropic.com").rstrip('/')
                    probe = await client.get(
                        f"{base}/v1/models",
                        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"}
                    )
                    probe.raise_for_status()
                    results["tests"]["connection"] = {"status": "success", "message": "Anthropic models endpoint reachable"}

                elif provider == "gemini":
                    base = (endpoint_url or "https://generativelanguage.googleapis.com").rstrip('/')
                    probe = await client.get(f"{base}/v1beta/models?key={quote(api_key)}")
                    probe.raise_for_status()
                    results["tests"]["connection"] = {"status": "success", "message": "Gemini models endpoint reachable"}

                else:  # custom
                    base = endpoint_url.rstrip('/')
                    checks = [
                        base,
                        f"{base}/v1/models",
                        f"{base}/models",
                        f"{base}/api/tags",
                        f"{base}/health",
                    ]
                    reachable = False
                    for url in checks:
                        try:
                            resp = await client.get(url)
                            if resp.status_code < 500:
                                reachable = True
                                break
                        except Exception:
                            continue
                    if not reachable:
                        raise Exception("Custom endpoint not reachable or not responding with usable API shape")
                    results["tests"]["connection"] = {"status": "success", "message": "Custom endpoint reachable"}

        except Exception as connection_error:
            results["tests"]["connection"] = {
                "status": "error",
                "message": f"Connection probe failed: {connection_error}",
                "error": str(connection_error)
            }
            results["status"] = "error"
            return results

        # Test 2: Model generation
        try:
            if uses_openai_image_generation:
                if openai_model_ids and not openai_model_ids_include(openai_model_ids, model):
                    results["tests"]["model"] = {
                        "status": "error",
                        "message": f"Image model '{model}' is not listed for this OpenAI credential"
                    }
                    results["status"] = "error"
                    return results

                results["tests"]["model"] = {
                    "status": "info",
                    "message": f"{model} uses the OpenAI images API. Skipped text completion probe; summary infographic generation should use the dedicated image endpoint.",
                }
            else:
                llm_client = LLMClientFactory.create_client(
                    provider=provider,
                    custom_endpoint=endpoint_url,
                    api_key=api_key,
                    model=model
                )

                model_response = await llm_client.generate_response(
                    messages=[{"role": "user", "content": "Reply with exactly: test successful"}],
                    max_tokens=min(max_tokens, 64),
                    temperature=0.0,
                )
                results["tests"]["model"] = {
                    "status": "success",
                    "message": "Model responded successfully",
                    "response_preview": str(model_response)[:120]
                }
        except Exception as model_error:
            results["tests"]["model"] = {
                "status": "error",
                "message": f"Model test failed: {model_error}",
                "error": str(model_error)
            }
            results["status"] = "error"
            return results

        # Test 3: Recommended token configuration
        if uses_openai_image_generation:
            results["tests"]["max_tokens"] = {
                "status": "info",
                "detected_max": None,
                "message": f"max_tokens is not used for {model}. Summary infographic generation is constrained by image output size instead.",
            }
        else:
            recommended_max = max(512, min(max_tokens, 16000))
            if provider == "gemini":
                recommended_max = max(512, min(max_tokens, 8192))
            elif provider == "anthropic":
                recommended_max = max(512, min(max_tokens, 8192))
            elif provider == "custom":
                recommended_max = max(512, min(max_tokens, 4096))

            results["tests"]["max_tokens"] = {
                "status": "info",
                "detected_max": recommended_max,
                "message": f"Using provider-safe recommended max_tokens={recommended_max}"
            }

        results["status"] = "success"
        results["message"] = "All provider tests passed"
        if uses_openai_image_generation:
            results["recommended_config"] = {
                "temperature": temperature
            }
        else:
            results["recommended_config"] = {
                "max_tokens": recommended_max,
                "temperature": temperature
            }
        return results

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "error": str(e),
            "message": f"Test failed: {str(e)}"
        }


@app.get("/summarize-progress/{session_id}")
async def get_summarize_progress(session_id: str):
    """Get current progress of summarization with input validation."""
    try:
        # Security: Validate session ID format
        safe_session_id = validate_session_id(session_id)
        return summarization_progress.get(safe_session_id, {
            "stage": "idle",
            "progress": 0,
            "message": "Not started"
        })
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid session ID")


@app.post("/summarize-session")
async def summarize_session(request: Dict[str, Any]):
    """
    Generate AI-powered summary with SPL queries and contextual questions.
    
    This endpoint:
    1. Checks if summary already exists and returns it if found
    2. Loads discovery reports for the session
    3. Generates contextual SPL queries for discovered data
    4. Identifies unknown/ambiguous data sources
    5. Creates executive summary with priority actions
    6. Saves the summary for future use
    """
    from spl.generator import SPLGenerator
    from spl.unknown_identifier import UnknownDataIdentifier
    
    timestamp = request.get("timestamp")
    if not timestamp:
        raise HTTPException(status_code=400, detail="timestamp required")
    
    # Security: Validate session ID format
    try:
        safe_timestamp = validate_session_id(timestamp)
    except HTTPException:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")

    # Normalize to validated timestamp for all downstream file operations
    timestamp = safe_timestamp

    output_dir = Path("output")

    # Load V2 session artifacts only (legacy artifacts intentionally ignored)
    json_file = output_dir / f"v2_intelligence_blueprint_{timestamp}.json"
    detailed_file = output_dir / f"v2_operator_runbook_{timestamp}.md"
    classification_file = output_dir / f"v2_developer_handoff_{timestamp}.md"
    executive_file = output_dir / f"v2_insights_brief_{timestamp}.md"
    
    # Check if summary already exists
    summary_file = output_dir / f"v2_ai_summary_{safe_timestamp}.json"
    
    if summary_file.exists():
        # Load and return existing summary
        try:
            with open(summary_file, 'r', encoding='utf-8') as f:
                existing_summary = json.load(f)
            has_v2_panels = all(
                key in existing_summary
                for key in ["schema_version", "trend_signals", "risk_register", "recursive_investigations"]
            )
            if has_v2_panels:
                if "context_explorer" not in existing_summary and json_file.exists():
                    try:
                        with open(json_file, 'r', encoding='utf-8') as cached_discovery_file:
                            cached_discovery_data = json.load(cached_discovery_file)
                        existing_summary["context_explorer"] = build_context_explorer_payload(
                            cached_discovery_data,
                            unknown_questions=existing_summary.get("unknown_data"),
                            admin_tasks=existing_summary.get("admin_tasks"),
                            coverage_gaps=existing_summary.get("coverage_gaps"),
                            risk_register=existing_summary.get("risk_register"),
                            readiness_score=existing_summary.get("readiness_score"),
                        )
                        with open(summary_file, 'w', encoding='utf-8') as summary_out:
                            json.dump(existing_summary, summary_out, indent=2)
                    except Exception as cache_patch_error:
                        print(f"Error backfilling context explorer for cached summary: {cache_patch_error}")
                existing_summary['from_cache'] = True
                return existing_summary
            print(f"Cached summary {summary_file.name} missing V2 fields; regenerating...")
        except Exception as e:
            print(f"Error loading cached summary: {e}")
            # Continue to regenerate

    if not json_file.exists():
        return {"error": "V2 session data not found"}
    
    # Initialize progress tracking
    summarization_progress[timestamp] = {
        "stage": "loading",
        "progress": 10,
        "message": "Loading discovery reports..."
    }
    
    # Load V2 discovery data
    with open(json_file, 'r', encoding='utf-8') as f:
        discovery_data = json.load(f)
    
    # Extract discovery results from V2 finding ledger
    finding_ledger = discovery_data.get('finding_ledger', []) if isinstance(discovery_data, dict) else []
    discovery_results = [entry for entry in finding_ledger if isinstance(entry, dict)]
    discovery_entities = []
    for entry in discovery_results:
        data_obj = entry.get('data', {})
        if isinstance(data_obj, dict) and data_obj:
            discovery_entities.append(data_obj)
        else:
            discovery_entities.append(entry)

    coverage_gaps = discovery_data.get("coverage_gaps", []) if isinstance(discovery_data.get("coverage_gaps", []), list) else []
    trend_signals = discovery_data.get("trend_signals", {}) if isinstance(discovery_data.get("trend_signals", {}), dict) else {}
    if not trend_signals:
        trend_signals = {
            "evidence_steps": len(discovery_results),
            "high_priority_recommendations": len([
                r for r in (discovery_data.get("recommendations", []) or [])
                if isinstance(r, dict) and str(r.get("priority", "")).lower() == "high"
            ]),
            "coverage_gap_count": len(coverage_gaps),
            "recommendation_by_domain": {
                "security": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and "security" in str(r.get("category", "")).lower()]),
                "performance": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and "performance" in str(r.get("category", "")).lower()]),
                "data_quality": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and ("data" in str(r.get("category", "")).lower() or "quality" in str(r.get("category", "")).lower())]),
                "compliance": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and "compliance" in str(r.get("category", "")).lower()]),
            }
        }

    risk_register = discovery_data.get("risk_register", []) if isinstance(discovery_data.get("risk_register", []), list) else []
    if not risk_register:
        risk_register = [
            {
                "risk": gap.get("gap", "Coverage risk"),
                "severity": str(gap.get("priority", "medium")).lower(),
                "domain": "coverage",
                "impact": gap.get("why_it_matters", ""),
                "mitigation": "Convert this gap into verification + remediation SPL workflows."
            }
            for gap in coverage_gaps[:10]
            if isinstance(gap, dict)
        ]

    recursive_investigations = discovery_data.get("recursive_investigations", []) if isinstance(discovery_data.get("recursive_investigations", []), list) else []
    if not recursive_investigations:
        recursive_investigations = [
            {
                "loop": "Trend Baseline Expansion",
                "objective": "Re-run discovery weekly and compare high-priority recommendations over time.",
                "next_iteration_trigger": "Recommendation volume or severity increases.",
                "output": "Delta report with priority shifts and anomaly candidates."
            },
            {
                "loop": "Risk Verification Loop",
                "objective": "Validate each high-severity risk with focused SPL and record closure evidence.",
                "next_iteration_trigger": "Any high risk remains unresolved after runbook execution.",
                "output": "Residual risk register with owners and due dates."
            }
        ]

    vulnerability_hypotheses = discovery_data.get("vulnerability_hypotheses", []) if isinstance(discovery_data.get("vulnerability_hypotheses", []), list) else []
    readiness_score = discovery_data.get("readiness_score")
    
    # Update progress
    summarization_progress[timestamp] = {
        "stage": "generating_queries",
        "progress": 25,
        "message": "Generating SPL queries..."
    }
    
    # Generate template SPL queries (used as fallback if AI generation fails)
    spl_gen = SPLGenerator(discovery_results)
    template_queries = []
    
    # Security queries
    security_queries = spl_gen.generate_security_queries()
    template_queries.extend([{
        **q,
        "category": "Security & Compliance",
        "query_source": "template"
    } for q in security_queries])
    
    # Infrastructure queries
    infra_queries = spl_gen.generate_infrastructure_queries()
    template_queries.extend([{
        **q,
        "category": "Infrastructure & Performance",
        "query_source": "template"
    } for q in infra_queries])
    
    # Performance queries
    perf_queries = spl_gen.generate_performance_queries()
    template_queries.extend([{
        **q,
        "category": "Capacity Planning",
        "query_source": "template"
    } for q in perf_queries])
    
    # Exploratory queries
    explore_queries = spl_gen.generate_exploratory_queries()
    template_queries.extend([{
        **q,
        "category": "Data Exploration",
        "query_source": "template"
    } for q in explore_queries])
    
    print(f"Generated {len(template_queries)} template queries as fallback")
    
    # Update progress
    summarization_progress[timestamp] = {
        "stage": "identifying_unknowns",
        "progress": 50,
        "message": "Identifying unknown data sources..."
    }
    
    # Identify unknown data sources
    unknown_id = UnknownDataIdentifier(discovery_entities)
    unknown_items = unknown_id.identify_unknown_items()
    unknown_questions = unknown_id.generate_contextual_questions(unknown_items)
    
    # Update progress
    summarization_progress[timestamp] = {
        "stage": "loading_reports",
        "progress": 60,
        "message": "Analyzing discovery reports..."
    }
    
    # Load reports for analysis
    executive_summary = ""
    if executive_file.exists():
        with open(executive_file, 'r', encoding='utf-8') as f:
            executive_summary = f.read()
    
    detailed_findings = ""
    if detailed_file.exists():
        with open(detailed_file, 'r', encoding='utf-8') as f:
            detailed_findings = f.read()
    
    classification_report = ""
    if classification_file.exists():
        with open(classification_file, 'r', encoding='utf-8') as f:
            classification_report = f.read()
    
    # ===== AI-POWERED REPORT ANALYSIS =====
    # Use LLM to extract actual findings from reports
    config = config_manager.get()
    llm_client = get_or_create_llm_client(config)
    
    # Extract environment entities from discovery results
    discovered_indexes = set()
    discovered_sourcetypes = set()
    discovered_hosts = set()
    for result in discovery_results:
        data = result.get('data', {})
        if isinstance(data, dict):
            host_value = data.get('host') or data.get('hostname')
            if isinstance(host_value, str) and host_value.strip():
                discovered_hosts.add(host_value.strip())
            if isinstance(data.get('hosts'), list):
                for host in data.get('hosts', []):
                    if isinstance(host, str) and host.strip():
                        discovered_hosts.add(host.strip())
            index_value = data.get('index')
            if isinstance(index_value, str) and index_value.strip():
                discovered_indexes.add(index_value.strip())
        if 'title' in data and 'totalEventCount' in data:
            discovered_indexes.add(data['title'])
        elif 'sourcetype' in data:
            discovered_sourcetypes.add(data['sourcetype'])

    discovered_indexes_list = sorted([idx for idx in discovered_indexes if isinstance(idx, str) and idx.strip()])
    discovered_sourcetypes_list = sorted([st for st in discovered_sourcetypes if isinstance(st, str) and st.strip()])
    discovered_hosts_list = sorted([h for h in discovered_hosts if isinstance(h, str) and h.strip()])

    environment_context_block = {
        "indexes": discovered_indexes_list[:30],
        "sourcetypes": discovered_sourcetypes_list[:40],
        "hosts": discovered_hosts_list[:40],
        "coverage_gaps": [g.get("gap") for g in coverage_gaps[:10] if isinstance(g, dict)],
        "risk_register": [r.get("risk") for r in risk_register[:10] if isinstance(r, dict)],
    }

    def _safe_str(value: Any, fallback: str = "") -> str:
        if value is None:
            return fallback
        text = str(value).strip()
        return text if text else fallback

    def _severity_rank(severity: str) -> int:
        normalized = _safe_str(severity, "medium").lower()
        if normalized == "critical":
            return 4
        if normalized == "high":
            return 3
        if normalized == "medium":
            return 2
        return 1

    def _priority_from_severity(severity: str) -> str:
        rank = _severity_rank(severity)
        if rank >= 4:
            return "🔴 HIGH"
        if rank == 3:
            return "🔴 HIGH"
        if rank == 2:
            return "🟠 MEDIUM"
        return "🟡 LOW"

    def _preferred_anchor_index() -> str:
        if discovered_indexes_list:
            return discovered_indexes_list[0]
        return "*"

    def _anchor_spl_to_environment(spl_query: str) -> str:
        query = (spl_query or "").strip()
        if not query:
            return query
        if not discovered_indexes_list:
            return query
        query_lower = query.lower()
        has_index = any(f"index={idx.lower()}" in query_lower for idx in discovered_indexes_list)
        if has_index:
            return query
        anchor_index = discovered_indexes_list[0]
        if query.startswith("|"):
            return f"index={anchor_index} {query}"
        if query_lower.startswith("search "):
            return f"search index={anchor_index} {query[len('search '):]}"
        return f"index={anchor_index} | {query}"

    def _strip_code_fence(text: str) -> str:
        cleaned = _safe_str(text)
        cleaned = cleaned.replace("```spl", "").replace("```sql", "").replace("```", "").strip()
        return cleaned

    def _extract_environment_evidence(spl_query: str) -> List[str]:
        evidence = []
        q = (spl_query or "").lower()
        for idx in discovered_indexes_list[:20]:
            if f"index={idx.lower()}" in q:
                evidence.append(f"index:{idx}")
        for st in discovered_sourcetypes_list[:20]:
            if st.lower() in q:
                evidence.append(f"sourcetype:{st}")
        for host in discovered_hosts_list[:20]:
            if host.lower() in q:
                evidence.append(f"host:{host}")
        if not evidence and discovered_indexes_list:
            evidence.append(f"index:{discovered_indexes_list[0]}")
        return evidence[:5]

    def _flatten_findings(findings: Dict[str, Any]) -> List[Dict[str, str]]:
        category_to_domain = {
            "security_findings": "Security & Compliance",
            "performance_findings": "Infrastructure & Performance",
            "data_quality_findings": "Data Quality",
            "optimization_findings": "Capacity Planning",
            "compliance_findings": "Security & Compliance",
            "trend_findings": "Infrastructure & Performance",
            "risk_hypotheses": "Security & Compliance",
        }
        flattened: List[Dict[str, str]] = []
        for category, domain in category_to_domain.items():
            entries = findings.get(category, []) if isinstance(findings, dict) else []
            if not isinstance(entries, list):
                continue
            for entry in entries[:10]:
                if not isinstance(entry, dict):
                    continue
                description = _safe_str(entry.get("description"), _safe_str(entry.get("type"), "Discovery finding"))
                flattened.append({
                    "domain": domain,
                    "severity": _safe_str(entry.get("severity"), "medium"),
                    "reference": description[:220],
                    "recommendation": _safe_str(entry.get("recommendation"), "Investigate and validate in Splunk.")
                })
        return flattened

    def _normalize_query_item(query: Dict[str, Any], idx: int, finding_pool: List[Dict[str, str]]) -> Dict[str, Any]:
        category = _safe_str(query.get("category"), "Infrastructure & Performance")
        valid_categories = {
            "Security & Compliance",
            "Infrastructure & Performance",
            "Data Quality",
            "Capacity Planning",
            "Data Exploration"
        }
        if category not in valid_categories:
            category = "Infrastructure & Performance"

        default_use_case_by_category = {
            "Security & Compliance": "Security Investigation",
            "Infrastructure & Performance": "Performance Monitoring",
            "Data Quality": "Data Quality",
            "Capacity Planning": "Capacity Planning",
            "Data Exploration": "Data Quality"
        }

        finding_ref = _safe_str(query.get("finding_reference"))
        matching_finding = None
        if finding_ref:
            for f in finding_pool:
                if finding_ref.lower()[:40] in f.get("reference", "").lower():
                    matching_finding = f
                    break
        if not matching_finding and finding_pool:
            preferred = [f for f in finding_pool if f.get("domain") == category]
            matching_finding = preferred[0] if preferred else finding_pool[0]

        raw_spl = _strip_code_fence(_safe_str(query.get("spl")))
        if not raw_spl:
            anchor_index = _preferred_anchor_index()
            raw_spl = f"index={anchor_index} earliest=-24h | stats count by sourcetype host | sort - count"
        normalized_spl = _anchor_spl_to_environment(raw_spl)
        if "earliest=" not in normalized_spl.lower():
            normalized_spl = normalized_spl.replace("|", "earliest=-24h |", 1) if "|" in normalized_spl else f"{normalized_spl} earliest=-24h"

        evidence = query.get("environment_evidence")
        if not isinstance(evidence, list) or not evidence:
            evidence = _extract_environment_evidence(normalized_spl)

        severity = matching_finding.get("severity", "medium") if matching_finding else "medium"
        priority = _safe_str(query.get("priority"), _priority_from_severity(severity))
        if not any(priority.startswith(prefix) for prefix in ["🔴", "🟠", "🟡"]):
            priority = _priority_from_severity(severity)

        title = _safe_str(query.get("title"), f"🔍 Contextual Query {idx + 1}")
        description = _safe_str(query.get("description"), "Investigate this finding with environment-specific telemetry.")

        return {
            "title": title,
            "description": description,
            "use_case": _safe_str(query.get("use_case"), default_use_case_by_category.get(category, "Performance Monitoring")),
            "category": category,
            "spl": normalized_spl,
            "finding_reference": finding_ref or (matching_finding.get("reference") if matching_finding else "Discovery-derived finding"),
            "execution_time": _safe_str(query.get("execution_time"), "< 30s"),
            "business_value": _safe_str(query.get("business_value"), "Provides measurable visibility into operational and risk posture."),
            "priority": priority,
            "difficulty": _safe_str(query.get("difficulty"), "Intermediate"),
            "environment_evidence": evidence,
            "query_source": _safe_str(query.get("query_source"), "ai_finding")
        }

    def _context_engine_queries(finding_pool: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        anchor_index = _preferred_anchor_index()
        anchor_sourcetype = discovered_sourcetypes_list[0] if discovered_sourcetypes_list else "*"
        anchor_host = discovered_hosts_list[0] if discovered_hosts_list else "*"

        candidates = [
            {
                "title": "📈 Data Throughput & Coverage Drift",
                "description": "Track ingestion drift by index and sourcetype to detect sudden blind spots.",
                "use_case": "Performance Monitoring",
                "category": "Infrastructure & Performance",
                "spl": f"index={anchor_index} earliest=-24h | bin _time span=1h | stats count dc(host) as hosts dc(sourcetype) as sourcetypes by _time | eval ingestion_risk=if(count<100,'review','ok')",
                "finding_reference": (finding_pool[0]["reference"] if finding_pool else "Coverage and ingestion monitoring"),
                "execution_time": "< 30s",
                "business_value": "Flags ingestion degradation early before detections lose fidelity.",
                "priority": "🔴 HIGH",
                "difficulty": "Intermediate",
                "query_source": "context_engine"
            },
            {
                "title": "🛡️ Security Signal Health by Sourcetype",
                "description": "Validate that expected security telemetry is present and consistent.",
                "use_case": "Security Investigation",
                "category": "Security & Compliance",
                "spl": f"index={anchor_index} sourcetype={anchor_sourcetype} earliest=-24h | stats count by sourcetype host | sort - count",
                "finding_reference": "Risk validation for security monitoring coverage.",
                "execution_time": "< 30s",
                "business_value": "Confirms security-useful data remains searchable and complete.",
                "priority": "🔴 HIGH",
                "difficulty": "Beginner",
                "query_source": "context_engine"
            },
            {
                "title": "🧪 Unknown Entity Validation",
                "description": "Profile volume and spread for unknown entities requiring classification.",
                "use_case": "Data Quality",
                "category": "Data Quality",
                "spl": f"index={anchor_index} host={anchor_host} earliest=-7d | stats count by sourcetype host index | sort - count",
                "finding_reference": "Unknown entities need context before onboarding decisions.",
                "execution_time": "< 45s",
                "business_value": "Turns unknown data into actionable ownership and onboarding tasks.",
                "priority": "🟠 MEDIUM",
                "difficulty": "Intermediate",
                "query_source": "context_engine"
            },
            {
                "title": "📊 Hotspot Trend for High-Risk Sources",
                "description": "Trend high-volume sources to identify accelerating operational or risk hotspots.",
                "use_case": "Capacity Planning",
                "category": "Capacity Planning",
                "spl": f"index={anchor_index} earliest=-14d | timechart span=1d count by sourcetype limit=10 useother=true",
                "finding_reference": "Trend and hotspot validation from discovery intelligence.",
                "execution_time": "< 60s",
                "business_value": "Supports capacity and risk planning with trend evidence.",
                "priority": "🟠 MEDIUM",
                "difficulty": "Intermediate",
                "query_source": "context_engine"
            }
        ]
        return candidates

    def _normalize_task_item(task: Dict[str, Any], idx: int, finding_pool: List[Dict[str, str]]) -> Dict[str, Any]:
        if not isinstance(task, dict):
            task = {}

        priority_raw = _safe_str(task.get("priority"), "MEDIUM").upper()
        if priority_raw not in {"HIGH", "MEDIUM", "LOW"}:
            priority_raw = "MEDIUM"

        category_raw = _safe_str(task.get("category"), "Configuration")
        valid_categories = {"Security", "Performance", "Compliance", "Data Quality", "Configuration"}
        if category_raw not in valid_categories:
            category_raw = "Configuration"

        steps_raw = task.get("steps") if isinstance(task.get("steps"), list) else []
        normalized_steps: List[Dict[str, Any]] = []
        for step_idx, step in enumerate(steps_raw[:6]):
            if isinstance(step, str):
                normalized_steps.append({
                    "number": step_idx + 1,
                    "action": _safe_str(step, f"Step {step_idx + 1}"),
                    "spl": ""
                })
                continue
            if not isinstance(step, dict):
                continue
            step_spl = _strip_code_fence(_safe_str(step.get("spl")))
            if step_spl:
                step_spl = _anchor_spl_to_environment(step_spl)
            normalized_steps.append({
                "number": int(step.get("number", step_idx + 1)) if str(step.get("number", "")).isdigit() else step_idx + 1,
                "action": _safe_str(step.get("action"), f"Step {step_idx + 1}"),
                "spl": step_spl
            })

        if not normalized_steps:
            anchor_index = _preferred_anchor_index()
            normalized_steps = [
                {"number": 1, "action": "Baseline current state and affected entities.", "spl": f"index={anchor_index} earliest=-24h | stats count by sourcetype host | sort - count"},
                {"number": 2, "action": "Apply the remediation/update described by the task.", "spl": ""},
                {"number": 3, "action": "Re-run validation and compare to baseline.", "spl": f"index={anchor_index} earliest=-24h | timechart span=1h count"}
            ]

        verification_spl = _strip_code_fence(_safe_str(task.get("verification_spl")))
        if verification_spl:
            verification_spl = _anchor_spl_to_environment(verification_spl)
        elif normalized_steps and _safe_str(normalized_steps[0].get("spl")):
            verification_spl = _safe_str(normalized_steps[0].get("spl"))
        else:
            verification_spl = f"index={_preferred_anchor_index()} earliest=-24h | stats count as post_change_events"

        evidence_blob = verification_spl + " " + " ".join(_safe_str(step.get("spl")) for step in normalized_steps)
        evidence = _extract_environment_evidence(evidence_blob)

        matching_finding = finding_pool[idx] if idx < len(finding_pool) else (finding_pool[0] if finding_pool else None)

        return {
            "title": _safe_str(task.get("title"), f"Contextual remediation task {idx + 1}"),
            "priority": priority_raw,
            "category": category_raw,
            "description": _safe_str(task.get("description"), "Apply this action to reduce risk and improve telemetry quality in your environment."),
            "prerequisites": task.get("prerequisites") if isinstance(task.get("prerequisites"), list) and task.get("prerequisites") else ["Search access to affected indexes", "Change window approval if production-impacting"],
            "steps": normalized_steps,
            "verification_spl": verification_spl,
            "expected_outcome": _safe_str(task.get("expected_outcome"), "Improved stability, visibility, and measurable reduction in the targeted risk."),
            "impact": _safe_str(task.get("impact"), "Improves operational confidence and lowers blind-spot risk."),
            "estimated_time": _safe_str(task.get("estimated_time"), "1-2 hours"),
            "rollback": _safe_str(task.get("rollback"), "Revert configuration changes and re-run baseline query for validation."),
            "environment_evidence": evidence,
            "finding_reference": matching_finding.get("reference") if matching_finding else "Discovery-derived finding"
        }

    def _context_engine_tasks(finding_pool: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        anchor_index = _preferred_anchor_index()
        security_ref = next((f for f in finding_pool if f.get("domain") == "Security & Compliance"), None)
        perf_ref = next((f for f in finding_pool if f.get("domain") == "Infrastructure & Performance"), None)
        quality_ref = next((f for f in finding_pool if f.get("domain") == "Data Quality"), None)

        return [
            {
                "title": "Establish telemetry health baseline and anomaly guardrails",
                "priority": "HIGH",
                "category": "Data Quality",
                "description": "Create a repeatable baseline for ingestion, source diversity, and volatility so regressions can be detected quickly.",
                "prerequisites": ["Access to search indexes", "Agreement on baseline thresholds"],
                "steps": [
                    {"number": 1, "action": "Capture baseline counts by index/sourcetype/host.", "spl": f"index={anchor_index} earliest=-24h | stats count dc(host) as hosts dc(sourcetype) as sourcetypes by index"},
                    {"number": 2, "action": "Define alert thresholds for low-volume or missing data windows."},
                    {"number": 3, "action": "Schedule recurring baseline checks and ownership review."}
                ],
                "verification_spl": f"index={anchor_index} earliest=-24h | timechart span=1h count by sourcetype limit=10",
                "expected_outcome": "Daily and hourly telemetry baselines exist with alertable thresholds.",
                "impact": "Reduces blind spots and shortens mean-time-to-detection for ingestion failures.",
                "estimated_time": "2 hours",
                "rollback": "Remove scheduled checks and revert threshold configs.",
                "finding_reference": (quality_ref or perf_ref or security_ref or {"reference": "Discovery trend validation"}).get("reference")
            },
            {
                "title": "Validate high-risk security signal coverage",
                "priority": "HIGH",
                "category": "Security",
                "description": "Ensure critical security sourcetypes and hosts are consistently represented and searchable.",
                "prerequisites": ["Security data owner mapping", "Access to relevant security indexes"],
                "steps": [
                    {"number": 1, "action": "Measure signal consistency by sourcetype and host.", "spl": f"index={anchor_index} earliest=-7d | stats count by sourcetype host | sort - count"},
                    {"number": 2, "action": "Identify missing/low-volume sources and assign remediation owners."},
                    {"number": 3, "action": "Re-run signal consistency query after remediation."}
                ],
                "verification_spl": f"index={anchor_index} earliest=-24h | stats dc(host) as active_hosts dc(sourcetype) as active_sourcetypes",
                "expected_outcome": "Critical security signals are present with stable source coverage.",
                "impact": "Improves detection reliability and reduces high-severity monitoring gaps.",
                "estimated_time": "3 hours",
                "rollback": "Revert onboarding/filter changes and restore previous source routing.",
                "finding_reference": (security_ref or quality_ref or perf_ref or {"reference": "Security risk validation"}).get("reference")
            },
            {
                "title": "Operationalize recursive risk verification loop",
                "priority": "MEDIUM",
                "category": "Configuration",
                "description": "Convert discovery risks into a repeatable review loop with measurable closure criteria.",
                "prerequisites": ["Risk owner assignment", "Weekly review cadence"],
                "steps": [
                    {"number": 1, "action": "Map each top risk to a validation query and owner.", "spl": f"index={anchor_index} earliest=-14d | timechart span=1d count by sourcetype"},
                    {"number": 2, "action": "Track unresolved items and escalation age."},
                    {"number": 3, "action": "Review weekly deltas and close or re-prioritize risks."}
                ],
                "verification_spl": f"index={anchor_index} earliest=-7d | stats count by host sourcetype",
                "expected_outcome": "Each risk has owner, evidence query, and clear closure criteria.",
                "impact": "Builds predictable risk reduction and continuous improvement.",
                "estimated_time": "1 day",
                "rollback": "Disable loop schedule and revert to ad-hoc review model.",
                "finding_reference": (perf_ref or security_ref or quality_ref or {"reference": "Recursive risk reduction"}).get("reference")
            }
        ]
    
    findings_prompt = f"""Analyze these Splunk V2 discovery artifacts and extract specific, actionable findings.

**Executive Summary:**
{executive_summary[:3000]}

**Detailed Findings:**
{detailed_findings[:3000]}

**Classification Report:**
{classification_report[:2000]}

**Discovered Indexes:** {', '.join(discovered_indexes_list[:20])}
**Discovered Sourcetypes:** {', '.join(discovered_sourcetypes_list[:30])}
**Discovered Hosts:** {', '.join(discovered_hosts_list[:20])}

Extract specific findings in these categories:
1. **Security Issues** (failed logins, suspicious activity, missing security monitoring)
2. **Performance Issues** (high CPU/memory/disk, slow queries, bottlenecks)
3. **Data Quality Issues** (missing data, parsing errors, empty indexes, data gaps)
4. **Optimization Opportunities** (retention policies, acceleration, index consolidation)
5. **Compliance Gaps** (missing audit logs, retention violations, access control issues)
6. **Trend Signals** (behavior shifts over time windows, emerging hot spots)
7. **Risk & Vulnerability Hypotheses** (areas needing recursive validation)

For each finding, provide:
- **Type**: Specific issue type
- **Severity**: critical/high/medium/low
- **Description**: What was found (include specific numbers, indexes, sourcetypes when mentioned)
- **Affected_Resources**: Specific indexes, sourcetypes, or hosts mentioned
- **Metric**: Specific number/percentage if available
- **Recommendation**: How to investigate or fix it

Return as JSON:
{{
  "security_findings": [
    {{"type": "...", "severity": "...", "description": "...", "affected_resources": [...], "metric": "...", "recommendation": "..."}}
  ],
  "performance_findings": [...],
  "data_quality_findings": [...],
  "optimization_findings": [...],
    "compliance_findings": [...],
    "trend_findings": [...],
    "risk_hypotheses": [...]
}}

Focus on ACTUAL findings from the reports with SPECIFIC details. If no findings in a category, return empty array.
Return ONLY the JSON object."""

    # Update progress - starting AI analysis
    summarization_progress[timestamp] = {
        "stage": "ai_analysis",
        "progress": 65,
        "message": "AI analyzing findings (this may take 1-3 minutes)..."
    }
    
    try:
        # Use 25% of configured max_tokens for findings extraction
        findings_max_tokens = min(4000, int(config.llm.max_tokens * 0.25))
        findings_response = await llm_client.generate_response(
            prompt=findings_prompt,
            max_tokens=findings_max_tokens,
            temperature=0.3
        )
        
        # Parse JSON response
        import re
        json_match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', findings_response, re.DOTALL)
        if json_match:
            findings_json = json_match.group(1)
        else:
            json_match = re.search(r'(\{.*\})', findings_response, re.DOTALL)
            findings_json = json_match.group(1) if json_match else '{}'
        
        # Validate before parsing
        if not findings_json.strip():
            raise ValueError("Empty JSON response")
        
        ai_findings = json.loads(findings_json)
        print(f"AI extracted findings: {len(ai_findings.get('security_findings', []))} security, "
              f"{len(ai_findings.get('performance_findings', []))} performance, "
              f"{len(ai_findings.get('data_quality_findings', []))} data quality")
        
    except json.JSONDecodeError as e:
        print(f"Error parsing findings JSON: {e}")
        print(f"JSON string length: {len(findings_json) if 'findings_json' in locals() else 0}")
        print(f"Response length: {len(findings_response) if 'findings_response' in locals() else 0}")
        ai_findings = {
            "security_findings": [],
            "performance_findings": [],
            "data_quality_findings": [],
            "optimization_findings": [],
            "compliance_findings": [],
            "trend_findings": [],
            "risk_hypotheses": []
        }
    except Exception as e:
        print(f"Error extracting findings with AI: {e}")
        ai_findings = {
            "security_findings": [],
            "performance_findings": [],
            "data_quality_findings": [],
            "optimization_findings": [],
            "compliance_findings": [],
            "trend_findings": [],
            "risk_hypotheses": []
        }
    
    # Update progress - findings extracted
    summarization_progress[timestamp] = {
        "stage": "generating_queries",
        "progress": 75,
        "message": "AI generating SPL queries (1-2 minutes)..."
    }
    
    # ===== AI-POWERED QUERY GENERATION =====
    # Generate SPL queries based on actual findings
    query_generation_prompt = f"""Generate 8 SPL queries based on these Splunk findings.

Findings: {json.dumps(ai_findings, indent=2)[:2000]}

Environment Context: {json.dumps(environment_context_block, indent=2)[:2500]}

Return JSON array with exactly 8 queries. Each query must have:
- title: Clear, actionable title with emoji
- description: 1 sentence explaining the query
- use_case: Security Investigation, Performance Monitoring, Data Quality, or Capacity Planning
- category: Security & Compliance, Infrastructure & Performance, Data Quality, or Capacity Planning
- spl: Valid SPL query using actual indexes/sourcetypes/hosts from this specific environment context
- finding_reference: Which finding this addresses
- execution_time: Estimated time
- business_value: Why this matters
- priority: 🔴 HIGH, 🟠 MEDIUM, or 🟡 LOW
- difficulty: Beginner, Intermediate, or Advanced
- environment_evidence: array of specific discovered entities used (index/sourcetype/host)

NON-NEGOTIABLE RULES:
1) At least 7/8 queries must reference one or more discovered indexes or sourcetypes from Environment Context.
2) Do not use placeholders like index=main unless it exists in Environment Context.
3) Every query must be directly tied to a discovery finding or risk hypothesis.
4) Include time windows (`earliest=...`) and aggregation logic (`stats`, `timechart`, or `tstats`) for operational usefulness.
5) Avoid near-duplicate queries; each query should answer a distinct investigative question.

Example:
[{{"title": "🔍 Investigation Title", "description": "What this does", "use_case": "Security Investigation", "category": "Security & Compliance", "spl": "index=main | stats count", "finding_reference": "Specific finding", "execution_time": "< 30s", "business_value": "Why it matters", "priority": "🔴 HIGH", "difficulty": "Beginner"}}]

Return ONLY the JSON array of 8 queries, nothing else."""

    finding_based_queries = []
    try:
        # Use 50% of configured max_tokens for query generation (needs more for detailed queries)
        query_max_tokens = min(8000, int(config.llm.max_tokens * 0.5))
        
        # Debug: Check what we're sending to LLM
        print(f"DEBUG: Generating queries - {len(ai_findings.get('security_findings', []))} security, "
              f"{len(ai_findings.get('data_quality_findings', []))} data quality findings")
        print(f"DEBUG: Using {len(discovered_indexes)} indexes, {len(discovered_sourcetypes)} sourcetypes, "
              f"max_tokens={query_max_tokens}")
        
        queries_response = await llm_client.generate_response(
            prompt=query_generation_prompt,
            max_tokens=query_max_tokens,
            temperature=0.75  # Higher temperature for creative, varied query generation
        )
        
        print(f"DEBUG: LLM response length: {len(queries_response)}")
        print(f"DEBUG: Response starts with: {queries_response[:100]}")
        print(f"DEBUG: Response ends with: {queries_response[-100:]}")
        
        # Parse JSON response - try multiple extraction methods
        queries_json = None
        
        # Method 1: Extract from code block
        json_match = re.search(r'```(?:json)?\s*(\[.*\])\s*```', queries_response, re.DOTALL)
        if json_match:
            queries_json = json_match.group(1)
            print(f"DEBUG: Extracted from code block (length: {len(queries_json)})")
        
        # Method 2: Find JSON between first [ and last ]
        if not queries_json:
            first_bracket = queries_response.find('[')
            last_bracket = queries_response.rfind(']')
            if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket:
                queries_json = queries_response[first_bracket:last_bracket+1]
                print(f"DEBUG: Extracted by finding brackets (length: {len(queries_json)})")
        
        # Method 3: Empty array fallback
        if not queries_json:
            queries_json = '[]'
            print(f"DEBUG: No JSON array found, using empty array")
        
        print(f"DEBUG: Final JSON length: {len(queries_json)}")
        print(f"DEBUG: JSON starts with: {queries_json[:200]}")
        print(f"DEBUG: JSON ends with: {queries_json[-200:]}")
        
        # Validate before parsing
        if not queries_json.strip():
            raise ValueError("Empty JSON response")
        
        finding_based_queries = json.loads(queries_json)
        print(f"✅ AI generated {len(finding_based_queries)} finding-based queries")
        
        # Mark as finding-based
        for q in finding_based_queries:
            q['spl'] = _anchor_spl_to_environment(q.get('spl', ''))
            q['environment_evidence'] = q.get('environment_evidence') or _extract_environment_evidence(q.get('spl', ''))
            q['query_source'] = 'ai_finding'
        
    except json.JSONDecodeError as e:
        print(f"Error parsing queries JSON: {e}")
        print(f"JSON string length: {len(queries_json) if 'queries_json' in locals() else 0}")
        print(f"Response length: {len(queries_response) if 'queries_response' in locals() else 0}")
        # Try to salvage partial queries
        try:
            last_complete = queries_json.rfind('}')
            if last_complete > 0:
                salvaged_json = queries_json[:last_complete+1] + ']'
                finding_based_queries = json.loads(salvaged_json)
                print(f"Salvaged {len(finding_based_queries)} queries from truncated response")
                for q in finding_based_queries:
                    q['spl'] = _anchor_spl_to_environment(q.get('spl', ''))
                    q['environment_evidence'] = q.get('environment_evidence') or _extract_environment_evidence(q.get('spl', ''))
                    q['query_source'] = 'ai_finding'
            else:
                raise
        except:
            print("Could not salvage queries, will use templates")
            finding_based_queries = []
    except Exception as e:
        print(f"Error generating finding-based queries with AI: {e}")
        finding_based_queries = []
    
    # Normalize and enrich query set using finding-aware + context-engine strategies
    finding_pool = _flatten_findings(ai_findings)
    context_engine_query_candidates = _context_engine_queries(finding_pool)

    normalized_query_candidates: List[Dict[str, Any]] = []
    for idx, query_item in enumerate(finding_based_queries):
        if isinstance(query_item, dict):
            normalized_query_candidates.append(_normalize_query_item(query_item, idx, finding_pool))

    for idx, query_item in enumerate(context_engine_query_candidates):
        normalized_query_candidates.append(_normalize_query_item(query_item, len(normalized_query_candidates) + idx, finding_pool))

    for idx, template_query in enumerate(template_queries):
        if not isinstance(template_query, dict):
            continue
        template_copy = dict(template_query)
        template_copy["query_source"] = "template"
        normalized_query_candidates.append(_normalize_query_item(template_copy, len(normalized_query_candidates) + idx, finding_pool))

    deduped_queries: List[Dict[str, Any]] = []
    seen_query_keys = set()
    for query in normalized_query_candidates:
        key = re.sub(r"\s+", " ", _safe_str(query.get("spl"), "").lower()).strip()
        if not key:
            continue
        if key in seen_query_keys:
            continue
        seen_query_keys.add(key)
        deduped_queries.append(query)

    def _query_rank(query: Dict[str, Any]) -> Tuple[int, int, int, int]:
        source_rank = 0 if query.get("query_source") == "ai_finding" else 1 if query.get("query_source") == "context_engine" else 2
        priority_rank = 0 if str(query.get("priority", "")).startswith("🔴") else 1 if str(query.get("priority", "")).startswith("🟠") else 2
        evidence_rank = -len(query.get("environment_evidence", []) if isinstance(query.get("environment_evidence", []), list) else [])
        complexity_rank = -len(_safe_str(query.get("spl"), ""))
        return (source_rank, priority_rank, evidence_rank, complexity_rank)

    deduped_queries.sort(key=_query_rank)
    queries = deduped_queries[:10]

    # Ensure minimum query volume and environment anchoring
    if len(queries) < 8:
        for candidate in deduped_queries[10:]:
            queries.append(candidate)
            if len(queries) >= 8:
                break

    print(f"📊 Query Status: AI raw={len(finding_based_queries)}, context_engine={len(context_engine_query_candidates)}, template={len(template_queries)}, final={len(queries)}")
    
    # Debug: Show query sources
    ai_query_count = sum(1 for q in queries if q.get('query_source') == 'ai_finding')
    template_query_count = sum(1 for q in queries if q.get('query_source') == 'template')
    print(f"📝 Final query breakdown: {ai_query_count} AI-generated, {template_query_count} template-based")
    
    # Prioritize queries (AI findings first, then by priority)
    queries.sort(key=lambda q: (
        0 if q.get('query_source') == 'ai_finding' else 1,  # AI findings first
        0 if q.get('priority', '').startswith('🔴') else 
        1 if q.get('priority', '').startswith('🟠') else
        2 if q.get('priority', '').startswith('🟡') else 3,  # Then by priority
        -len(q.get('spl', ''))  # Then by complexity
    ))
    
    # Update progress - AI summary generation
    summarization_progress[timestamp] = {
        "stage": "generating_summary",
        "progress": 70,
        "message": "Building executive summary..."
    }
    
    # Generate AI summary
    config = config_manager.get()
    llm_client = get_or_create_llm_client(config)
    
    # Get current date for temporal context
    from datetime import datetime
    current_date = datetime.now().strftime("%B %d, %Y")
    
    summary_prompt = f"""You are analyzing a Splunk V2 intelligence report. Create a high-value executive summary.

**IMPORTANT CONTEXT:** Today's date is {current_date}. Any timestamps in the reports should be interpreted relative to this date, not as future dates.

**Discovery Reports:**
{executive_summary[:3000]}

**Key Findings:**
{detailed_findings[:2000]}

**Data Classification:**
{classification_report[:2000]}

Please provide:
1. **Executive Summary** (3-4 sentences highlighting most important findings based on ACTUAL data in reports)
2. **Priority Actions** (Top 3 immediate actions the admin should take)
3. **Quick Wins** (2-3 easy implementations with high impact)
4. **Risk Areas** (Any security or compliance gaps identified)
5. **Trend Story** (what appears to be changing, increasing, or degrading)
6. **Recursive Next Loop** (what should be re-checked in the next discovery cycle)

Keep it concise and actionable. Focus on business value, risk reduction, and measurable outcomes. Base all statements on actual data from the reports above."""
    
    # Update progress - creating summary
    summarization_progress[timestamp] = {
        "stage": "creating_summary",
        "progress": 82,
        "message": "AI creating executive summary (30-60 seconds)..."
    }
    
    try:
        # Use 15% of configured max_tokens for executive summary (concise output)
        summary_max_tokens = min(2000, int(config.llm.max_tokens * 0.15))
        ai_summary = await llm_client.generate_response(
            prompt=summary_prompt,
            max_tokens=summary_max_tokens,
            temperature=0.7
        )
    except Exception as e:
        ai_summary = f"Could not generate AI summary: {str(e)}"
    
    # Update progress - Admin tasks generation
    summarization_progress[timestamp] = {
        "stage": "generating_tasks",
        "progress": 88,
        "message": "AI generating admin tasks (1-2 minutes)..."
    }
    
    # ===== ADMIN TASK GENERATION =====
    # Generate actionable admin tasks based on findings
    admin_tasks = []
    
    tasks_prompt = f"""Based on the Splunk discovery analysis below, generate a prioritized list of implementation tasks for the Splunk administrator.

**Discovery Reports:**
{executive_summary[:2500]}

**Key Findings:**
{detailed_findings[:2000]}

**Environment Context (use this explicitly):**
{json.dumps(environment_context_block, indent=2)[:2500]}

For each task, provide:
1. **Title**: Clear, action-oriented task name
2. **Priority**: HIGH/MEDIUM/LOW based on impact and urgency
3. **Category**: Security/Performance/Compliance/Data Quality/Configuration
4. **Description**: 2-3 sentences explaining why this task matters
5. **Prerequisites**: What's needed before starting (e.g., admin access, specific licenses)
6. **Steps**: 3-5 specific implementation steps with SPL queries where applicable
7. **Verification SPL**: A query to verify the task was completed successfully (use standard SPL commands like 'search', 'stats', 'tstats' - avoid 'rest' or admin-only commands)
8. **Expected Outcome**: What should be true after successful implementation
9. **Impact**: Business value and ROI of completing this task
10. **Estimated Time**: Realistic time estimate (e.g., "30 minutes", "2 hours", "1 day")

IMPORTANT: Verification queries should use standard SPL commands (search, stats, tstats, timechart) that any user can run.
Avoid using administrative commands like 'rest', 'inputlookup' on system lookups, or commands requiring special permissions.

Focus on:
- Tasks that address identified gaps or risks
- Quick wins with high impact
- Security improvements
- Data quality enhancements
- Performance optimizations

HARD REQUIREMENTS:
- At least 3 tasks must include SPL that references discovered indexes/sourcetypes/hosts from Environment Context.
- Verification SPL must validate outcomes against environment-specific telemetry.

Return ONLY a valid JSON array of task objects. Each task should follow this structure:
{{
  "title": "Task name",
  "priority": "HIGH|MEDIUM|LOW",
  "category": "Security|Performance|Compliance|Data Quality|Configuration",
  "description": "Why this matters...",
  "prerequisites": ["requirement 1", "requirement 2"],
  "steps": [
    {{"number": 1, "action": "Step description", "spl": "optional SPL query"}},
    {{"number": 2, "action": "Step description", "spl": "optional SPL query"}}
  ],
  "verification_spl": "SPL query to verify completion",
  "expected_outcome": "What should be true after completion",
  "impact": "Business value description",
  "estimated_time": "time estimate",
  "rollback": "How to undo if needed"
}}

Generate 6-8 prioritized tasks. Keep each task concise but actionable.
At least 4 tasks must include verification SPL anchored to discovered indexes/sourcetypes/hosts.
Return ONLY the JSON array, no other text."""

    try:
        # Use 50% of configured max_tokens for admin tasks to allow comprehensive responses
        # (tasks require detailed JSON with multiple fields per task)
        task_max_tokens = min(8000, int(config.llm.max_tokens * 0.5))
        tasks_response = await llm_client.generate_response(
            prompt=tasks_prompt,
            max_tokens=task_max_tokens,
            temperature=0.6
        )
        
        # Parse JSON response
        import re
        # Extract JSON array from response (handle markdown code blocks)
        json_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', tasks_response, re.DOTALL)
        if json_match:
            tasks_json = json_match.group(1)
        else:
            # Try to find raw JSON array
            json_match = re.search(r'(\[.*\])', tasks_response, re.DOTALL)
            tasks_json = json_match.group(1) if json_match else '[]'
        
        # Validate it's valid JSON before parsing
        if not tasks_json.strip():
            raise ValueError("Empty JSON response")
        
        admin_tasks = json.loads(tasks_json)
        print(f"Generated {len(admin_tasks)} admin tasks")
        
        # Update progress - Tasks generated successfully
        summarization_progress[timestamp] = {
            "stage": "finalizing",
            "progress": 93,
            "message": "Finalizing summary..."
        }
        
    except json.JSONDecodeError as e:
        print(f"Error parsing admin tasks JSON: {e}")
        print(f"JSON string length: {len(tasks_json) if 'tasks_json' in locals() else 0}")
        print(f"Raw response (first 1000 chars): {tasks_response[:1000] if 'tasks_response' in locals() else 'No response'}")
        print(f"Raw response (last 500 chars): {tasks_response[-500:] if 'tasks_response' in locals() else 'No response'}")
        # Try to salvage partial tasks
        try:
            # Find the last complete task object
            last_complete = tasks_json.rfind('}')
            if last_complete > 0:
                # Try to close the array
                salvaged_json = tasks_json[:last_complete+1] + ']'
                admin_tasks = json.loads(salvaged_json)
                print(f"Salvaged {len(admin_tasks)} tasks from truncated response")
            else:
                raise
        except:
            print("Could not salvage tasks, using default task")
            # Use default task when salvage fails
            admin_tasks = []
    except Exception as e:
        print(f"Error generating admin tasks: {e}")
        print(f"Raw response: {tasks_response[:500] if 'tasks_response' in locals() else 'No response'}")
        # Create default tasks based on common findings
        admin_tasks = []

    # Normalize + enrich admin tasks with context-engine supplement
    context_engine_tasks = _context_engine_tasks(finding_pool)
    normalized_task_candidates: List[Dict[str, Any]] = []
    for idx, task in enumerate(admin_tasks):
        normalized_task_candidates.append(_normalize_task_item(task, idx, finding_pool))
    for idx, task in enumerate(context_engine_tasks):
        normalized_task_candidates.append(_normalize_task_item(task, len(normalized_task_candidates) + idx, finding_pool))

    deduped_tasks: List[Dict[str, Any]] = []
    seen_task_titles = set()
    for task in normalized_task_candidates:
        title_key = _safe_str(task.get("title"), "").lower()
        if not title_key or title_key in seen_task_titles:
            continue
        seen_task_titles.add(title_key)
        deduped_tasks.append(task)

    def _task_rank(task: Dict[str, Any]) -> Tuple[int, int]:
        priority = _safe_str(task.get("priority"), "MEDIUM").upper()
        priority_rank = 0 if priority == "HIGH" else 1 if priority == "MEDIUM" else 2
        evidence_rank = -len(task.get("environment_evidence", []) if isinstance(task.get("environment_evidence", []), list) else [])
        return (priority_rank, evidence_rank)

    deduped_tasks.sort(key=_task_rank)
    admin_tasks = deduped_tasks[:6]
    if not admin_tasks:
        admin_tasks = [_normalize_task_item(task, idx, finding_pool) for idx, task in enumerate(context_engine_tasks[:3])]

    print(f"📋 Task Status: ai_raw={len(normalized_task_candidates) - len(context_engine_tasks)}, context_engine={len(context_engine_tasks)}, final={len(admin_tasks)}")

    context_explorer = build_context_explorer_payload(
        discovery_data,
        unknown_questions=unknown_questions,
        admin_tasks=admin_tasks,
        coverage_gaps=coverage_gaps,
        risk_register=risk_register,
        readiness_score=readiness_score,
    )
    
    # Prepare response
    response_data = {
        "success": True,
        "session_id": timestamp,
        "schema_version": "2.0",
        "ai_summary": ai_summary,
        "spl_queries": queries,
        "admin_tasks": admin_tasks,
        "unknown_data": unknown_questions,
        "readiness_score": readiness_score,
        "coverage_gaps": coverage_gaps,
        "risk_register": risk_register,
        "trend_signals": trend_signals,
        "vulnerability_hypotheses": vulnerability_hypotheses,
        "recursive_investigations": recursive_investigations,
        "context_explorer": context_explorer,
        "v2_context": {
            "readiness_score": readiness_score,
            "coverage_gaps": len(coverage_gaps),
            "risk_register": len(risk_register),
            "recursive_investigations": len(recursive_investigations)
        },
        "stats": {
            "total_queries": len(queries),
            "total_tasks": len(admin_tasks),
            "unknown_items": len(unknown_questions),
            "categories": list({q.get('category', 'General') for q in queries if isinstance(q, dict)})
        },
        "from_cache": False
    }
    
    # Update progress - Saving results
    summarization_progress[timestamp] = {
        "stage": "saving",
        "progress": 95,
        "message": "Saving results..."
    }
    
    # Save summary for future use
    try:
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2)
        print(f"Saved summary to {summary_file}")
    except Exception as e:
        print(f"Error saving summary: {e}")
        # Don't fail the request if save fails
    
    # Update progress - Complete
    summarization_progress[timestamp] = {
        "stage": "complete",
        "progress": 100,
        "message": "Analysis complete!"
    }
    
    # Clean up progress after a delay (async cleanup)
    import asyncio
    async def cleanup_progress():
        await asyncio.sleep(2)  # Keep visible for 2 seconds
        if timestamp in summarization_progress:
            del summarization_progress[timestamp]
    
    asyncio.create_task(cleanup_progress())
    
    return response_data


@app.post("/verify-task")
async def verify_task(request: Dict[str, Any]):
    """
    Execute verification SPL query and analyze results against expected outcome.
    
    Request:
    {
        "session_id": "20251027_165208",
        "task_index": 0,
        "verification_spl": "| rest /services/data/indexes | search disabled=1 | stats count",
        "expected_outcome": "Zero or minimal disabled indexes remaining"
    }
    
    Response:
    {
        "status": "success|partial|failed",
        "message": "Detailed explanation",
        "results": {...},  # Raw SPL results
        "recommendations": [...],  # If partial/failed
        "metrics": {
            "before": "...",
            "after": "...",
            "improvement": "..."
        }
    }
    """
    try:
        # Validate inputs
        session_id = request.get("session_id")
        task_index = request.get("task_index")
        verification_spl = request.get("verification_spl")
        expected_outcome = request.get("expected_outcome")
        
        if not all([session_id, verification_spl, expected_outcome]):
            return {"error": "Missing required fields"}
        
        # Validate session ID format
        try:
            safe_session_id = validate_session_id(session_id)
        except HTTPException as e:
            return {"error": str(e.detail)}
        
        # Validate task index
        try:
            safe_task_index = int(task_index) if task_index is not None else None
            if safe_task_index is not None and (safe_task_index < 0 or safe_task_index > 1000):
                return {"error": "Invalid task index"}
        except (ValueError, TypeError):
            return {"error": "Task index must be a number"}
        
        # Load configuration
        config = config_manager.get()
        
        # Execute SPL via MCP
        print(f"Executing verification SPL for task {task_index}...")
        
        mcp_tool_call = {
            "method": "tools/call",
            "params": {
                "name": "splunk_run_query",
                "arguments": {
                    "query": verification_spl,
                    "earliest_time": "-24h",
                    "latest_time": "now"
                }
            }
        }
        
        spl_result = await execute_mcp_tool_call(mcp_tool_call, config)
        
        if "error" in spl_result:
            return {
                "status": "error",
                "message": f"Failed to execute verification query: {spl_result['error']}",
                "results": None
            }
        
        # Analyze results with AI
        llm_client = get_or_create_llm_client(config)
        
        analysis_prompt = f"""You are analyzing the results of a Splunk admin task verification.

**Task Verification:**
Expected Outcome: {expected_outcome}

**SPL Query Executed:**
{verification_spl}

**Query Results:**
{json.dumps(spl_result, indent=2)[:2000]}

**Analysis Instructions:**
1. Determine if the task was completed successfully based on the expected outcome
2. Classify the result as: SUCCESS, PARTIAL, or FAILED
3. Provide specific metrics comparing the current state to the expected outcome
4. If PARTIAL or FAILED, provide actionable recommendations

Return a JSON object with this structure:
{{
  "status": "success|partial|failed",
  "message": "Clear explanation of the verification result",
  "metrics": {{
    "current_value": "What the query found",
    "expected_value": "What was expected",
    "gap": "What's missing (if any)"
  }},
  "recommendations": ["step 1", "step 2"] // Only if partial/failed
}}

Return ONLY the JSON object, no other text."""

        try:
            # Use 10% of configured max_tokens for verification analysis (smaller response)
            analysis_max_tokens = min(1000, int(config.llm.max_tokens * 0.1))
            analysis_response = await llm_client.generate_response(
                prompt=analysis_prompt,
                max_tokens=analysis_max_tokens,
                temperature=0.3  # Lower temperature for more consistent analysis
            )
            
            # Parse JSON response
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', analysis_response, re.DOTALL)
            if json_match:
                analysis_json = json_match.group(1)
            else:
                json_match = re.search(r'(\{.*\})', analysis_response, re.DOTALL)
                analysis_json = json_match.group(1) if json_match else '{}'
            
            analysis = json.loads(analysis_json)
            
        except Exception as e:
            print(f"Error analyzing verification results: {e}")
            # Fallback analysis
            analysis = {
                "status": "unknown",
                "message": f"Could not analyze results automatically. Raw results available for manual review.",
                "metrics": {},
                "recommendations": ["Review the query results manually", "Ensure the SPL query is correct"]
            }
        
        # Combine SPL results with AI analysis
        response = {
            **analysis,
            "results": spl_result,
            "verification_spl": verification_spl,
            "expected_outcome": expected_outcome,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save verification result - use session timestamp to group with other reports
        output_dir = Path("output")
        verification_file = output_dir / f"verification_task{task_index}_{session_id}.json"
        try:
            with open(verification_file, 'w', encoding='utf-8') as f:
                json.dump(response, f, indent=2)
            print(f"Saved verification result to {verification_file}")
        except Exception as e:
            print(f"Error saving verification: {e}")
        
        return response
        
    except Exception as e:
        print(f"Error in verify_task: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": f"Verification failed: {str(e)}",
            "results": None
        }


@app.post("/get-remediation")
async def get_remediation(request: Dict[str, Any]):
    """
    Generate AI-powered remediation steps for failed/partial verification.
    
    Request:
    {
        "session_id": "20251027_165208",
        "task_index": 0,
        "task_details": {...},
        "verification_result": {...}
    }
    
    Response:
    {
        "remediation_steps": [...],
        "root_cause": "...",
        "estimated_time": "...",
        "success_probability": "high|medium|low"
    }
    """
    try:
        # Validate inputs
        session_id = request.get("session_id")
        task_index = request.get("task_index")
        task_details = request.get("task_details")
        verification_result = request.get("verification_result")
        
        if not all([session_id, task_details, verification_result]):
            return {"error": "Missing required fields"}
        
        # Validate session ID format
        try:
            safe_session_id = validate_session_id(session_id)
        except HTTPException as e:
            return {"error": str(e.detail)}
        
        # Validate task index
        try:
            safe_task_index = int(task_index) if task_index is not None else None
            if safe_task_index is not None and (safe_task_index < 0 or safe_task_index > 1000):
                return {"error": "Invalid task index"}
        except (ValueError, TypeError):
            return {"error": "Task index must be a number"}
        
        # Load configuration
        config = config_manager.get()
        
        # Generate remediation with AI
        llm_client = get_or_create_llm_client(config)
        
        remediation_prompt = f"""You are a Splunk expert helping an administrator troubleshoot a failed task.

**Task Details:**
Title: {task_details.get('title', 'Unknown')}
Priority: {task_details.get('priority', 'Unknown')}
Category: {task_details.get('category', 'Unknown')}
Description: {task_details.get('description', 'No description')}

**Original Steps Taken:**
{json.dumps(task_details.get('steps', []), indent=2)}

**Verification Results:**
Status: {verification_result.get('status', 'unknown')}
Message: {verification_result.get('message', 'No message')}
Metrics: {json.dumps(verification_result.get('metrics', {}), indent=2)}
Current Recommendations: {json.dumps(verification_result.get('recommendations', []), indent=2)}

**Your Task:**
Analyze why the verification failed and provide detailed remediation guidance.

Return a JSON object with:
{{
  "root_cause": "Primary reason for failure (1-2 sentences)",
  "remediation_steps": [
    {{
      "number": 1,
      "action": "Detailed step description",
      "spl": "SPL query if applicable (optional)",
      "explanation": "Why this step helps",
      "risk": "low|medium|high"
    }}
  ],
  "estimated_time": "Realistic time to complete remediation",
  "success_probability": "high|medium|low",
  "preventive_measures": ["How to avoid this issue in the future"],
  "alternative_approaches": ["Other ways to accomplish the same goal"]
}}

Focus on actionable, specific steps. Include SPL queries where helpful.
Return ONLY the JSON object."""

        try:
            # Use 15% of configured max_tokens for remediation steps
            remediation_max_tokens = min(2000, int(config.llm.max_tokens * 0.15))
            remediation_response = await llm_client.generate_response(
                prompt=remediation_prompt,
                max_tokens=remediation_max_tokens,
                temperature=0.5
            )
            
            # Parse JSON response
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', remediation_response, re.DOTALL)
            if json_match:
                remediation_json = json_match.group(1)
            else:
                json_match = re.search(r'(\{.*\})', remediation_response, re.DOTALL)
                remediation_json = json_match.group(1) if json_match else '{}'
            
            remediation = json.loads(remediation_json)
            
        except Exception as e:
            print(f"Error generating remediation: {e}")
            # Fallback remediation
            remediation = {
                "root_cause": "Unable to automatically determine the root cause. Manual investigation required.",
                "remediation_steps": [
                    {
                        "number": 1,
                        "action": "Review the verification results and query output carefully",
                        "explanation": "Understanding what the query returned is the first step",
                        "risk": "low"
                    },
                    {
                        "number": 2,
                        "action": "Check Splunk logs for any related errors or warnings",
                        "spl": "index=_internal source=*splunkd.log ERROR OR WARN earliest=-1h",
                        "explanation": "System logs may reveal underlying issues",
                        "risk": "low"
                    },
                    {
                        "number": 3,
                        "action": "Consult Splunk documentation for the specific feature or configuration",
                        "explanation": "Official documentation may have troubleshooting steps",
                        "risk": "low"
                    }
                ],
                "estimated_time": "30-60 minutes",
                "success_probability": "medium",
                "preventive_measures": ["Regular monitoring", "Documentation of changes"],
                "alternative_approaches": ["Manual verification", "Consult Splunk support"]
            }
        
        # Add metadata
        remediation['session_id'] = session_id
        remediation['task_index'] = task_index
        remediation['timestamp'] = datetime.now().isoformat()
        
        # Save remediation
        output_dir = Path("output")
        remediation_file = output_dir / f"remediation_task{task_index}_{session_id}.json"
        try:
            with open(remediation_file, 'w', encoding='utf-8') as f:
                json.dump(remediation, f, indent=2)
            print(f"Saved remediation to {remediation_file}")
        except Exception as e:
            print(f"Error saving remediation: {e}")
        
        return remediation
        
    except Exception as e:
        print(f"Error in get_remediation: {e}")
        import traceback
        traceback.print_exc()
        return {
            "error": f"Failed to generate remediation: {str(e)}"
        }


@app.get("/verification-history/{session_id}/{task_index}")
async def get_verification_history(session_id: str, task_index: int):
    """
    Get verification history for a specific task, showing improvements over time.
    
    Response:
    {
        "verifications": [...],
        "remediations": [...],
        "success_rate": 0.75,
        "total_attempts": 4,
        "time_to_success": "2 hours",
        "improvement_trend": "improving|stable|declining"
    }
    """
    try:
        output_dir = Path("output")
        
        # Find all verification files for this task
        verification_pattern = f"verification_task{task_index}_{session_id}*.json"
        verification_files = sorted(output_dir.glob(verification_pattern))
        
        # Find all remediation files for this task
        remediation_pattern = f"remediation_task{task_index}_{session_id}*.json"
        remediation_files = sorted(output_dir.glob(remediation_pattern))
        
        verifications = []
        for vf in verification_files:
            try:
                with open(vf, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data['filename'] = vf.name
                    data['file_timestamp'] = datetime.fromtimestamp(vf.stat().st_mtime).isoformat()
                    verifications.append(data)
            except Exception as e:
                print(f"Error loading verification {vf}: {e}")
        
        remediations = []
        for rf in remediation_files:
            try:
                with open(rf, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data['filename'] = rf.name
                    data['file_timestamp'] = datetime.fromtimestamp(rf.stat().st_mtime).isoformat()
                    remediations.append(data)
            except Exception as e:
                print(f"Error loading remediation {rf}: {e}")
        
        # Calculate metrics
        total_attempts = len(verifications)
        successful = sum(1 for v in verifications if v.get('status') == 'success')
        success_rate = successful / total_attempts if total_attempts > 0 else 0
        
        # Determine improvement trend
        if total_attempts >= 2:
            recent_status = [v.get('status') for v in verifications[-3:]]
            if recent_status[-1] == 'success':
                trend = "improving"
            elif all(s == recent_status[0] for s in recent_status):
                trend = "stable"
            else:
                trend = "declining"
        else:
            trend = "insufficient_data"
        
        # Calculate time to success
        time_to_success = None
        if successful > 0:
            first_timestamp = datetime.fromisoformat(verifications[0].get('timestamp', datetime.now().isoformat()))
            success_timestamp = next((datetime.fromisoformat(v.get('timestamp', datetime.now().isoformat())) 
                                     for v in verifications if v.get('status') == 'success'), None)
            if success_timestamp:
                delta = success_timestamp - first_timestamp
                hours = delta.total_seconds() / 3600
                if hours < 1:
                    time_to_success = f"{int(delta.total_seconds() / 60)} minutes"
                else:
                    time_to_success = f"{hours:.1f} hours"
        
        return {
            "verifications": verifications,
            "remediations": remediations,
            "success_rate": success_rate,
            "total_attempts": total_attempts,
            "successful_attempts": successful,
            "time_to_success": time_to_success,
            "improvement_trend": trend
        }
        
    except Exception as e:
        print(f"Error in get_verification_history: {e}")
        import traceback
        traceback.print_exc()
        return {
            "error": f"Failed to get verification history: {str(e)}"
        }


@app.post("/chat/stream")
async def chat_with_splunk_stream(request: dict):
    """Stream chat responses with real-time status updates via SSE."""
    # Create a queue for status updates
    status_queue = asyncio.Queue()
    
    async def generate_sse():
        """Generator for Server-Sent Events."""
        try:
            # Process chat in background task
            chat_task = asyncio.create_task(
                process_chat_with_streaming(request, status_queue)
            )
            
            # Stream status updates as they come in
            while True:
                try:
                    # Wait for next status update with timeout
                    update = await asyncio.wait_for(status_queue.get(), timeout=0.1)
                    
                    if update['type'] == 'done':
                        # Send final response and close stream
                        yield f"data: {json.dumps({'type': 'response', 'data': update['data']})}\n\n"
                        break
                    elif update['type'] == 'error':
                        yield f"data: {json.dumps({'type': 'error', 'error': update['error']})}\n\n"
                        break
                    else:
                        # Send status update
                        yield f"data: {json.dumps(update)}\n\n"
                        
                except asyncio.TimeoutError:
                    # No new updates, send keepalive
                    yield ": keepalive\n\n"
                    
                    # Check if chat task is done
                    if chat_task.done():
                        break
                        
        except Exception as e:
            print(f"SSE Error: {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(generate_sse(), media_type="text/event-stream")


def load_latest_discovery_insights():
    """Load key insights from latest V2 artifacts for agent context."""
    knowledge = load_latest_report_knowledge(chat_session_settings.get("discovery_freshness_days", 7))
    if not knowledge:
        return None

    return {
        'summary_text': knowledge.get('executive_summary', ''),
        'structured': {
            'key_findings': knowledge.get('headline_findings', []),
            'recommendations': [
                rec.get('title') for rec in knowledge.get('recommendations', [])[:5]
                if isinstance(rec, dict) and rec.get('title')
            ],
            'data_patterns': knowledge.get('trend_signals', {}),
            'coverage_gaps': [
                gap.get('gap') for gap in knowledge.get('coverage_gaps', [])[:5]
                if isinstance(gap, dict) and gap.get('gap')
            ],
        },
        'age_days': knowledge.get('age_days', 0),
        'timestamp': knowledge.get('timestamp', ''),
    }


def _read_text_if_exists(path: Path, limit: Optional[int] = None) -> str:
    if not isinstance(path, Path) or not path.exists():
        return ""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ""
    if isinstance(limit, int) and limit > 0:
        return text[:limit]
    return text


def _read_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    text = _read_text_if_exists(path)
    if not text:
        return None
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _extract_markdown_section_items(markdown_text: str, heading: str, max_items: int = 4) -> List[str]:
    if not isinstance(markdown_text, str) or not markdown_text.strip():
        return []

    pattern = rf'##\s+{re.escape(heading)}\s*\n(.*?)(?:\n##\s+|\Z)'
    match = re.search(pattern, markdown_text, re.DOTALL | re.IGNORECASE)
    if not match:
        return []

    items: List[str] = []
    for line in match.group(1).splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        cleaned = re.sub(r'^[-*]\s+', '', cleaned)
        cleaned = re.sub(r'^\d+\.\s+', '', cleaned)
        cleaned = cleaned.strip()
        if cleaned:
            items.append(cleaned)
    return items[:max(1, max_items)]


def _parse_v2_notable_patterns(raw_patterns: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_patterns, list):
        return []

    for item in raw_patterns:
        payload = item
        if isinstance(item, str):
            try:
                payload = json.loads(item)
            except Exception:
                continue
        if isinstance(payload, dict) and isinstance(payload.get('patterns'), list):
            return [pattern for pattern in payload.get('patterns', []) if isinstance(pattern, dict)]
    return []


def _dedupe_ranked_entities(items: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    ranked = sorted(items, key=lambda item: item.get('events', 0), reverse=True)
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in ranked:
        name = str(item.get('name', '')).strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


def _rank_v2_entities(finding_ledger: Any, entity_type: str, limit: int = 6) -> List[Dict[str, Any]]:
    if not isinstance(finding_ledger, list):
        return []

    ranked: List[Dict[str, Any]] = []
    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue
        data = entry.get('data', {}) if isinstance(entry.get('data', {}), dict) else {}
        if not data:
            continue

        name = None
        events = 0
        size_mb = None

        if entity_type == 'indexes' and 'title' in data and 'totalEventCount' in data:
            name = data.get('title')
            events = _safe_int(data.get('totalEventCount'))
            size_mb = _safe_int(data.get('currentDBSizeMB'))
        elif entity_type == 'sourcetypes':
            name = data.get('sourcetype') or (data.get('title') if str(data.get('type', '')).lower() in {'sourcetypes', 'source_types'} else None)
            events = _safe_int(data.get('totalCount') or data.get('count') or data.get('eventCount'))
        elif entity_type == 'hosts':
            name = data.get('host') or data.get('hostname')
            events = _safe_int(data.get('totalCount') or data.get('count') or data.get('eventCount'))
        elif entity_type == 'sources':
            name = data.get('source')
            events = _safe_int(data.get('totalCount') or data.get('count') or data.get('eventCount'))

        if isinstance(name, str) and name.strip():
            entity = {
                'name': name.strip(),
                'events': events,
            }
            if size_mb is not None:
                entity['size_mb'] = size_mb
            if isinstance(data.get('recentTimeIso'), str):
                entity['recent_time'] = data.get('recentTimeIso')
            ranked.append(entity)

    return _dedupe_ranked_entities(ranked, limit=limit)


def _format_ranked_entities(items: List[Dict[str, Any]], include_size: bool = False) -> str:
    formatted: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        label = str(item.get('name', '')).strip()
        if not label:
            continue
        events = _safe_int(item.get('events'))
        if include_size and item.get('size_mb') is not None:
            formatted.append(f"{label} ({events:,} events, {item.get('size_mb')}MB)")
        else:
            formatted.append(f"{label} ({events:,} events)")
    return ', '.join(formatted)


def _extract_report_priority_actions(ai_summary_payload: Dict[str, Any]) -> List[str]:
    ai_summary_text = ai_summary_payload.get('ai_summary', '') if isinstance(ai_summary_payload, dict) else ''
    return _extract_markdown_section_items(ai_summary_text, 'Priority Actions', max_items=4)


def _extract_report_quick_wins(ai_summary_payload: Dict[str, Any]) -> List[str]:
    ai_summary_text = ai_summary_payload.get('ai_summary', '') if isinstance(ai_summary_payload, dict) else ''
    return _extract_markdown_section_items(ai_summary_text, 'Quick Wins', max_items=4)


def _build_report_viability(bundle: Dict[str, Any], staleness_days: int) -> Dict[str, Any]:
    timestamp = str(bundle.get('timestamp', '')).strip()
    age_days = 999
    try:
        if timestamp:
            bundle_time = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
            age_days = max(0, int((datetime.now() - bundle_time).total_seconds() / 86400))
    except Exception:
        age_days = 999

    blueprint = bundle.get('blueprint', {}) if isinstance(bundle.get('blueprint', {}), dict) else {}
    ai_summary = bundle.get('ai_summary', {}) if isinstance(bundle.get('ai_summary', {}), dict) else {}
    insights_text = bundle.get('insights_brief_text', '') if isinstance(bundle.get('insights_brief_text', ''), str) else ''

    score = 0
    reasons: List[str] = []

    if blueprint:
        score += 40
    else:
        reasons.append('Missing V2 intelligence blueprint')

    if insights_text or ai_summary:
        score += 20
    else:
        reasons.append('Missing summarized discovery narrative')

    if isinstance(blueprint.get('overview', {}), dict) and blueprint.get('overview'):
        score += 10
    else:
        reasons.append('Overview section is incomplete')

    if isinstance(blueprint.get('finding_ledger', []), list) and blueprint.get('finding_ledger'):
        score += 10
    else:
        reasons.append('Finding ledger is missing or empty')

    if isinstance(blueprint.get('recommendations', []), list) and blueprint.get('recommendations'):
        score += 10
    elif isinstance(ai_summary.get('risk_register', []), list) and ai_summary.get('risk_register'):
        score += 5
    else:
        reasons.append('Recommendations and risk register are thin')

    freshness_window = max(1, int(staleness_days))
    if age_days <= freshness_window:
        score += 10
    elif age_days <= freshness_window * 2:
        reasons.append(f'Discovery bundle is {age_days} days old')
    else:
        reasons.append(f'Discovery bundle is stale at {age_days} days old')

    has_core_artifacts = bool(blueprint) and bool(insights_text or ai_summary)
    fresh = age_days <= freshness_window
    usable = bool(blueprint) and score >= 45
    viable = has_core_artifacts and score >= 60 and fresh

    status = 'viable'
    if not viable and usable:
        status = 'stale' if has_core_artifacts else 'partial'
    elif not usable:
        status = 'partial'

    warning = None
    if status == 'stale':
        warning = f"⚠️ Discovery reports are {age_days} days old. Treat them as baseline context and validate live findings before acting."
    elif status == 'partial':
        warning = '⚠️ Discovery reports are incomplete. Strategic guidance is available, but it should be treated as partial context.'

    return {
        'timestamp': timestamp,
        'age_days': age_days,
        'score': score,
        'status': status,
        'fresh': fresh,
        'usable': usable,
        'viable': viable,
        'reasons': reasons,
        'warning': warning,
    }


def _build_report_knowledge(bundle: Dict[str, Any], viability: Dict[str, Any]) -> Dict[str, Any]:
    blueprint = bundle.get('blueprint', {}) if isinstance(bundle.get('blueprint', {}), dict) else {}
    ai_summary_payload = bundle.get('ai_summary', {}) if isinstance(bundle.get('ai_summary', {}), dict) else {}
    overview = blueprint.get('overview', {}) if isinstance(blueprint.get('overview', {}), dict) else {}
    finding_ledger = blueprint.get('finding_ledger', []) if isinstance(blueprint.get('finding_ledger', []), list) else []
    coverage_gaps = blueprint.get('coverage_gaps', []) if isinstance(blueprint.get('coverage_gaps', []), list) else ai_summary_payload.get('coverage_gaps', [])
    risk_register = blueprint.get('risk_register', []) if isinstance(blueprint.get('risk_register', []), list) else ai_summary_payload.get('risk_register', [])
    recommendations = blueprint.get('recommendations', []) if isinstance(blueprint.get('recommendations', []), list) else []
    suggested_use_cases = blueprint.get('suggested_use_cases', []) if isinstance(blueprint.get('suggested_use_cases', []), list) else []
    trend_signals = blueprint.get('trend_signals', {}) if isinstance(blueprint.get('trend_signals', {}), dict) else {}
    notable_patterns = _parse_v2_notable_patterns(overview.get('notable_patterns', []))
    top_indexes = _rank_v2_entities(finding_ledger, 'indexes', limit=6)
    top_sourcetypes = _rank_v2_entities(finding_ledger, 'sourcetypes', limit=6)
    top_hosts = _rank_v2_entities(finding_ledger, 'hosts', limit=6)
    top_sources = _rank_v2_entities(finding_ledger, 'sources', limit=6)
    priority_actions = _extract_report_priority_actions(ai_summary_payload)
    quick_wins = _extract_report_quick_wins(ai_summary_payload)

    executive_summary = ''
    if isinstance(ai_summary_payload.get('ai_summary'), str) and ai_summary_payload.get('ai_summary', '').strip():
        executive_summary = ai_summary_payload.get('ai_summary', '').strip()[:2400]
    elif isinstance(bundle.get('insights_brief_text', ''), str):
        executive_summary = bundle.get('insights_brief_text', '').strip()[:2400]

    headline_findings: List[str] = []
    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue
        findings = entry.get('findings', []) if isinstance(entry.get('findings', []), list) else []
        title = str(entry.get('title', '')).strip()
        if title and findings:
            headline_findings.append(title)
        for finding in findings[:2]:
            if isinstance(finding, str) and finding.strip():
                headline_findings.append(finding.strip())
        if len(headline_findings) >= 8:
            break
    headline_findings = list(dict.fromkeys(headline_findings))[:6]

    top_gap_titles = [gap.get('gap') for gap in coverage_gaps[:4] if isinstance(gap, dict) and gap.get('gap')]
    top_recommendation_titles = [rec.get('title') for rec in recommendations[:4] if isinstance(rec, dict) and rec.get('title')]
    top_risk_titles = [risk.get('risk') for risk in risk_register[:4] if isinstance(risk, dict) and risk.get('risk')]

    prompt_context_compact = "\n".join([
        '🔍 DISCOVERY KNOWLEDGE SNAPSHOT:',
        f"- Report viability: {viability.get('status', 'unknown')} (score {viability.get('score', 0)}/100, {viability.get('age_days', 0)} days old)",
        f"- Readiness score: {_safe_int(blueprint.get('readiness_score') or ai_summary_payload.get('readiness_score'))}/100",
        f"- Surface area: {overview.get('total_indexes', 0)} indexes, {overview.get('total_sourcetypes', 0)} sourcetypes, {overview.get('total_hosts', 0)} hosts, {overview.get('total_sources', 0)} sources, {overview.get('data_volume_24h', 'unknown')} over 24h",
        f"- Dominant indexes: {_format_ranked_entities(top_indexes[:4], include_size=True) or 'unknown'}",
        f"- Dominant sourcetypes: {_format_ranked_entities(top_sourcetypes[:4]) or 'unknown'}",
        f"- Highest-priority gaps: {', '.join(top_gap_titles[:4]) or 'none identified'}",
        f"- Highest-priority recommendations: {', '.join(top_recommendation_titles[:4]) or 'none identified'}",
    ]).strip()

    prompt_context_strategic = "\n".join([
        '📊 STRATEGIC REPORT CONTEXT:',
        f"- Top risks: {', '.join(top_risk_titles[:4]) or 'none identified'}",
        f"- Priority actions: {', '.join(priority_actions[:4]) or 'none extracted'}",
        f"- Quick wins: {', '.join(quick_wins[:3]) or 'none extracted'}",
        f"- Trend signals: evidence_steps={_safe_int(trend_signals.get('evidence_steps'))}, high_priority_recommendations={_safe_int(trend_signals.get('high_priority_recommendations'))}, coverage_gap_count={_safe_int(trend_signals.get('coverage_gap_count'))}",
        f"- Suggested live validation areas: {', '.join(top_recommendation_titles[:3] or top_gap_titles[:3]) or 'validate the most active indexes and sources live'}",
    ]).strip()

    greeting_context = (
        f"\n🔍 Splunk Environment: {overview.get('total_indexes', 0)} indexes, "
        f"{overview.get('total_sourcetypes', 0)} sourcetypes, {overview.get('total_hosts', 0)} hosts"
    )

    return {
        'timestamp': viability.get('timestamp') or bundle.get('timestamp', ''),
        'age_days': viability.get('age_days', 0),
        'viability': viability,
        'warning': viability.get('warning'),
        'readiness_score': _safe_int(blueprint.get('readiness_score') or ai_summary_payload.get('readiness_score')),
        'overview': overview,
        'finding_ledger': finding_ledger,
        'coverage_gaps': coverage_gaps if isinstance(coverage_gaps, list) else [],
        'risk_register': risk_register if isinstance(risk_register, list) else [],
        'recommendations': recommendations if isinstance(recommendations, list) else [],
        'suggested_use_cases': suggested_use_cases if isinstance(suggested_use_cases, list) else [],
        'trend_signals': trend_signals,
        'notable_patterns': notable_patterns,
        'top_indexes': top_indexes,
        'top_sourcetypes': top_sourcetypes,
        'top_hosts': top_hosts,
        'top_sources': top_sources,
        'priority_actions': priority_actions,
        'quick_wins': quick_wins,
        'executive_summary': executive_summary,
        'headline_findings': headline_findings,
        'prompt_context_compact': prompt_context_compact,
        'prompt_context_strategic': prompt_context_strategic,
        'greeting_context': greeting_context,
        'known_entities': {
            'indexes': [item.get('name') for item in top_indexes if isinstance(item, dict) and item.get('name')],
            'sourcetypes': [item.get('name') for item in top_sourcetypes if isinstance(item, dict) and item.get('name')],
            'hosts': [item.get('name') for item in top_hosts if isinstance(item, dict) and item.get('name')],
            'sources': [item.get('name') for item in top_sources if isinstance(item, dict) and item.get('name')],
        },
    }


def load_latest_report_knowledge(staleness_days: int = 7) -> Optional[Dict[str, Any]]:
    """Load the latest viable V2 report bundle and synthesize a reusable knowledge object."""
    output_dir = Path('output')
    if not output_dir.exists():
        return None

    timestamps = set()
    prefixes = [
        'v2_intelligence_blueprint_',
        'v2_insights_brief_',
        'v2_ai_summary_',
        'v2_operator_runbook_',
        'v2_developer_handoff_',
    ]
    for prefix in prefixes:
        for path in output_dir.glob(f'{prefix}*'):
            if path.is_file():
                timestamps.add(path.stem.replace(prefix, '', 1))

    best_usable = None
    for timestamp in sorted(timestamps, reverse=True):
        bundle = {
            'timestamp': timestamp,
            'blueprint': _read_json_if_exists(output_dir / f'v2_intelligence_blueprint_{timestamp}.json'),
            'insights_brief_text': _read_text_if_exists(output_dir / f'v2_insights_brief_{timestamp}.md', limit=5000),
            'ai_summary': _read_json_if_exists(output_dir / f'v2_ai_summary_{timestamp}.json'),
            'runbook_text': _read_text_if_exists(output_dir / f'v2_operator_runbook_{timestamp}.md', limit=3000),
            'handoff_text': _read_text_if_exists(output_dir / f'v2_developer_handoff_{timestamp}.md', limit=3000),
        }
        viability = _build_report_viability(bundle, staleness_days)
        knowledge = _build_report_knowledge(bundle, viability)
        if viability.get('viable'):
            return knowledge
        if viability.get('usable') and best_usable is None:
            best_usable = knowledge

    return best_usable


def _known_entity_matches(user_message: str, candidates: List[str], limit: int = 4) -> List[str]:
    if not isinstance(user_message, str):
        return []
    lowered = user_message.lower()
    matches: List[str] = []
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        cleaned = candidate.strip()
        if cleaned and cleaned.lower() in lowered and cleaned not in matches:
            matches.append(cleaned)
        if len(matches) >= limit:
            break
    return matches


def _candidate_indexes_for_domain(domain: str, report_knowledge: Dict[str, Any]) -> List[str]:
    known_indexes = report_knowledge.get('known_entities', {}).get('indexes', []) if isinstance(report_knowledge, dict) else []
    domain_defaults = {
        'security': ['endpoint', 'wineventlog', '_audit', 'security'],
        'platform operations': ['_internal', '_audit', '_introspection'],
        'application monitoring': ['wmata', 'main'],
        'network operations': ['netops', 'ping', 'main'],
        'iot monitoring': ['homebridge_for_splunk', 'esp32', 'main'],
        'compliance': ['_audit', 'wineventlog'],
    }
    candidates = []
    for desired in domain_defaults.get(domain, []):
        for index_name in known_indexes:
            if index_name.lower() == desired.lower() and index_name not in candidates:
                candidates.append(index_name)
    if candidates:
        return candidates[:4]
    return [name for name in known_indexes[:4] if isinstance(name, str)]


def build_query_plan_brief(user_message: str, report_knowledge: Optional[Dict[str, Any]], memory: Optional[Dict[str, Any]] = None) -> str:
    """Build a concise deterministic investigation plan from report knowledge and chat memory."""
    if not isinstance(user_message, str) or not report_knowledge:
        return ''

    message = user_message.lower()
    known_entities = report_knowledge.get('known_entities', {}) if isinstance(report_knowledge, dict) else {}
    domain = 'general'
    anchor = 'Use the report as baseline context and live queries for recency checks.'

    if any(token in message for token in ['windows', 'security', 'auth', 'login', 'privilege', 'lockout']):
        domain = 'security'
        anchor = 'Windows Security Monitoring and Threat Detection is a known high-priority gap with existing telemetry.'
    elif any(token in message for token in ['platform', 'splunk health', 'ingestion', 'license', 'scheduler', 'search performance', '_internal', '_audit', '_introspection']):
        domain = 'platform operations'
        anchor = 'Platform Health and Splunk Operational Monitoring is a top recommendation backed by heavy internal telemetry.'
    elif any(token in message for token in ['wmata', 'api', 'feed', 'collector']):
        domain = 'application monitoring'
        anchor = 'WMATA API monitoring is a top recommendation and a major business/application data surface.'
    elif any(token in message for token in ['network', 'ping', 'latency', 'packet loss', 'interface', 'connectivity']):
        domain = 'network operations'
        anchor = 'Network traffic and connectivity monitoring is a named coverage gap.'
    elif any(token in message for token in ['compliance', 'audit', 'admin action', 'governance']):
        domain = 'compliance'
        anchor = 'Compliance and audit activity monitoring is already identified as a medium-priority risk area.'

    remembered_index = _remembered_entity(memory or {}, 'index')
    remembered_host = _remembered_entity(memory or {}, 'host')
    candidate_indexes = _known_entity_matches(user_message, known_entities.get('indexes', []), limit=4) or _candidate_indexes_for_domain(domain, report_knowledge)
    candidate_sourcetypes = _known_entity_matches(user_message, known_entities.get('sourcetypes', []), limit=4)
    if not candidate_sourcetypes and domain == 'security':
        candidate_sourcetypes = [name for name in known_entities.get('sourcetypes', []) if isinstance(name, str) and 'wineventlog' in name.lower()][:3]

    lines = [
        'INVESTIGATION PLAN HINTS:',
        f"- Likely domain: {domain}",
        f"- Report anchor: {anchor}",
    ]

    if candidate_indexes:
        lines.append(f"- Candidate indexes: {', '.join(candidate_indexes[:4])}")
    if candidate_sourcetypes:
        lines.append(f"- Candidate sourcetypes: {', '.join(candidate_sourcetypes[:4])}")
    if remembered_index or remembered_host:
        memory_parts = []
        if remembered_index:
            memory_parts.append(f"index={remembered_index}")
        if remembered_host:
            memory_parts.append(f"host={remembered_host}")
        lines.append(f"- Chat memory anchors: {', '.join(memory_parts)}")

    if any(token in message for token in ['summary', 'overview', 'recommend', 'risk', 'gap', 'improve', 'priority']):
        lines.append('- This is partly answerable from the discovery reports; use live queries only to validate freshness, compare drift, or drill deeper.')
    else:
        lines.append('- Start with one focused validation query, then broaden the time range or pivot by sourcetype/host if the first result is thin.')

    return '\n'.join(lines)


def extract_structured_report_request(user_message: str) -> Optional[Dict[str, str]]:
    """Parse structured summary-to-chat prompts so routing can honor the clicked context."""
    if not isinstance(user_message, str) or not user_message.strip():
        return None

    def _extract_field(field_name: str) -> str:
        match = re.search(
            rf'{field_name}\s*:\s*(.*?)(?=\n[A-Za-z][A-Za-z ]*:\s|\Z)',
            user_message,
            flags=re.IGNORECASE | re.DOTALL,
        )
        return str(match.group(1)).strip() if match else ""

    lowered = user_message.lower()
    if 'risk:' in lowered:
        title = _extract_field('risk')
        if title:
            return {
                'kind': 'risk',
                'title': title,
                'impact': _extract_field('impact'),
                'mitigation': _extract_field('mitigation'),
            }

    return None


def _match_report_item(items: List[Dict[str, Any]], key: str, focus_text: str = '') -> Optional[Dict[str, Any]]:
    """Return the first matching report item for a focused prompt, falling back to the first populated item."""
    candidates = [item for item in items if isinstance(item, dict) and item.get(key)] if isinstance(items, list) else []
    if not candidates:
        return None

    lowered_focus = str(focus_text or '').strip().lower()
    if lowered_focus:
        for item in candidates:
            candidate_value = str(item.get(key) or '').strip()
            if candidate_value and candidate_value.lower() in lowered_focus:
                return item

    return candidates[0]


def detect_report_intent(user_message: str, report_knowledge: Optional[Dict[str, Any]]) -> Optional[str]:
    """Detect strategic report-backed questions that should be answered directly from discovery knowledge."""
    if not isinstance(user_message, str) or not report_knowledge:
        return None
    viability = report_knowledge.get('viability', {}) if isinstance(report_knowledge, dict) else {}
    if not viability.get('usable'):
        return None

    message = user_message.lower()
    if detect_latest_entry_index_request(user_message) or detect_last_offline_target(user_message) or detect_edge_processor_template_request(user_message):
        return None
    if detect_basic_inventory_intent(user_message):
        return None
    structured_request = extract_structured_report_request(user_message)
    if structured_request and structured_request.get('kind') == 'risk':
        return 'top_risks'
    if re.search(r'\b(index|host|sourcetype|source)\s*[=:]', message):
        return None
    if any(token in message for token in ['how many', 'count', 'latest event', 'last seen', 'timechart', 'break down', 'show events', 'run query', 'search for']):
        return None

    if any(token in message for token in ['what should i improve', 'what should we improve', 'what should i do next', 'next steps', 'priorities', 'recommend', 'recommendation', 'improve the environment']):
        return 'recommendations'
    if any(token in message for token in ['biggest risk', 'top risk', 'risks', 'weak spot', 'weak spots', 'exposure', 'blind spot']):
        return 'top_risks'
    if any(token in message for token in ['coverage gap', 'coverage gaps', 'gaps', 'missing coverage', 'what is missing']):
        return 'coverage_gaps'
    if any(token in message for token in ['use case', 'use cases', 'detections should', 'dashboards should', 'what should we build', 'monitoring opportunity']):
        return 'use_cases'
    if any(token in message for token in ['readiness', 'maturity', 'posture', 'how ready are we']):
        return 'readiness'
    if any(token in message for token in ['overall environment', 'summarize the environment', 'environment summary', 'what do we know about this environment', 'give me a summary', 'overview of the environment']):
        return 'environment_summary'
    return None


def build_report_intent_response(intent: str, report_knowledge: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Build a deterministic response from the current report knowledge bundle."""
    overview = report_knowledge.get('overview', {}) if isinstance(report_knowledge.get('overview', {}), dict) else {}
    viability = report_knowledge.get('viability', {}) if isinstance(report_knowledge.get('viability', {}), dict) else {}
    coverage_gaps = report_knowledge.get('coverage_gaps', []) if isinstance(report_knowledge.get('coverage_gaps', []), list) else []
    risk_register = report_knowledge.get('risk_register', []) if isinstance(report_knowledge.get('risk_register', []), list) else []
    recommendations = report_knowledge.get('recommendations', []) if isinstance(report_knowledge.get('recommendations', []), list) else []
    suggested_use_cases = report_knowledge.get('suggested_use_cases', []) if isinstance(report_knowledge.get('suggested_use_cases', []), list) else []
    top_indexes = report_knowledge.get('top_indexes', []) if isinstance(report_knowledge.get('top_indexes', []), list) else []
    top_sourcetypes = report_knowledge.get('top_sourcetypes', []) if isinstance(report_knowledge.get('top_sourcetypes', []), list) else []

    opening = (
        f"Latest discovery bundle status: {viability.get('status', 'unknown')} "
        f"(score {viability.get('score', 0)}/100, {viability.get('age_days', 0)} days old)."
    )
    if viability.get('warning'):
        opening = f"{opening}\n\n{viability.get('warning')}"

    insights: List[str] = []
    lines = [opening]

    if intent == 'environment_summary':
        insights = [item for item in (report_knowledge.get('headline_findings', []) or [])[:5] if isinstance(item, str)]
        lines.extend([
            '',
            f"Environment snapshot: {overview.get('total_indexes', 0)} indexes, {overview.get('total_sourcetypes', 0)} sourcetypes, {overview.get('total_hosts', 0)} hosts, {overview.get('total_sources', 0)} sources, and {overview.get('data_volume_24h', 'unknown')} of data over 24 hours.",
            f"Readiness score: {_safe_int(report_knowledge.get('readiness_score'))} / 100.",
            f"Dominant indexes: {_format_ranked_entities(top_indexes[:4], include_size=True) or 'unknown' }.",
            f"Dominant sourcetypes: {_format_ranked_entities(top_sourcetypes[:4]) or 'unknown' }.",
            f"Highest-value gaps: {', '.join([gap.get('gap') for gap in coverage_gaps[:4] if isinstance(gap, dict) and gap.get('gap')]) or 'none identified' }.",
            f"Priority actions: {', '.join(report_knowledge.get('priority_actions', [])[:3]) or ', '.join([rec.get('title') for rec in recommendations[:3] if isinstance(rec, dict) and rec.get('title')]) or 'no explicit priority actions extracted' }.",
        ])
    elif intent == 'recommendations':
        for rec in recommendations[:5]:
            if not isinstance(rec, dict):
                continue
            title = rec.get('title')
            if not title:
                continue
            insights.append(str(title))
            lines.append(f"- {title} [{str(rec.get('priority', 'medium')).upper()}]: {str(rec.get('description', '')).strip()}")
        if report_knowledge.get('priority_actions'):
            lines.extend(['', 'Fastest priority actions:'])
            lines.extend([f"- {item}" for item in report_knowledge.get('priority_actions', [])[:3]])
    elif intent == 'top_risks':
        for risk in risk_register[:6]:
            if not isinstance(risk, dict):
                continue
            title = risk.get('risk')
            if not title:
                continue
            insights.append(str(title))
            severity = str(risk.get('severity', 'medium')).upper()
            impact = str(risk.get('impact', '')).strip()
            lines.append(f"- {title} [{severity}]: {impact}")
    elif intent == 'coverage_gaps':
        for gap in coverage_gaps[:6]:
            if not isinstance(gap, dict):
                continue
            title = gap.get('gap')
            if not title:
                continue
            insights.append(str(title))
            priority = str(gap.get('priority', 'medium')).upper()
            lines.append(f"- {title} [{priority}]: {str(gap.get('why_it_matters', '')).strip()}")
    elif intent == 'use_cases':
        for use_case in suggested_use_cases[:5]:
            if not isinstance(use_case, dict):
                continue
            title = use_case.get('title')
            if not title:
                continue
            insights.append(str(title))
            lines.append(f"- {title}: {str(use_case.get('scenario') or use_case.get('description') or '').strip()} Business value: {str(use_case.get('business_value', '')).strip()}")
    else:
        blocker_titles = [gap.get('gap') for gap in coverage_gaps[:3] if isinstance(gap, dict) and gap.get('gap')]
        readiness_score = _safe_int(report_knowledge.get('overview', {}).get('readiness_score') or report_knowledge.get('readiness_score') or report_knowledge.get('viability', {}).get('score'))
        insights = blocker_titles
        lines.extend([
            '',
            f"Readiness score: {readiness_score}/100.",
            f"Top blockers: {', '.join(blocker_titles) or 'no major blockers identified'}.",
            f"The main drag on readiness is that the environment is data-rich but still missing higher-order detections and operational monitoring in areas like {', '.join(blocker_titles[:3]) or 'security and platform health'}.",
        ])

    lines.extend([
        '',
        'Use MCP queries to validate current conditions, measure drift since the report snapshot, or drill into one risk area live.',
    ])
    return '\n'.join([line for line in lines if isinstance(line, str)]).strip(), insights[:8]


def build_focused_report_response(
    intent: str,
    report_knowledge: Dict[str, Any],
    focus_request: Optional[Dict[str, str]],
) -> Optional[Tuple[str, List[str]]]:
    """Build a targeted report-backed response for structured summary-to-chat prompts."""
    if intent != 'top_risks' or not isinstance(focus_request, dict) or focus_request.get('kind') != 'risk':
        return None

    risk_register = report_knowledge.get('risk_register', []) if isinstance(report_knowledge.get('risk_register', []), list) else []
    recommendations = report_knowledge.get('recommendations', []) if isinstance(report_knowledge.get('recommendations', []), list) else []
    coverage_gaps = report_knowledge.get('coverage_gaps', []) if isinstance(report_knowledge.get('coverage_gaps', []), list) else []
    title = str(focus_request.get('title') or '').strip()
    matched_risk = _match_report_item(risk_register, 'risk', title)
    matched_recommendation = _match_report_item(recommendations, 'title', title)
    matched_gap = _match_report_item(coverage_gaps, 'gap', title)

    if not title:
        return None

    severity = str((matched_risk or {}).get('severity') or 'medium').strip().upper()
    domain = str((matched_risk or {}).get('domain') or 'general').strip()
    impact = str((matched_risk or {}).get('impact') or focus_request.get('impact') or 'No explicit impact statement was captured.').strip()
    mitigation = str((matched_risk or {}).get('mitigation') or focus_request.get('mitigation') or 'Use live validation to confirm the fastest remediation path.').strip()

    lines = [
        f"Focused risk investigation: {title}",
        f"Severity: {severity} | Domain: {domain}",
        f"Why this matters: {impact}",
        f"Mitigation path: {mitigation}",
    ]

    if isinstance(matched_recommendation, dict) and matched_recommendation.get('description'):
        lines.append(f"Related recommendation: {str(matched_recommendation.get('title')).strip()} - {str(matched_recommendation.get('description')).strip()}")
    if isinstance(matched_gap, dict) and matched_gap.get('why_it_matters'):
        lines.append(f"Related coverage gap: {str(matched_gap.get('gap')).strip()} - {str(matched_gap.get('why_it_matters')).strip()}")

    lines.extend([
        '',
        'Use MCP queries to validate the current severity, check whether the risk is already visible in live telemetry, and confirm whether mitigation work should start with platform health, data quality, or coverage expansion.',
    ])

    insights = [title]
    if isinstance(matched_recommendation, dict) and matched_recommendation.get('title'):
        insights.append(str(matched_recommendation.get('title')).strip())

    return '\n'.join([line for line in lines if isinstance(line, str) and line.strip()]).strip(), insights[:8]


def build_report_follow_on_actions(
    intent: str,
    report_knowledge: Dict[str, Any],
    focus_text: str = '',
    assistant_response: str = '',
) -> List[Dict[str, Any]]:
    """Return live validation prompts that naturally follow a strategic report-backed answer."""
    actions: List[Dict[str, Any]] = _extract_response_follow_on_actions(assistant_response)
    recommendations = report_knowledge.get('recommendations', []) if isinstance(report_knowledge.get('recommendations', []), list) else []
    coverage_gaps = report_knowledge.get('coverage_gaps', []) if isinstance(report_knowledge.get('coverage_gaps', []), list) else []
    risk_register = report_knowledge.get('risk_register', []) if isinstance(report_knowledge.get('risk_register', []), list) else []
    suggested_use_cases = report_knowledge.get('suggested_use_cases', []) if isinstance(report_knowledge.get('suggested_use_cases', []), list) else []
    recommendation_titles = [
        str(rec.get('title')).lower()
        for rec in recommendations[:6]
        if isinstance(rec, dict) and rec.get('title')
    ]
    top_recommendation = _match_report_item(recommendations, 'title', focus_text)
    top_gap = _match_report_item(coverage_gaps, 'gap', focus_text)
    top_risk = _match_report_item(risk_register, 'risk', focus_text)
    top_use_case = _match_report_item(suggested_use_cases, 'title', focus_text)

    if intent == 'recommendations' and isinstance(top_recommendation, dict):
        actions.append(_make_follow_on_action(
            'Validate the top recommendation',
            (
                f"Validate this discovery recommendation with live Splunk data and summarize drift from the report snapshot: "
                f"{str(top_recommendation.get('title')).strip()}. "
                f"Context: {str(top_recommendation.get('description') or 'No additional recommendation context was captured.').strip()}"
            ),
            'validate_top_recommendation',
        ))

    if intent == 'top_risks' and isinstance(top_risk, dict):
        actions.append(_make_follow_on_action(
            'Investigate the top risk live',
            (
                f"Investigate this discovery risk in Splunk and show whether it is visible right now: "
                f"{str(top_risk.get('risk')).strip()}. "
                f"Impact: {str(top_risk.get('impact') or 'No impact statement was captured.').strip()} "
                f"Mitigation: {str(top_risk.get('mitigation') or 'Identify the most direct validation path.').strip()}"
            ),
            'investigate_top_risk',
        ))

    if intent == 'coverage_gaps' and isinstance(top_gap, dict):
        actions.append(_make_follow_on_action(
            'Validate the highest-priority gap',
            (
                f"Validate this coverage gap with live Splunk data and state whether the environment is ready to close it: "
                f"{str(top_gap.get('gap')).strip()}. "
                f"Why it matters: {str(top_gap.get('why_it_matters') or 'No impact summary was captured.').strip()}"
            ),
            'validate_top_gap',
        ))

    if intent == 'use_cases' and isinstance(top_use_case, dict):
        actions.append(_make_follow_on_action(
            'Prototype the strongest use case',
            (
                f"Prototype the strongest report-backed use case with the current data and explain the validation path: "
                f"{str(top_use_case.get('title')).strip()}. "
                f"Scenario: {str(top_use_case.get('scenario') or top_use_case.get('description') or 'No scenario details were captured.').strip()}"
            ),
            'prototype_top_use_case',
        ))

    if any('windows security' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Validate Windows security live',
            'Validate Windows security telemetry over the last 24 hours and show failed logons, privilege changes, and account lockouts.',
            'validate_windows_security',
        ))
    if any('platform health' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Check Splunk platform health',
            'Check platform health in _internal, _audit, and _introspection over the last 24 hours and summarize ingestion issues, search failures, and license signals.',
            'validate_platform_health',
        ))
    if any('wmata' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Review WMATA feed health',
            'Check WMATA API and collector data over the last 24 hours for outages, elevated errors, and latency spikes.',
            'validate_wmata_health',
        ))
    if any('network' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Inspect network connectivity',
            'Show connectivity, latency, and packet-loss trends from ping or network telemetry over the last 24 hours.',
            'validate_network_health',
        ))

    if intent == 'use_cases':
        actions.append(_make_follow_on_action(
            'Show the strongest live use-case candidate',
            'Show the strongest live candidate for a new detection or dashboard based on the most active data sources in this environment.',
            'live_use_case_candidate',
        ))

    if intent == 'readiness' and isinstance(top_gap, dict):
        actions.append(_make_follow_on_action(
            'Measure readiness against the top blocker',
            (
                f"Measure current readiness against this blocker and explain the next implementation step: "
                f"{str(top_gap.get('gap')).strip()}."
            ),
            'measure_readiness_blocker',
        ))

    if not actions:
        actions.append(_make_follow_on_action(
            'Validate the top gap live',
            'Validate the highest-priority discovery gap with a live query and summarize whether the current data supports immediate implementation.',
            'validate_top_gap',
        ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _is_numeric_like(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        cleaned = value.strip().replace(',', '')
        if not cleaned:
            return False
        try:
            float(cleaned)
            return True
        except Exception:
            return False
    return False


def analyze_result_rows(rows: Any) -> Dict[str, Any]:
    """Extract compact structural clues from query results for planning and summarization."""
    if not isinstance(rows, list) or not rows:
        return {}

    dict_rows = [row for row in rows[:60] if isinstance(row, dict)]
    if not dict_rows:
        return {}

    sample_fields = list(dict_rows[0].keys())[:12]
    time_fields = [
        field for field in sample_fields
        if field.lower() in {'_time', 'time', 'firsttimeiso', 'lasttimeiso', 'recenttimeiso'}
        or field.lower().endswith('time')
        or field.lower().endswith('timeiso')
    ]

    numeric_fields: List[str] = []
    for field in sample_fields:
        sample_values = [row.get(field) for row in dict_rows[:8] if row.get(field) not in (None, '')]
        if sample_values and all(_is_numeric_like(value) for value in sample_values):
            numeric_fields.append(field)

    top_dimensions: List[Dict[str, Any]] = []
    for field in sample_fields:
        lowered = field.lower()
        if field in numeric_fields or lowered in time_fields or lowered.endswith('time') or lowered.endswith('timeiso'):
            continue
        counts: Dict[str, int] = {}
        for row in dict_rows[:50]:
            value = row.get(field)
            if value in (None, ''):
                continue
            text = str(value).strip()
            if not text or len(text) > 80:
                continue
            counts[text] = counts.get(text, 0) + 1
        if len(counts) < 2:
            continue
        ranked_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        top_dimensions.append({
            'field': field,
            'distinct_count': len(counts),
            'values': [f"{name} ({count})" for name, count in ranked_counts[:3]],
        })

    top_dimensions = sorted(top_dimensions, key=lambda item: item.get('distinct_count', 0), reverse=True)[:3]

    time_bounds = {}
    for field in time_fields[:2]:
        values = [str(row.get(field)).strip() for row in dict_rows if row.get(field) not in (None, '')]
        if values:
            time_bounds = {
                'field': field,
                'first': values[0],
                'last': values[-1],
            }
            break

    query_shape = 'tabular'
    numeric_names = {field.lower() for field in numeric_fields}
    if time_fields and numeric_names.intersection({'count', 'event_count', 'events', 'totalcount'}):
        query_shape = 'time_series'
    elif top_dimensions and numeric_fields:
        query_shape = 'aggregation'
    elif len(rows) <= 5 and len(sample_fields) >= 4:
        query_shape = 'event_sample'

    next_pivots: List[str] = []
    if top_dimensions:
        first_dimension = top_dimensions[0]
        top_value = str(first_dimension['values'][0]).rsplit(' (', 1)[0]
        next_pivots.append(f"Filter on {first_dimension['field']}={top_value}")
    if query_shape == 'time_series':
        next_pivots.append('Compare adjacent time buckets for spikes or drops')
    if len(rows) > 100:
        next_pivots.append('Tighten the query or aggregate by one dimension')

    return {
        'query_shape': query_shape,
        'sample_fields': sample_fields,
        'time_bounds': time_bounds,
        'top_dimensions': top_dimensions,
        'numeric_fields': numeric_fields[:6],
        'next_pivots': next_pivots[:3],
    }


def format_result_summary_for_llm(summary: Dict[str, Any]) -> str:
    """Convert structured result metadata into a compact analysis brief for follow-up reasoning."""
    if not isinstance(summary, dict):
        return ''

    lines: List[str] = []
    for finding in summary.get('findings', [])[:5]:
        if isinstance(finding, str) and finding.strip():
            lines.append(f"- {finding}")

    query_shape = str(summary.get('query_shape', '')).strip()
    if query_shape:
        lines.append(f"- Result shape: {query_shape}")

    time_bounds = summary.get('time_bounds', {}) if isinstance(summary.get('time_bounds', {}), dict) else {}
    if time_bounds.get('field') and (time_bounds.get('first') or time_bounds.get('last')):
        lines.append(
            f"- Time bounds from {time_bounds.get('field')}: {time_bounds.get('first', 'unknown')} -> {time_bounds.get('last', 'unknown')}"
        )

    for dimension in summary.get('top_dimensions', [])[:2]:
        if not isinstance(dimension, dict):
            continue
        field = str(dimension.get('field', '')).strip()
        values = dimension.get('values', []) if isinstance(dimension.get('values', []), list) else []
        if field and values:
            lines.append(f"- Top {field} values: {', '.join(values[:3])}")

    next_pivots = summary.get('next_pivots', []) if isinstance(summary.get('next_pivots', []), list) else []
    if next_pivots:
        lines.append(f"- Suggested pivots: {', '.join(next_pivots[:3])}")

    return '\n'.join(lines)


async def process_chat_with_streaming(request: dict, status_queue: asyncio.Queue):
    """Process chat request and push status updates to queue."""
    try:
        # Define callback that pushes to queue
        async def status_callback(action: str, iteration: int, time: float):
            await status_queue.put({
                'type': 'status',
                'action': action,
                'iteration': iteration,
                'time': round(time, 1)
            })
        
        # Call chat logic with streaming callback
        result = await chat_with_splunk_logic(request, status_callback)
        await status_queue.put({'type': 'done', 'data': result})
    except Exception as e:
        await status_queue.put({'type': 'error', 'error': str(e)})


async def chat_with_splunk_logic(request: dict, status_callback=None):
    """Core chat logic that can optionally stream status updates.
    
    Args:
        request: The chat request dict
        status_callback: Optional async function to call with status updates
                        Signature: async def callback(action: str, iteration: int, time: float)
    """
    try:
        sync_chat_settings_with_capability_defaults()
        print(f"🔵 [CHAT] Request received: {request.get('message', '')[:50]}")
        user_message = request.get('message', '')
        history = request.get('history', [])
        chat_session_id = sanitize_chat_session_id(request.get('chat_session_id', 'default'))
        
        if not user_message.strip():
            return {"error": "Message cannot be empty"}
        
        # Sanitize user message to prevent prompt injection
        # Remove control characters but preserve normal punctuation
        safe_message = ''.join(char for char in user_message if char.isprintable() or char in '\n\r\t')
        
        # Limit message length
        if len(safe_message) > 10000:
            return {"error": "Message too long (max 10000 characters)"}
        
        # Validate history format
        if not isinstance(history, list):
            return {"error": "Invalid history format"}
        
        # Load configuration
        config = config_manager.get()
        request_started_at = time.time()

        async def push_status(timeline: List[Dict[str, Any]], action: str, iteration: int = 0):
            elapsed = time.time() - request_started_at
            event = {"iteration": iteration, "action": action, "time": elapsed}
            timeline.append(event)
            if status_callback:
                await status_callback(action, iteration, elapsed)

        # Load and update persistent chat memory for this session
        update_chat_memory(chat_session_id, user_message)
        chat_memory = load_chat_memory(chat_session_id)
        memory_context = build_chat_memory_context(chat_memory)
        
        query_lower = user_message.lower()
        simple_greetings = any(word in query_lower for word in ['hi', 'hello', 'hey', 'thanks', 'thank you', 'bye'])
        needs_insights = any(keyword in query_lower for keyword in [
            'summary', 'overview', 'recommend', 'best practice', 'optimization',
            'use case', 'compliance', 'security', 'improve', 'assess', 'risk', 'gap', 'priority'
        ])

        report_knowledge = load_latest_report_knowledge(chat_session_settings["discovery_freshness_days"])
        discovery_context = ""
        discovery_age_warning = None

        if report_knowledge:
            discovery_age_warning = report_knowledge.get('warning')
            if simple_greetings:
                discovery_context = report_knowledge.get('greeting_context', '')
            else:
                discovery_context = report_knowledge.get('prompt_context_compact', '')
                if needs_insights and report_knowledge.get('prompt_context_strategic'):
                    discovery_context = "\n\n".join([
                        section for section in [
                            discovery_context,
                            report_knowledge.get('prompt_context_strategic', ''),
                        ] if isinstance(section, str) and section.strip()
                    ])
        else:
            discovery_age_warning = "⚠️ No discovery data found. Run a discovery first to get environment context."

        report_intent = detect_report_intent(user_message, report_knowledge) if bool(chat_session_settings.get("enable_splunk_augmentation", True)) else None

        query_plan_context = build_query_plan_brief(user_message, report_knowledge, chat_memory)

        if report_intent:
            report_status_timeline: List[Dict[str, Any]] = []
            report_capability_usage: List[Dict[str, Any]] = []
            structured_report_request = extract_structured_report_request(user_message)
            await push_status(report_status_timeline, "📚 Synthesizing discovery knowledge", 0)
            if bool(chat_session_settings.get("enable_rag_context", False)):
                rag_max_chunks = _safe_int(chat_session_settings.get("rag_max_chunks", 3))
                _, report_capability_usage = get_optional_rag_context(user_message, max_chunks=rag_max_chunks)
            focused_report_response = build_focused_report_response(report_intent, report_knowledge, structured_report_request)
            if focused_report_response:
                response_text, report_insights = focused_report_response
            else:
                response_text, report_insights = build_report_intent_response(report_intent, report_knowledge)
            report_context_brief = build_capability_usage_brief(report_capability_usage)
            if report_context_brief:
                response_text = f"{response_text}\n\n{report_context_brief}"
            follow_on_actions = build_report_follow_on_actions(
                report_intent,
                report_knowledge,
                focus_text=user_message,
                assistant_response=response_text,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                assistant_response=response_text,
                report_intent=report_intent,
                record_user_turn=False,
            )
            await push_status(report_status_timeline, "✅ Returning report-backed guidance", 0)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": [],
                "spl_query": None,
                "iterations": 0,
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": report_insights,
                "status_timeline": report_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": report_capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions,
            }

        available_mcp_tools = await discover_mcp_tools(config)
        if not available_mcp_tools:
            available_mcp_tools = {
                "splunk_run_query",
                "splunk_get_info",
                "splunk_get_indexes",
                "splunk_get_index_info",
                "splunk_get_metadata",
                "splunk_get_user_info",
                "splunk_get_knowledge_objects"
            }

        primary_tool_order = [
            "splunk_run_query",
            "splunk_get_info",
            "splunk_get_indexes",
            "splunk_get_index_info",
            "splunk_get_metadata",
            "splunk_get_user_info",
            "splunk_get_knowledge_objects",
            "saia_generate_spl",
            "saia_optimize_spl",
            "saia_explain_spl",
            "saia_ask_splunk_question"
        ]
        ordered_tools = [name for name in primary_tool_order if name in available_mcp_tools]
        ordered_tools.extend(sorted([name for name in available_mcp_tools if name not in ordered_tools]))

        available_tools_text = "\n".join(
            f"- {name}: {MCP_TOOL_DESCRIPTIONS.get(name, 'MCP tool available for Splunk operations.')}"
            for name in ordered_tools
        )

        query_tool_name = resolve_tool_name("splunk_run_query", available_mcp_tools)
        provider_name = normalize_provider_name(getattr(config.llm, "provider", ""))
        is_custom_provider = provider_name in {"custom", "custom endpoint"}

        # Deterministic path for "latest entry in <index>" requests to avoid LLM misclassification
        latest_index_name = detect_latest_entry_index_request(user_message)
        if latest_index_name:
            latest_status_timeline: List[Dict[str, Any]] = []
            latest_tool_calls: List[Dict[str, Any]] = []
            normalized_index_name = latest_index_name.strip()

            # Step 1: validate index presence from live tool results
            indexes_tool_name = resolve_tool_name("splunk_get_indexes", available_mcp_tools)
            indexes_call = {
                "method": "tools/call",
                "params": {
                    "name": indexes_tool_name,
                    "arguments": {"row_limit": 1000}
                }
            }
            await push_status(latest_status_timeline, "📁 Validating index existence", 1)
            indexes_result = await execute_mcp_tool_call(indexes_call, config)
            parsed_indexes = extract_results_from_mcp_response(indexes_result)
            index_rows = parsed_indexes.get("results", []) if isinstance(parsed_indexes, dict) else []
            index_names = []
            for row in index_rows:
                if not isinstance(row, dict):
                    continue
                candidate = row.get("title") or row.get("name")
                if isinstance(candidate, str) and candidate.strip():
                    index_names.append(candidate.strip())

            index_exists = any(name.lower() == normalized_index_name.lower() for name in index_names)
            latest_tool_calls.append({
                "iteration": 1,
                "tool": indexes_tool_name,
                "args": {"row_limit": 1000},
                "spl_query": None,
                "result": indexes_result,
                "summary": {
                    "type": indexes_tool_name,
                    "row_count": len(index_rows),
                    "findings": [f"Found {len(index_rows)} indexes"],
                    "actual_results": index_rows[:5]
                }
            })

            if not index_exists:
                similar = [name for name in index_names if normalized_index_name.lower() in name.lower()][:5]
                response_text = f"I validated live index metadata and could not find an index named `{normalized_index_name}`."
                if similar:
                    response_text += "\n\nClosest matches: " + ", ".join(similar)
                elif index_names:
                    response_text += "\n\nIf helpful, I can list all currently available indexes."

                updated_memory = update_chat_memory(
                    chat_session_id,
                    user_message,
                    latest_tool_calls,
                    assistant_response=response_text,
                    record_user_turn=False,
                )
                follow_on_actions = build_follow_on_actions(
                    user_message,
                    updated_memory,
                    latest_tool_calls,
                    assistant_response=response_text,
                )
                await push_status(latest_status_timeline, "✅ Finalizing response", len(latest_tool_calls))
                visualization_spec, capability_usage = augment_capability_usage_with_visualization(latest_tool_calls)
                return {
                    "response": response_text,
                    "initial_response": user_message,
                    "tool_calls": latest_tool_calls,
                    "spl_query": extract_primary_spl_query(latest_tool_calls),
                    "visualization_spec": visualization_spec,
                    "iterations": len(latest_tool_calls),
                    "execution_time": f"{time.time() - request_started_at:.2f}s",
                    "insights": ["Index was validated directly from Splunk index inventory."],
                    "status_timeline": latest_status_timeline,
                    "discovery_age_warning": discovery_age_warning,
                    "chat_session_id": chat_session_id,
                    "chat_memory": updated_memory,
                    "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                    "capability_usage": capability_usage,
                    "has_follow_on": len(follow_on_actions) > 0,
                    "follow_on_actions": follow_on_actions
                }

            # Step 2: fetch latest event in that index
            latest_query = f"search index={normalized_index_name} | sort - _time | head 1"
            latest_call = {
                "method": "tools/call",
                "params": {
                    "name": query_tool_name,
                    "arguments": {
                        "query": latest_query,
                        "earliest_time": "-30d",
                        "latest_time": "now",
                        "row_limit": 1
                    }
                }
            }
            await push_status(latest_status_timeline, "🔍 Retrieving latest event", 2)
            latest_result = await execute_mcp_tool_call(latest_call, config)
            parsed_latest = extract_results_from_mcp_response(latest_result)
            latest_rows = parsed_latest.get("results", []) if isinstance(parsed_latest, dict) else []
            latest_error_code = parsed_latest.get("status_code") if isinstance(parsed_latest, dict) else None
            latest_error_message = parsed_latest.get("error_message") if isinstance(parsed_latest, dict) else ""

            latest_tool_calls.append({
                "iteration": 2,
                "tool": query_tool_name,
                "args": {
                    "query": latest_query,
                    "earliest_time": "-30d",
                    "latest_time": "now",
                    "row_limit": 1
                },
                "spl_query": latest_query,
                "result": latest_result,
                "summary": {
                    "type": query_tool_name,
                    "row_count": len(latest_rows),
                    "findings": [f"{len(latest_rows)} results returned"],
                    "actual_results": latest_rows[:1]
                }
            })

            if isinstance(latest_error_code, int) and latest_error_code >= 400:
                response_text = (
                    f"I confirmed index `{normalized_index_name}` exists, but the latest-entry query returned an error "
                    f"(status_code={latest_error_code}).\n\n"
                    f"{latest_error_message or 'No additional error details were returned.'}"
                )
            elif latest_rows:
                latest_event = latest_rows[0] if isinstance(latest_rows[0], dict) else {"value": latest_rows[0]}
                pretty_event = json.dumps(latest_event, indent=2, default=str)
                response_text = (
                    f"Latest event in index `{normalized_index_name}`:\n\n"
                    f"```json\n{pretty_event}\n```"
                )
            else:
                response_text = (
                    f"Index `{normalized_index_name}` exists, but no events were returned for the last 30 days "
                    f"with `search index={normalized_index_name} | sort - _time | head 1`."
                )

            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                latest_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                latest_tool_calls,
                assistant_response=response_text,
            )
            await push_status(latest_status_timeline, "✅ Finalizing response", len(latest_tool_calls))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(latest_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": latest_tool_calls,
                "spl_query": extract_primary_spl_query(latest_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(latest_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": ["Used deterministic latest-event flow for index validation and retrieval."],
                "status_timeline": latest_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        if bool(chat_session_settings.get("enable_splunk_augmentation", True)) and detect_edge_processor_template_request(user_message):
            skill_status_timeline: List[Dict[str, Any]] = []
            skill_tool_calls: List[Dict[str, Any]] = []

            knowledge_tool_name = resolve_tool_name("splunk_get_knowledge_objects", available_mcp_tools)
            await push_status(skill_status_timeline, "🧭 Fetching knowledge objects", 1)

            attempts = [
                {"object_type": "saved_searches", "row_limit": 1000},
                {"object_type": "macros", "row_limit": 1000},
                {"object_type": "data_models", "row_limit": 500},
                {"row_limit": 1000}
            ]

            collected_rows: List[Dict[str, Any]] = []
            for attempt_idx, args in enumerate(attempts, 1):
                call_payload = {
                    "method": "tools/call",
                    "params": {
                        "name": knowledge_tool_name,
                        "arguments": args
                    }
                }
                attempt_result = await execute_mcp_tool_call(call_payload, config)
                parsed = extract_results_from_mcp_response(attempt_result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                if isinstance(rows, list):
                    for row in rows:
                        if isinstance(row, dict):
                            collected_rows.append(row)

                skill_tool_calls.append({
                    "iteration": attempt_idx,
                    "tool": knowledge_tool_name,
                    "args": args,
                    "spl_query": None,
                    "result": attempt_result,
                    "summary": {
                        "type": knowledge_tool_name,
                        "row_count": len(rows) if isinstance(rows, list) else 0,
                        "findings": [f"Attempt {attempt_idx}: {len(rows) if isinstance(rows, list) else 0} objects returned"],
                        "actual_results": rows[:8] if isinstance(rows, list) else []
                    }
                })

            filtered_templates: List[Dict[str, Any]] = []
            for row in collected_rows:
                title = str(row.get("title") or row.get("name") or row.get("id") or "").strip()
                description = str(row.get("description") or row.get("search") or row.get("qualifiedSearch") or "").strip()
                searchable = f"{title} {description}".lower()
                if not searchable:
                    continue
                if "edge" in searchable and ("processor" in searchable or "template" in searchable):
                    filtered_templates.append({
                        "title": title or "Unnamed object",
                        "description": description[:240],
                        "type": row.get("type") or row.get("object_type") or "knowledge_object"
                    })

            deduped: List[Dict[str, Any]] = []
            seen_titles = set()
            for item in filtered_templates:
                key = str(item.get("title", "")).lower()
                if key and key not in seen_titles:
                    seen_titles.add(key)
                    deduped.append(item)

            if deduped:
                lines = ["I found these Splunk knowledge objects that match Edge Processor template intent:"]
                for idx, item in enumerate(deduped[:12], 1):
                    lines.append(f"{idx}. {item.get('title', 'Template')} ({item.get('type', 'knowledge_object')})")
                    if item.get("description"):
                        lines.append(f"   - {item.get('description')}")
                response_text = "\n".join(lines)
            else:
                fallback_query_args = {
                    "query": "| rest /servicesNS/-/-/saved/searches | search title=\"*edge*\" OR search=\"*edge*\" OR title=\"*template*\" | table title description eai:acl.app",
                    "earliest_time": "-24h",
                    "latest_time": "now"
                }
                fallback_result = await execute_mcp_tool_call({
                    "method": "tools/call",
                    "params": {
                        "name": query_tool_name,
                        "arguments": fallback_query_args
                    }
                }, config)
                fallback_parsed = extract_results_from_mcp_response(fallback_result)
                fallback_rows = fallback_parsed.get("results", []) if isinstance(fallback_parsed, dict) else []

                fallback_matches: List[str] = []
                for row in fallback_rows if isinstance(fallback_rows, list) else []:
                    if isinstance(row, dict):
                        title = str(row.get("title") or "").strip()
                        if title:
                            fallback_matches.append(title)

                skill_tool_calls.append({
                    "iteration": len(skill_tool_calls) + 1,
                    "tool": query_tool_name,
                    "args": fallback_query_args,
                    "spl_query": fallback_query_args.get("query"),
                    "result": fallback_result,
                    "summary": {
                        "type": query_tool_name,
                        "row_count": len(fallback_rows) if isinstance(fallback_rows, list) else 0,
                        "findings": [f"Fallback REST lookup returned {len(fallback_matches)} entries"],
                        "actual_results": fallback_rows[:8] if isinstance(fallback_rows, list) else []
                    }
                })

                if fallback_matches:
                    response_text = "I found these template-like saved searches related to edge processing:\n" + "\n".join([f"- {item}" for item in fallback_matches[:20]])
                else:
                    response_text = (
                        "I queried knowledge objects and a saved-search REST fallback, but found no objects clearly tagged as Edge Processor templates. "
                        "If you use a naming convention, I can search for that exact prefix next."
                    )

            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                skill_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                skill_tool_calls,
                assistant_response=response_text,
            )
            await push_status(skill_status_timeline, "✅ Finalizing response", max(1, len(skill_tool_calls)))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(skill_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": skill_tool_calls,
                "spl_query": extract_primary_spl_query(skill_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(skill_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": ["Used deterministic template lookup for Edge Processor intent."],
                "status_timeline": skill_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        offline_target = detect_last_offline_target(user_message) if bool(chat_session_settings.get("enable_splunk_augmentation", True)) else None
        if offline_target:
            offline_status_timeline: List[Dict[str, Any]] = []
            offline_tool_calls: List[Dict[str, Any]] = []

            memory_indexes = (chat_memory.get("entities", {}).get("indexes", []) if isinstance(chat_memory, dict) else [])
            candidate_indexes = []
            for name in (memory_indexes[-4:] if isinstance(memory_indexes, list) else []) + ["network_logs", "main"]:
                if isinstance(name, str) and name and name not in candidate_indexes:
                    candidate_indexes.append(name)

            offline_terms = '(offline OR down OR unreachable OR disconnected OR "link down" OR status=offline OR status=down)'
            entity_clause = f'(host="{offline_target}" OR src="{offline_target}" OR dest="{offline_target}" OR ip="{offline_target}" OR "{offline_target}")'
            noise_exclusion = 'NOT sourcetype=mcp_server NOT source="*mcp_server*" NOT "Executing SPL query:"'

            query_attempts = []
            for idx_name in candidate_indexes[:5]:
                query_attempts.append({
                    "query": f"search index={idx_name} {entity_clause} {offline_terms} {noise_exclusion} | sort - _time | head 1 | table _time host src dest ip status sourcetype source message",
                    "earliest_time": "-30d",
                    "latest_time": "now"
                })
                query_attempts.append({
                    "query": f"search index={idx_name} {entity_clause} {offline_terms} {noise_exclusion} | sort - _time | head 1 | table _time host src dest ip status sourcetype source message",
                    "earliest_time": "-90d",
                    "latest_time": "now"
                })

            query_attempts.append({
                "query": f"search {entity_clause} {offline_terms} {noise_exclusion} | sort - _time | head 1 | table _time host src dest ip status sourcetype source message",
                "earliest_time": "-90d",
                "latest_time": "now"
            })

            found_event: Optional[Dict[str, Any]] = None
            for attempt_idx, attempt_args in enumerate(query_attempts[:8], 1):
                await push_status(offline_status_timeline, "🔍 Searching for latest offline signal", attempt_idx)
                call_payload = {
                    "method": "tools/call",
                    "params": {
                        "name": query_tool_name,
                        "arguments": attempt_args
                    }
                }
                attempt_result = await execute_mcp_tool_call(call_payload, config)
                parsed = extract_results_from_mcp_response(attempt_result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                row_count = len(rows) if isinstance(rows, list) else 0

                offline_tool_calls.append({
                    "iteration": attempt_idx,
                    "tool": query_tool_name,
                    "args": attempt_args,
                    "spl_query": attempt_args.get("query"),
                    "result": attempt_result,
                    "summary": {
                        "type": query_tool_name,
                        "row_count": row_count,
                        "findings": [f"Attempt {attempt_idx}: {row_count} results returned"],
                        "actual_results": rows[:2] if isinstance(rows, list) else []
                    }
                })

                if row_count > 0:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        row_message = str(row.get("message") or "")
                        row_source = str(row.get("source") or "")
                        row_sourcetype = str(row.get("sourcetype") or "")
                        is_noise = (
                            "executing spl query:" in row_message.lower()
                            or "mcp_server" in row_source.lower()
                            or row_sourcetype.lower() == "mcp_server"
                        )
                        if not is_noise:
                            found_event = row
                            break
                    if found_event:
                        break

            if found_event:
                raw_time = found_event.get("_time") or found_event.get("time") or found_event.get("timestamp")
                friendly_time = str(raw_time)
                if isinstance(raw_time, (int, float)):
                    try:
                        friendly_time = datetime.fromtimestamp(float(raw_time)).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        friendly_time = str(raw_time)

                pretty_event = json.dumps(found_event, indent=2, default=str)
                response_text = (
                    f"The latest offline event I found for `{offline_target}` was at **{friendly_time}**.\n\n"
                    f"```json\n{pretty_event}\n```"
                )
            else:
                attempted_patterns = [str(call.get("args", {}).get("query", ""))[:90] for call in offline_tool_calls[:3]]
                response_text = (
                    f"I searched multiple indexes and broader time windows but found no offline events for `{offline_target}`. "
                    f"I tried patterns like: {' | '.join(attempted_patterns)}. "
                    f"If you want, I can retry with a custom index list or alternate status keywords used in your environment."
                )

            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                offline_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                offline_tool_calls,
                assistant_response=response_text,
            )
            await push_status(offline_status_timeline, "✅ Finalizing response", max(1, len(offline_tool_calls)))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(offline_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": offline_tool_calls,
                "spl_query": extract_primary_spl_query(offline_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(offline_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": ["Used deterministic offline-event lookup with index and time-range fallbacks."],
                "status_timeline": offline_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        basic_intent = None
        if bool(chat_session_settings.get("enable_splunk_augmentation", True)) and not should_bypass_basic_inventory_intent(request):
            basic_intent = detect_basic_inventory_intent(user_message, chat_memory)
        if basic_intent:
            basic_status_timeline: List[Dict[str, Any]] = []
            basic_tool_calls: List[Dict[str, Any]] = []
            await push_status(basic_status_timeline, "🧭 Interpreting request with deterministic route", 0)

            if basic_intent == "list_indexes":
                indexes_tool_name = resolve_tool_name("splunk_get_indexes", available_mcp_tools)
                args = {"row_limit": 200}
                await push_status(basic_status_timeline, "📁 Loading indexes", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": indexes_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                names = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        candidate = row.get("title") or row.get("name")
                        if isinstance(candidate, str) and candidate.strip():
                            names.append(candidate.strip())
                names = sorted(list(dict.fromkeys(names)))
                response_text = "Available indexes:\n" + "\n".join([f"- {name}" for name in names[:80]]) if names else "No indexes were returned by Splunk."
                basic_tool_calls.append({"iteration": 1, "tool": indexes_tool_name, "args": args, "spl_query": None, "result": result, "summary": {"type": indexes_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(names)} indexes"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "list_sourcetypes":
                args = {"query": "| tstats count where index=* by sourcetype | sort - count | head 50", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "🧾 Loading sourcetypes", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                sourcetypes = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        value = row.get("sourcetype") or row.get("SOURCETYPE")
                        if isinstance(value, str) and value.strip():
                            sourcetypes.append(value.strip())
                sourcetypes = list(dict.fromkeys(sourcetypes))
                response_text = "Top sourcetypes (last 7d):\n" + "\n".join([f"- {value}" for value in sourcetypes[:50]]) if sourcetypes else "No sourcetypes were returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(sourcetypes)} sourcetypes"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "top_indexes":
                args = {"query": "| tstats count where index=* by index | sort - count | head 25", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "📊 Loading top indexes", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                lines: List[str] = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        idx_name = row.get("index") or row.get("INDEX")
                        count_value = row.get("count") or row.get("COUNT")
                        if idx_name is not None:
                            lines.append(f"- {idx_name}: {count_value if count_value is not None else 'n/a'}")
                response_text = "Top indexes by event count (last 7d):\n" + "\n".join(lines[:25]) if lines else "No index volume data was returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(lines)} index rows"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "top_errors":
                args = {"query": "search index=* (error OR failed OR exception) | stats count by sourcetype | sort - count | head 20", "earliest_time": "-24h", "latest_time": "now"}
                await push_status(basic_status_timeline, "🚨 Loading top error sources", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                lines = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        source_type = row.get("sourcetype") or row.get("SOURCETYPE") or "unknown"
                        count_value = row.get("count") or row.get("COUNT") or "n/a"
                        lines.append(f"- {source_type}: {count_value}")
                response_text = "Top error-producing sourcetypes (last 24h):\n" + "\n".join(lines[:20]) if lines else "No error-focused results were returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(lines)} error rows"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "latest_auth_failures":
                args = {"query": "search index=* (\"failed login\" OR \"authentication failed\" OR \"login failed\" OR \"invalid user\" OR action=failure) | sort - _time | head 20 | table _time host user src src_ip action status message sourcetype", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "🔐 Loading latest authentication failures", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                entries = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        entries.append(f"- {row.get('_time', 'unknown time')} | host={row.get('host', 'n/a')} | user={row.get('user', 'n/a')} | src={row.get('src', row.get('src_ip', 'n/a'))}")
                response_text = "Latest authentication failure events:\n" + "\n".join(entries[:20]) if entries else "No authentication failure events were returned in the last 7 days."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(entries)} auth failure events"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "count_index_events":
                target_index = extract_index_from_message(user_message)
                if not target_index:
                    response_text = "I could not identify the index name. Try a prompt like: 'how many events in index=main'."
                else:
                    args_24h = {"query": f"search index={target_index} | stats count as event_count", "earliest_time": "-24h", "latest_time": "now"}
                    args_7d = {"query": f"search index={target_index} | stats count as event_count", "earliest_time": "-7d", "latest_time": "now"}
                    await push_status(basic_status_timeline, f"📏 Counting events for index={target_index}", 1)
                    res_24h = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_24h}}, config)
                    res_7d = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_7d}}, config)
                    parsed_24h = extract_results_from_mcp_response(res_24h)
                    parsed_7d = extract_results_from_mcp_response(res_7d)
                    rows_24h = parsed_24h.get("results", []) if isinstance(parsed_24h, dict) else []
                    rows_7d = parsed_7d.get("results", []) if isinstance(parsed_7d, dict) else []

                    def _extract_count(rows: Any) -> int:
                        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                            row = rows[0]
                            for key in ["event_count", "count", "COUNT"]:
                                if key in row:
                                    return _safe_int(row.get(key))
                        return 0

                    count_24h = _extract_count(rows_24h)
                    count_7d = _extract_count(rows_7d)
                    response_text = f"Event counts for index `{target_index}`:\n- Last 24h: {count_24h}\n- Last 7d: {count_7d}"
                    basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args_24h, "spl_query": args_24h.get("query"), "result": res_24h, "summary": {"type": query_tool_name, "row_count": len(rows_24h) if isinstance(rows_24h, list) else 0, "findings": [f"24h count={count_24h}"], "actual_results": rows_24h[:5] if isinstance(rows_24h, list) else []}})
                    basic_tool_calls.append({"iteration": 2, "tool": query_tool_name, "args": args_7d, "spl_query": args_7d.get("query"), "result": res_7d, "summary": {"type": query_tool_name, "row_count": len(rows_7d) if isinstance(rows_7d, list) else 0, "findings": [f"7d count={count_7d}"], "actual_results": rows_7d[:5] if isinstance(rows_7d, list) else []}})

            elif basic_intent == "timechart_index_trend":
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                explicit_earliest, explicit_latest = extract_time_range_from_message(user_message)
                memory_window = chat_memory.get("last_result", {}) if isinstance(chat_memory, dict) and isinstance(chat_memory.get("last_result", {}), dict) else {}
                earliest_time = explicit_earliest or str(memory_window.get("earliest_time") or "-24h")
                latest_time = explicit_latest or str(memory_window.get("latest_time") or "now")

                if not target_index:
                    response_text = "I need an index anchor for the trend view. Try including an index, for example: 'Show a timechart for index=main over the last 24 hours'."
                else:
                    span = "1h" if earliest_time in {"-24h", "-7d"} else "1d"
                    args = {
                        "query": f"search index={target_index} | timechart span={span} count",
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                    }
                    await push_status(basic_status_timeline, f"📈 Building timechart for index={target_index}", 1)
                    result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                    parsed = extract_results_from_mcp_response(result)
                    rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                    lines = []
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict):
                            timestamp = row.get("_time") or row.get("time") or row.get("TIME") or "unknown"
                            count_value = row.get("count") or row.get("COUNT") or row.get("value") or 0
                            lines.append(f"- {timestamp}: {count_value}")
                    response_text = (
                        f"Event volume trend for index `{target_index}` ({_describe_time_window(earliest_time, latest_time)}):\n"
                        + "\n".join(lines[:24])
                    ) if lines else f"No trend data was returned for index `{target_index}` in {_describe_time_window(earliest_time, latest_time)}."
                    basic_tool_calls.append({
                        "iteration": 1,
                        "tool": query_tool_name,
                        "args": args,
                        "spl_query": args.get("query"),
                        "result": result,
                        "summary": {
                            "type": query_tool_name,
                            "row_count": len(rows) if isinstance(rows, list) else 0,
                            "findings": [f"Found {len(lines)} timechart buckets"],
                            "actual_results": rows[:8] if isinstance(rows, list) else []
                        }
                    })

            elif basic_intent == "breakdown_index":
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                explicit_earliest, explicit_latest = extract_time_range_from_message(user_message)
                memory_window = chat_memory.get("last_result", {}) if isinstance(chat_memory, dict) and isinstance(chat_memory.get("last_result", {}), dict) else {}
                earliest_time = explicit_earliest or str(memory_window.get("earliest_time") or "-24h")
                latest_time = explicit_latest or str(memory_window.get("latest_time") or "now")

                if not target_index:
                    response_text = "I need an index anchor for the breakdown. Try including an index, for example: 'Break down index=main by sourcetype and host'."
                else:
                    args = {
                        "query": f"search index={target_index} | stats count by sourcetype host | sort - count | head 20",
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                    }
                    await push_status(basic_status_timeline, f"🧩 Breaking down index={target_index}", 1)
                    result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                    parsed = extract_results_from_mcp_response(result)
                    rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                    lines = []
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict):
                            sourcetype = row.get("sourcetype") or row.get("SOURCETYPE") or "unknown"
                            host = row.get("host") or row.get("HOST") or "unknown"
                            count_value = row.get("count") or row.get("COUNT") or 0
                            lines.append(f"- sourcetype={sourcetype} | host={host} | count={count_value}")
                    response_text = (
                        f"Top sourcetype and host breakdown for index `{target_index}` ({_describe_time_window(earliest_time, latest_time)}):\n"
                        + "\n".join(lines[:20])
                    ) if lines else f"No breakdown rows were returned for index `{target_index}` in {_describe_time_window(earliest_time, latest_time)}."
                    basic_tool_calls.append({
                        "iteration": 1,
                        "tool": query_tool_name,
                        "args": args,
                        "spl_query": args.get("query"),
                        "result": result,
                        "summary": {
                            "type": query_tool_name,
                            "row_count": len(rows) if isinstance(rows, list) else 0,
                            "findings": [f"Found {len(lines)} breakdown rows"],
                            "actual_results": rows[:8] if isinstance(rows, list) else []
                        }
                    })

            elif basic_intent == "baseline_index_check":
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                if not target_index:
                    response_text = "I need an index anchor for the baseline check. Try including an index, for example: 'Run a baseline count check for index=main'."
                else:
                    args_24h = {"query": f"search index={target_index} | stats count as event_count", "earliest_time": "-24h", "latest_time": "now"}
                    args_7d = {"query": f"search index={target_index} | stats count as event_count", "earliest_time": "-7d", "latest_time": "now"}
                    await push_status(basic_status_timeline, f"📏 Running baseline checks for index={target_index}", 1)
                    res_24h = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_24h}}, config)
                    res_7d = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_7d}}, config)
                    parsed_24h = extract_results_from_mcp_response(res_24h)
                    parsed_7d = extract_results_from_mcp_response(res_7d)
                    rows_24h = parsed_24h.get("results", []) if isinstance(parsed_24h, dict) else []
                    rows_7d = parsed_7d.get("results", []) if isinstance(parsed_7d, dict) else []

                    def _extract_count(rows: Any) -> int:
                        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                            row = rows[0]
                            for key in ["event_count", "count", "COUNT"]:
                                if key in row:
                                    return _safe_int(row.get(key))
                        return 0

                    count_24h = _extract_count(rows_24h)
                    count_7d = _extract_count(rows_7d)
                    availability = "Data is available" if count_7d > 0 else "No data was found"
                    response_text = (
                        f"Baseline check for index `{target_index}`:\n"
                        f"- Last 24h: {count_24h}\n"
                        f"- Last 7d: {count_7d}\n"
                        f"- Assessment: {availability}."
                    )
                    basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args_24h, "spl_query": args_24h.get("query"), "result": res_24h, "summary": {"type": query_tool_name, "row_count": len(rows_24h) if isinstance(rows_24h, list) else 0, "findings": [f"24h count={count_24h}"], "actual_results": rows_24h[:5] if isinstance(rows_24h, list) else []}})
                    basic_tool_calls.append({"iteration": 2, "tool": query_tool_name, "args": args_7d, "spl_query": args_7d.get("query"), "result": res_7d, "summary": {"type": query_tool_name, "row_count": len(rows_7d) if isinstance(rows_7d, list) else 0, "findings": [f"7d count={count_7d}"], "actual_results": rows_7d[:5] if isinstance(rows_7d, list) else []}})

            elif basic_intent == "host_pivot":
                target_host = extract_host_or_ip_from_message(user_message) or _remembered_entity(chat_memory, "host")
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                explicit_earliest, explicit_latest = extract_time_range_from_message(user_message)
                memory_window = chat_memory.get("last_result", {}) if isinstance(chat_memory, dict) and isinstance(chat_memory.get("last_result", {}), dict) else {}
                earliest_time = explicit_earliest or str(memory_window.get("earliest_time") or "-24h")
                latest_time = explicit_latest or str(memory_window.get("latest_time") or "now")

                if not target_host:
                    response_text = "I need a host or IP to pivot on. Try including a host, for example: 'Pivot on host=router-01 and identify related anomalies'."
                else:
                    search_scope = f"index={target_index} " if target_index else "index=* "
                    args = {
                        "query": f"search {search_scope}host=\"{target_host}\" | stats count by sourcetype source | sort - count | head 20",
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                    }
                    await push_status(basic_status_timeline, f"🖥️ Pivoting on host={target_host}", 1)
                    result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                    parsed = extract_results_from_mcp_response(result)
                    rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                    lines = []
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict):
                            sourcetype = row.get("sourcetype") or row.get("SOURCETYPE") or "unknown"
                            source = row.get("source") or row.get("SOURCE") or "unknown"
                            count_value = row.get("count") or row.get("COUNT") or 0
                            lines.append(f"- sourcetype={sourcetype} | source={source} | count={count_value}")
                    response_text = (
                        f"Host pivot for `{target_host}` ({_describe_time_window(earliest_time, latest_time)}):\n"
                        + "\n".join(lines[:20])
                    ) if lines else f"No host pivot rows were returned for `{target_host}` in {_describe_time_window(earliest_time, latest_time)}."
                    basic_tool_calls.append({
                        "iteration": 1,
                        "tool": query_tool_name,
                        "args": args,
                        "spl_query": args.get("query"),
                        "result": result,
                        "summary": {
                            "type": query_tool_name,
                            "row_count": len(rows) if isinstance(rows, list) else 0,
                            "findings": [f"Found {len(lines)} host pivot rows"],
                            "actual_results": rows[:8] if isinstance(rows, list) else []
                        }
                    })

            elif basic_intent == "latest_host_heartbeat":
                target_host = extract_host_or_ip_from_message(user_message)
                if not target_host and isinstance(chat_memory, dict):
                    remembered_hosts = chat_memory.get("entities", {}).get("hosts", [])
                    if isinstance(remembered_hosts, list) and remembered_hosts:
                        target_host = remembered_hosts[-1]

                if not target_host:
                    response_text = "I could not identify the host/IP. Try: 'last seen host=router-01' or include an IP address."
                else:
                    attempts = [
                        {"query": f"search index=* host=\"{target_host}\" (heartbeat OR alive OR uptime OR status=up OR status=online) | sort - _time | head 1 | table _time host sourcetype source message", "earliest_time": "-7d", "latest_time": "now"},
                        {"query": f"search index=* host=\"{target_host}\" | sort - _time | head 1 | table _time host sourcetype source message", "earliest_time": "-30d", "latest_time": "now"}
                    ]
                    found_row = None
                    for attempt_idx, args in enumerate(attempts, 1):
                        await push_status(basic_status_timeline, f"📡 Checking last-seen for {target_host}", attempt_idx)
                        result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                        parsed = extract_results_from_mcp_response(result)
                        rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                        basic_tool_calls.append({"iteration": attempt_idx, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Attempt {attempt_idx}: {len(rows) if isinstance(rows, list) else 0} rows"], "actual_results": rows[:5] if isinstance(rows, list) else []}})
                        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                            found_row = rows[0]
                            break

                    if found_row:
                        response_text = (
                            f"Latest event for `{target_host}`:\n"
                            f"- Time: {found_row.get('_time', 'unknown')}\n"
                            f"- Sourcetype: {found_row.get('sourcetype', 'n/a')}\n"
                            f"- Source: {found_row.get('source', 'n/a')}"
                        )
                    else:
                        response_text = f"No events found for `{target_host}` in the attempted heartbeat/last-seen windows."

            elif basic_intent == "list_hosts":
                args = {"query": "| tstats count where index=* by host | sort - count | head 50", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "🖥️ Loading hosts", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                hosts = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        value = row.get("host") or row.get("HOST")
                        if isinstance(value, str) and value.strip():
                            hosts.append(value.strip())
                hosts = list(dict.fromkeys(hosts))
                response_text = "Top hosts (last 7d):\n" + "\n".join([f"- {value}" for value in hosts[:50]]) if hosts else "No hosts were returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(hosts)} hosts"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            else:
                knowledge_tool_name = resolve_tool_name("splunk_get_knowledge_objects", available_mcp_tools)
                args = {"row_limit": 500}
                await push_status(basic_status_timeline, "📚 Loading knowledge objects", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": knowledge_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                templates = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        title = str(row.get("title") or row.get("name") or "").strip()
                        searchable = f"{title} {row.get('description', '')} {row.get('search', '')}".lower()
                        if title and "template" in searchable:
                            templates.append(title)
                templates = list(dict.fromkeys(templates))
                response_text = "Template-like knowledge objects:\n" + "\n".join([f"- {value}" for value in templates[:60]]) if templates else "No template-like knowledge objects were returned."
                basic_tool_calls.append({"iteration": 1, "tool": knowledge_tool_name, "args": args, "spl_query": None, "result": result, "summary": {"type": knowledge_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(templates)} template-like objects"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            await push_status(basic_status_timeline, "✅ Finalizing response", max(1, len(basic_tool_calls)))
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                basic_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                basic_tool_calls,
                assistant_response=response_text,
            )
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(basic_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": basic_tool_calls,
                "spl_query": extract_primary_spl_query(basic_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(basic_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": [f"Used deterministic basic intent route: {basic_intent}."],
                "status_timeline": basic_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }
        
        rag_context = ""
        capability_usage: List[Dict[str, Any]] = []
        if bool(chat_session_settings.get("enable_rag_context", False)):
            rag_max_chunks = _safe_int(chat_session_settings.get("rag_max_chunks", 3))
            rag_context, capability_usage = get_optional_rag_context(user_message, max_chunks=rag_max_chunks)

        # Initialize LLM client (cached for performance)
        print(f"🔵 [CHAT] Getting LLM client...")
        llm_client = get_or_create_llm_client(config)
        print(f"🔵 [CHAT] LLM client initialized, provider: {config.llm.provider}")
        chat_runtime_profile = build_chat_runtime_profile(config, llm_client)
        runtime_temperature = max(0.0, config.llm.temperature * chat_runtime_profile["temperature_multiplier"])
        print(
            f"🔵 [CHAT] Runtime profile: provider={chat_runtime_profile['provider']} "
            f"model={chat_runtime_profile['model'] or getattr(config.llm, 'model', '')} "
            f"compact={chat_runtime_profile['use_compact_prompt']} "
            f"context_limit={chat_runtime_profile['context_history_limit']} "
            f"initial_max_tokens={chat_runtime_profile['initial_max_tokens']}"
        )
        
        # Use simplified prompt for custom endpoints (local LLMs have smaller context windows)
        if is_custom_provider:
            system_prompt = f"""You are a Splunk assistant. Answer from this context or use tools when needed.

{discovery_context}
{rag_context}
{memory_context}

    Tool format: <TOOL_CALL>{{"tool": "{query_tool_name}", "args": {{"query": "YOUR_SPL_HERE"}}}}</TOOL_CALL>"""
        else:
            # Full agentic prompt for OpenAI (larger context window, better instruction following)
            system_prompt = f"""You are an ELITE Splunk expert with 20+ years of experience across:
- 🛡️ Cybersecurity (threat hunting, incident response, forensics)
- 🌐 Networking (traffic analysis, firewall logs, network monitoring)
- 🖥️ System Administration (Windows/Linux logs, performance monitoring)
- 🔧 IT Operations (infrastructure monitoring, capacity planning)
- 🚀 DevOps (CI/CD monitoring, application performance)
- 💾 Database Administration (query optimization, audit logging)
- ✅ Compliance & Auditing (PCI-DSS, HIPAA, SOX, GDPR)

🌍 ENVIRONMENT CONTEXT:
{discovery_context}
{rag_context}
{discovery_age_warning if 'discovery_age_warning' in locals() else ''}
{memory_context}

📊 DISCOVERY DATA AVAILABLE:
Latest discovery reports are available in the output/ folder with comprehensive insights:
- Executive Summary: High-level findings and recommendations
- Detailed Discovery: Complete environment inventory
- Data Classification: Data sensitivity and retention analysis
- Implementation Guide: Best practices and optimization tips
- Use Case Suggestions: Security, compliance, and ops recommendations

💡 WHEN TO REFERENCE DISCOVERY DATA:
- User asks about "overall environment", "summary", "recommendations"
- Query returns insufficient data - check discovery for historical context
- Need to understand data patterns, retention, or volume trends
- Questions about best practices, optimization, or use cases

🎯 YOUR SUPERPOWERS:
You are an AUTONOMOUS AGENT with the ability to:
1. Execute multiple queries in sequence to solve complex problems
2. Learn from errors and automatically retry with improved approaches
3. Break down complex questions into smaller investigative steps
4. Cross-reference data across multiple indexes and time ranges
5. Provide deep insights, not just raw data

🔧 AVAILABLE TOOLS:
{available_tools_text}

📚 REQUEST ADDITIONAL CONTEXT (On-Demand):
If you need detailed information, request it dynamically:
<CONTEXT_REQUEST>type</CONTEXT_REQUEST>
Available types: indexes, sourcetypes, hosts, alerts, dashboards, users, kv_stores

⚡ AUTONOMOUS REASONING PROTOCOL:
When you execute a tool and receive results, you can CONTINUE investigating by:
1. **If Error**: Analyze what went wrong and try a different approach
   - Bad syntax? Fix the SPL and retry
   - Index doesn't exist? Query discovery context for correct index
   - No data? Try broader time range or different index
   - WHERE clause error? Break into simpler queries

2. **If No Data**: Don't give up! Investigate further:
   - Try other relevant indexes from the discovery context
   - Expand the time range (e.g., -7d instead of -24h)
   - Simplify search criteria
   - Check if the index is disabled or empty

3. **If Successful**: Decide if you need more data:
   - Does this fully answer the user's question?
   - Would additional context make the answer better?
   - Should you cross-reference with other data sources?

🎨 TOOL EXECUTION FORMAT:
⚠️ CRITICAL: If the user's question requires querying Splunk data, you MUST provide a <TOOL_CALL> in your response.
Do NOT say "I'll execute a query" or "Let me check" without actually providing the tool call.
Either answer directly from your knowledge, OR include a <TOOL_CALL> block.

⚠️ JSON FORMATTING: When writing SPL queries, use SINGLE quotes (') for string literals in your query, NOT double quotes (").
Example: relative_time(now(), '-7d') NOT relative_time(now(), "-7d")
This prevents JSON parsing errors.

Always use this exact format for tool calls:

<TOOL_CALL>
{{
    "tool": "{query_tool_name}",
  "args": {{
    "query": "index=wineventlog earliest=-24h | stats count by EventCode | sort -count | head 10",
    "earliest_time": "-24h",
    "latest_time": "now"
  }}
}}
</TOOL_CALL>

I'm checking the top 10 event codes in the wineventlog index from the last 24 hours.

💡 EXPERT BEHAVIORS - BE THE SPLUNK GOD:

**1. Think Like a Cybersecurity Expert:**
- Identify security risks, anomalies, and indicators of compromise
- Suggest correlation searches and threat hunting queries
- Recommend security use cases (failed logins, privilege escalation, data exfiltration)

**2. Think Like a Network Engineer:**
- Analyze traffic patterns, bandwidth usage, and network performance
- Identify network bottlenecks and connectivity issues
- Suggest monitoring for DNS, firewall, and VPN logs

**3. Think Like a System Administrator:**
- Monitor system health, resource utilization, and errors
- Identify performance degradation and capacity issues
- Recommend alerting for critical system events

**4. Think Like a Compliance Officer:**
- Identify audit requirements and data retention policies
- Suggest searches for compliance reporting (PCI-DSS, HIPAA, SOX)
- Recommend data classification and access controls

**5. Think Like a Data Scientist:**
- Provide statistical analysis and trend identification
- Suggest correlations and predictive insights
- Visualize data patterns and anomalies

**6. Be Proactive & Educate:**
- Don't just answer - teach WHY and provide context
- Suggest related investigations users should consider
- Recommend best practices and optimization opportunities
- Warn about potential security/performance issues you notice

**7. Leverage Intelligence:**
- Reference discovery insights for strategic recommendations
- Cross-reference multiple data sources for complete picture
- If discovery data is stale (>7 days), recommend re-running discovery

📊 RESPONSE PATTERNS:

**For Data Questions:**
<TOOL_CALL>...</TOOL_CALL>
[Explain what you're investigating]

[After getting results, either provide final answer OR make another TOOL_CALL if needed]

**For Explanations:**
[Provide detailed explanation with examples]

**For Complex Investigations:**
<TOOL_CALL>...</TOOL_CALL>
[Explain step 1]
[Wait for results]
<TOOL_CALL>...</TOOL_CALL>
[Explain step 2 based on step 1 results]
[Continue until question fully answered]

🚀 EXAMPLE AUTONOMOUS REASONING:

User: "What indexes have data between 22:00 and 23:00 last Tuesday?"

You: <TOOL_CALL>
{{
    "tool": "{query_tool_name}",
  "args": {{
    "query": "| tstats count where _time>=relative_time(now(), \"-7d@d+22h\") AND _time<relative_time(now(), \"-7d@d+23h\") by index",
    "earliest_time": "-7d",
    "latest_time": "now"
  }}
}}
</TOOL_CALL>

I'm querying all indexes for data during the 22:00-23:00 hour last Tuesday using tstats for fast results.

[If this errors with WHERE clause issue]

<TOOL_CALL>
{{
    "tool": "{query_tool_name}",
  "args": {{
    "query": "earliest=-7d latest=now index=wineventlog | where _time>=relative_time(now(), \"-7d@d+22h\") AND _time<relative_time(now(), \"-7d@d+23h\") | stats count",
    "earliest_time": "-7d",
    "latest_time": "now"
  }}
}}
</TOOL_CALL>

The tstats approach had a WHERE clause issue, so I'm checking the wineventlog index first with a standard search approach. I'll iterate through other indexes based on results.

Remember: You are AUTONOMOUS. Don't stop at the first error or empty result. Investigate thoroughly until you find the answer or exhaust all reasonable options."""
        
        # Prepare messages
        # Use the compact prompt only for custom/local providers; OpenAI-class providers keep the richer agent prompt above.
        if chat_runtime_profile["use_compact_prompt"]:
            system_prompt = build_compact_chat_prompt(
                query_tool_name=query_tool_name,
                discovery_context=discovery_context,
                rag_context=rag_context,
                memory_context=memory_context,
                available_tools_text=available_tools_text,
                discovery_age_warning=discovery_age_warning
            )
            if chat_runtime_profile["reasoning_guard"]:
                system_prompt = f"{system_prompt}\n{chat_runtime_profile['reasoning_guard']}"

        context_limit = chat_runtime_profile["context_history_limit"]
        continuity_context = build_llm_continuity_context(
            user_message=user_message,
            history=history,
            memory=chat_memory,
            limit=context_limit,
        )
        has_session_context = bool(_build_llm_recent_context_turns(history, chat_memory, limit=max(2, context_limit)))
        requires_spl_explanation = user_requested_spl_explanation(user_message)
        spl_explanation_requirement = build_spl_explanation_requirement(requires_spl_explanation)

        query_lower = user_message.lower().strip()
        is_greeting = any(phrase in query_lower for phrase in ['hi', 'hello', 'hey', 'how are you', 'thanks', 'thank you', 'bye', 'goodbye'])
        
        if chat_runtime_profile["short_circuit_greetings"] and is_greeting and not has_session_context:
            # Bare minimum for greetings - just the user message
            messages = [{"role": "user", "content": user_message}]
        else:
            # Always rebuild the prompt gate so the latest memory, discovery context, and continuity rules are fresh.
            has_role_history = bool(history and len(history) > 0 and isinstance(history[0], dict) and 'role' in history[0])
            messages = [{"role": "system", "content": system_prompt}]
            if continuity_context:
                messages.append({"role": "system", "content": continuity_context})

            normalized_history = []
            if has_role_history:
                normalized_history = _compact_chat_role_history(history, limit=context_limit, include_system=False)
            else:
                normalized_history = history[-context_limit:] if context_limit > 0 else []

            for msg in normalized_history:
                if has_role_history:
                    messages.append({"role": msg["role"], "content": msg["content"]})
                elif msg.get('type') == 'user':
                    messages.append({"role": "user", "content": msg['content']})
                elif msg.get('type') == 'assistant':
                    messages.append({"role": "assistant", "content": msg['content']})

            if query_plan_context:
                messages.append({"role": "system", "content": query_plan_context})

            # Add current user message
            messages.append({"role": "user", "content": user_message})
        
        # Get LLM response - use session max_tokens setting (with 15% limit for initial chat)
        status_timeline: List[Dict[str, Any]] = []
        await push_status(status_timeline, "🧠 Building investigation plan", 0)
        chat_max_tokens = chat_runtime_profile["initial_max_tokens"]
        print(f"🔵 [CHAT] Calling LLM with {len(messages)} messages, max_tokens={chat_max_tokens}")
        print(f"🔵 [CHAT] Client type: {type(llm_client)}, has generate_response: {hasattr(llm_client, 'generate_response')}")
        print(f"🔵 [CHAT] About to await generate_response...")
        response = await llm_client.generate_response(
            messages=messages,
            max_tokens=chat_max_tokens,
            temperature=runtime_temperature
        )
        print(f"🔵 [CHAT] Got response: {len(response)} chars")
        
        # Check if response contains tool call or SPL
        tool_call = None
        spl_in_text = None
        clean_response = sanitize_llm_response_text(response)
        
        try:
            # Extract context requests using <CONTEXT_REQUEST> tags
            context_request_match = re.search(r'<CONTEXT_REQUEST>(.*?)</CONTEXT_REQUEST>', response, re.DOTALL)
            if context_request_match:
                requested_context_type = context_request_match.group(1).strip()
                debug_log(f"LLM requested context: {requested_context_type}", "info")
                
                # Load the requested context
                try:
                    ctx_mgr = get_context_manager()
                    specific_context = ctx_mgr.get_specific_context(requested_context_type)
                    
                    if specific_context:
                        formatted_context = ctx_mgr.format_context_for_llm({requested_context_type: specific_context})
                        
                        # Inject context into conversation before next LLM call
                        messages.append({
                            "role": "system",
                            "content": f"[Context loaded: {requested_context_type}]\n{formatted_context}"
                        })
                        
                        # Remove context request from response
                        clean_response = re.sub(r'<CONTEXT_REQUEST>.*?</CONTEXT_REQUEST>', '', clean_response, flags=re.DOTALL).strip()
                        
                        debug_log(f"Injected {requested_context_type} context into conversation", "info")
                except Exception as e:
                    debug_log(f"Error loading requested context: {e}", "error")
            default_earliest, default_latest = extract_time_range_from_message(user_message)
            default_earliest = default_earliest or "-24h"
            default_latest = default_latest or "now"

            tool_call = extract_recoverable_tool_call(
                response,
                query_tool_name,
                default_earliest=default_earliest,
                default_latest=default_latest,
            )
            if tool_call:
                extracted_name = tool_call.get("params", {}).get("name")
                extracted_args = tool_call.get("params", {}).get("arguments", {})
                clean_response = sanitize_llm_response_text(response)
                if extracted_name in {query_tool_name, "splunk_run_query", "run_splunk_query"}:
                    spl_in_text = str(extracted_args.get("query", "")).strip() or None
                debug_log(f"Recovered tool call - {extracted_name} with args: {extracted_args}", "query", extracted_args)
                    
        except Exception as e:
            debug_log(f"Error parsing response: {e}", "error")
            import traceback
            traceback.print_exc()
        
        if tool_call and tool_call.get('method') == 'tools/call':
            # ===== INTELLIGENT AGENTIC LOOP WITH QUALITY-DRIVEN STOPPING =====
            import time as time_module
            
            await push_status(status_timeline, "🛠 Tool plan created", 0)
            start_time = request_started_at
            # Use session settings (allow runtime tuning without restart)
            max_execution_time = chat_session_settings["max_execution_time"]
            max_iterations = chat_session_settings["max_iterations"]
            quality_threshold = chat_session_settings["quality_threshold"]
            convergence_threshold = chat_session_settings["convergence_detection"]
            sample_size = chat_session_settings["query_sample_size"]
            
            iteration = 0
            conversation_history = messages.copy()
            all_tool_calls = []
            accumulated_insights = []  # Track key findings across iterations
            final_answer = None
            user_intent = user_message  # Track refined understanding of user's goal
            
            # Helper function to summarize results for context efficiency
            def summarize_result(result_data, tool_name):
                """Extract key insights from results without full JSON dump"""
                summary = {"type": tool_name, "findings": []}
                is_query_tool = tool_name in {"run_splunk_query", "splunk_run_query"}
                is_metadata_tool = tool_name in {
                    "get_indexes", "splunk_get_indexes",
                    "get_metadata", "splunk_get_metadata"
                }
                
                if isinstance(result_data, dict):
                    if 'error' in result_data:
                        return {"type": "error", "message": result_data.get('error', 'Unknown error')}
                    
                    result = result_data.get('result', {})
                    
                    actual_results = None
                    structured_status_code = None
                    structured_error_message = ""

                    # GA v1 shape: result.structuredContent.results
                    if isinstance(result, dict):
                        structured_content = result.get('structuredContent', {})
                        if isinstance(structured_content, dict):
                            structured_status_code = structured_content.get('status_code')
                            if isinstance(structured_content.get('content'), str):
                                structured_error_message = structured_content.get('content', '')
                            if isinstance(structured_content.get('results'), list):
                                actual_results = structured_content.get('results', [])

                    if isinstance(structured_status_code, int) and structured_status_code >= 400:
                        return {
                            "type": "error",
                            "message": structured_error_message or f"MCP tool execution failed with status_code={structured_status_code}"
                        }

                    # Legacy/direct shape: result.results
                    if actual_results is None and isinstance(result, dict) and isinstance(result.get('results'), list):
                        actual_results = result.get('results', [])

                    # Legacy text-wrapper shape: result.content[0].text JSON
                    if actual_results is None and isinstance(result, dict) and 'content' in result:
                        content_items = result.get('content', [])
                        if content_items and len(content_items) > 0:
                            first_item = content_items[0]
                            if isinstance(first_item, dict) and 'text' in first_item:
                                try:
                                    parsed_text = json.loads(first_item['text'])
                                    if isinstance(parsed_text, dict) and isinstance(parsed_text.get('results'), list):
                                        actual_results = parsed_text.get('results', [])
                                    elif isinstance(parsed_text, list):
                                        actual_results = parsed_text
                                except json.JSONDecodeError as e:
                                    print(f"⚠️  Failed to parse MCP content text as JSON: {e}")
                    
                    # Summarize based on tool type
                    if is_query_tool:
                        results_array = actual_results if isinstance(actual_results, list) else None
                        
                        if results_array is not None:
                            result_count = len(results_array)
                            summary['row_count'] = result_count  # Set for quality assessment
                            summary['findings'].append(f"{result_count} results returned")
                            
                            if result_count > 0:
                                # Extract key fields from first few results
                                sample = results_array[:3]
                                summary['sample_fields'] = list(sample[0].keys()) if sample else []
                                summary['findings'].append(f"Sample fields: {', '.join(summary['sample_fields'][:5])}")
                                
                                # Check for specific interesting patterns
                                if result_count > 100:
                                    summary['findings'].append("⚠️ Large result set - may need filtering")
                                
                                # Store actual results for later use
                                summary['actual_results'] = results_array[:5]  # First 5 for context
                                row_analysis = analyze_result_rows(results_array)
                                if row_analysis:
                                    summary.update(row_analysis)
                                    if row_analysis.get('query_shape'):
                                        summary['findings'].append(f"Result shape: {row_analysis['query_shape']}")
                                    if row_analysis.get('top_dimensions'):
                                        top_dimension = row_analysis['top_dimensions'][0]
                                        if isinstance(top_dimension, dict) and top_dimension.get('field') and top_dimension.get('values'):
                                            summary['findings'].append(
                                                f"Top {top_dimension['field']}: {', '.join(top_dimension['values'][:3])}"
                                            )
                                    if row_analysis.get('time_bounds'):
                                        bounds = row_analysis['time_bounds']
                                        if isinstance(bounds, dict) and bounds.get('field'):
                                            summary['findings'].append(
                                                f"Time bounds from {bounds.get('field')}: {bounds.get('first', 'unknown')} -> {bounds.get('last', 'unknown')}"
                                            )
                            else:
                                summary['findings'].append("❌ No data found")
                        elif 'fields' in result:
                            summary['row_count'] = len(result['fields'])  # Metadata query
                            summary['findings'].append(f"Metadata query: {len(result['fields'])} fields")
                        else:
                            summary['row_count'] = 0  # No results found
                            summary['findings'].append("⚠️ No results field found in response")
                    
                    elif is_metadata_tool:
                        results_array = actual_results if isinstance(actual_results, list) else None
                        
                        if results_array is not None:
                            result_count = len(results_array)
                            summary['row_count'] = result_count
                            summary['findings'].append(f"Found {result_count} items")
                            
                            if result_count > 0:
                                # Store actual results for LLM context
                                summary['actual_results'] = results_array
                                
                                # Extract sample fields from first item
                                sample = results_array[0] if results_array else {}
                                if isinstance(sample, dict):
                                    summary['sample_fields'] = list(sample.keys())
                                    summary['findings'].append(f"Fields: {', '.join(list(sample.keys())[:5])}")
                                row_analysis = analyze_result_rows(results_array)
                                if row_analysis:
                                    summary.update(row_analysis)
                                    if row_analysis.get('top_dimensions'):
                                        top_dimension = row_analysis['top_dimensions'][0]
                                        if isinstance(top_dimension, dict) and top_dimension.get('field') and top_dimension.get('values'):
                                            summary['findings'].append(
                                                f"Top {top_dimension['field']}: {', '.join(top_dimension['values'][:3])}"
                                            )
                            else:
                                summary['findings'].append("❌ No items found")
                        else:
                            summary['row_count'] = 0
                            summary['findings'].append("⚠️ No results field found in response")
                
                return summary
            
            # Helper function to assess answer completeness (separate from investigation status)
            def assess_answer_quality(response_text, results_summary, has_actionable_data):
                """Determine if we have a complete, useful answer for the user"""
                score = 0
                reasons = []
                
                # HIGH VALUE: Did we get actionable data?
                if has_actionable_data:
                    score += 40
                    reasons.append("✅ Retrieved actionable data")
                else:
                    score -= 10  # Less harsh penalty - investigation takes time
                    reasons.append("❌ No actionable data yet")
                
                # MEDIUM VALUE: Is the response substantive?
                if len(response_text) > 200:
                    score += 15
                    reasons.append("📝 Detailed explanation")
                
                # HIGH VALUE: Conclusive analysis provided?
                conclusive_phrases = ['found that', 'shows that', 'indicates', 'based on', 'analysis reveals', 
                                     'the answer is', 'results show', 'this means', 'conclusion:', 'summary:']
                if any(phrase in response_text.lower() for phrase in conclusive_phrases):
                    score += 25
                    reasons.append("🎯 Conclusive analysis")
                
                # NEGATIVE: Contains errors or uncertainty
                if 'error' in response_text.lower() or 'unable to' in response_text.lower():
                    score -= 15
                    reasons.append("⚠️ Contains errors/uncertainty")
                
                # CONTEXT: Check if we're making progress
                if len(results_summary.get('findings', [])) > 0:
                    score += 10
                    reasons.append("📊 Investigation progressing")
                
                return max(0, min(100, score)), reasons  # Clamp to 0-100
            
            # Helper to detect if we're stuck in a loop
            def detect_convergence(accumulated_insights, tool_history):
                """Check if we're repeating similar queries without making progress"""
                # Need minimum iterations before checking convergence (use session setting)
                if len(tool_history) < convergence_threshold:
                    return False
                
                # Check if data quality is IMPROVING - don't stop if getting better results
                if len(tool_history) >= 2:
                    last_two = tool_history[-2:]
                    # Compare row counts from summaries
                    last_count = last_two[-1].get('summary', {}).get('row_count', 0)
                    prev_count = last_two[-2].get('summary', {}).get('row_count', 0)
                    
                    # If we're getting MORE data or BETTER fields, keep going
                    if last_count > prev_count:
                        return False  # Improving - don't stop
                    
                    # Check if field count is increasing (more detailed results)
                    last_fields = len(last_two[-1].get('summary', {}).get('sample_fields', []))
                    prev_fields = len(last_two[-2].get('summary', {}).get('sample_fields', []))
                    if last_fields > prev_fields:
                        return False  # Getting richer data - keep going
                
                # Check if last queries are TRULY identical (not just similar)
                # Extract just the SPL query strings, normalize whitespace
                recent_spl_queries = []
                for call in tool_history[-convergence_threshold:]:
                    params = call.get('args', {}) if isinstance(call.get('args', {}), dict) else call.get('params', {})
                    if 'query' in params:
                        # Normalize: remove whitespace differences, lowercase for comparison
                        query = ' '.join(params['query'].lower().split())
                        recent_spl_queries.append(query)
                
                # If all N queries are EXACTLY the same, it's true convergence
                if len(recent_spl_queries) == convergence_threshold and len(set(recent_spl_queries)) == 1:
                    return True  # Exact same query N times in a row
                
                return False
            
            while True:
                iteration += 1
                elapsed = time_module.time() - start_time

                if iteration > max_iterations:
                    print(f"🛑 Max iterations reached ({max_iterations})")
                    final_answer = (
                        f"I reached the configured limit of {max_iterations} investigation steps.\n\n"
                        f"Key findings so far:\n" + "\n".join([f"• {insight}" for insight in accumulated_insights[-8:]])
                    )
                    break
                
                # Safety valve: timeout check
                if elapsed > max_execution_time:
                    print(f"⏱️ Timeout reached after {elapsed:.1f}s and {iteration} iterations")
                    final_answer = f"I've spent {iteration} iterations investigating this query. Here's what I've found:\n\n" + "\n".join([f"• {insight}" for insight in accumulated_insights])
                    break
                
                # Execute the current tool call
                tool_name = tool_call['params']['name']
                tool_args = tool_call['params'].get('arguments', {})
                
                print(f"🔄 [Iteration {iteration}] Executing: {tool_name}")
                print(f"   Time elapsed: {elapsed:.1f}s")
                
                # Add status update (both to timeline and stream if callback provided)
                action = "🔍 Querying Splunk" if tool_name in {'run_splunk_query', 'splunk_run_query'} else f"⚙️ Executing {tool_name}"
                status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                if status_callback:
                    await status_callback(action, iteration, elapsed)
                
                mcp_result = await execute_mcp_tool_call(tool_call, config)
                
                # Check for fatal errors - stop immediately, don't retry
                if isinstance(mcp_result, dict) and mcp_result.get('fatal'):
                    error_detail = mcp_result.get('detail', 'Fatal error occurred')
                    status_code = mcp_result.get('status_code', 0)
                    print(f"🛑 FATAL ERROR - Stopping discovery")
                    print(f"   Status {status_code}: {error_detail}")
                    
                    # Provide helpful error messages based on status code
                    if status_code == 401:
                        error_type = "Authentication Failed"
                        suggestions = """**Please check:**
1. Your MCP Token is correct in the settings
2. The token has not expired
3. The token has proper permissions to access the Splunk instance"""
                    elif status_code == 403:
                        error_type = "Access Forbidden"
                        suggestions = """**Please check:**
1. Your MCP Token has proper permissions
2. The Splunk user associated with the token has access to the required resources
3. Network/firewall rules allow access"""
                    elif status_code == 404:
                        error_type = "MCP Endpoint Not Found"
                        suggestions = """**Please check:**
1. The MCP URL is correct in the settings
2. The Splunk MCP server is running
3. The endpoint path is correct (typically /services/mcp)"""
                    else:
                        error_type = "Connection Error"
                        suggestions = """**Please check:**
1. The MCP server is accessible
2. Network connectivity is working
3. Firewall/proxy settings allow the connection"""
                    
                    final_answer = f"""❌ **{error_type}**

The Splunk MCP server returned a {status_code} error:

```
{error_detail}
```

{suggestions}

Discovery has been stopped to avoid repeated failed attempts."""
                    
                    break  # Exit the main loop immediately
                
                # Get relevant context after tool execution to help LLM interpret results
                try:
                    ctx_mgr = get_context_manager()
                    post_tool_context = ctx_mgr.get_context_after_tool_call(
                        tool_name=tool_name,
                        tool_args=tool_args,
                        tool_result=mcp_result
                    )
                    
                    if post_tool_context:
                        debug_log(f"Injecting post-tool context for {tool_name}", "info")
                except Exception as e:
                    debug_log(f"Error getting post-tool context: {e}", "error")
                    post_tool_context = ""
                
                # Summarize result for efficient context
                result_summary = summarize_result(mcp_result, tool_name)
                result_analysis_brief = format_result_summary_for_llm(result_summary)
                action = f"📊 Analyzing {result_summary.get('row_count', 0)} results"
                elapsed = time_module.time() - start_time
                status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                if status_callback:
                    await status_callback(action, iteration, elapsed)
                
                # Track this tool call with summary
                spl_query = None
                if tool_name in {'run_splunk_query', 'splunk_run_query'} and 'query' in tool_args:
                    spl_query = tool_args['query']
                
                all_tool_calls.append({
                    "iteration": iteration,
                    "tool": tool_name,
                    "args": tool_args,
                    "spl_query": spl_query,
                    "result": mcp_result,
                    "summary": result_summary
                })
                
                # Extract insights for context building
                for finding in result_summary.get('findings', []):
                    accumulated_insights.append(f"[Iter {iteration}] {finding}")
                
                # Determine result status
                has_error = result_summary.get('type') == 'error'
                # Check for data in findings (works for both queries and metadata tools)
                findings = result_summary.get('findings', [])
                has_data = any(
                    ('results returned' in f and '0 results' not in f) or 
                    ('Found' in f and 'items' in f and '0 items' not in f)
                    for f in findings
                ) or (result_summary.get('row_count', 0) > 0)
                
                # Add assistant's reasoning to conversation
                conversation_history.append({"role": "assistant", "content": clean_response})
                
                # Build intelligent feedback with accumulated context
                insights_summary = "\n".join([f"  • {ins}" for ins in accumulated_insights[-5:]])  # Last 5 insights
                analysis_section = f"\nRESULT ANALYSIS:\n{result_analysis_brief}" if result_analysis_brief else ""
                
                # Add post-tool context if available
                context_section = f"\n\nRELEVANT CONTEXT:\n{post_tool_context}" if post_tool_context else ""
                
                if has_error:
                    error_msg = result_summary.get('message', 'Unknown error')
                    system_feedback = f"""🔴 ITERATION {iteration} RESULT: ERROR

Error: {error_msg}

ACCUMULATED INSIGHTS SO FAR:
{insights_summary}{analysis_section}{context_section}{spl_explanation_requirement}

REFINED USER INTENT: "{user_intent}"

STRATEGIC OPTIONS:
1. 🔧 Fix the query syntax and retry
2. 🔄 Try a different approach (different index, time range, or tool)
3. 🎯 Refine understanding of what the user actually wants
4. ✅ Accept this error as meaningful (e.g., "no such index exists")

If you can solve this, use <TOOL_CALL>...</TOOL_CALL> with your improved approach.
If this error IS the answer (e.g., "that index doesn't exist"), provide final response WITHOUT tool calls.
If you need to clarify the user's intent, ask a clarifying question WITHOUT tool calls."""
                
                elif has_data:
                    # Build compact result context using properly parsed results from summary
                    actual_results = result_summary.get('actual_results', [])
                    
                    # For metadata queries (indexes, sourcetypes), send full data
                    # For large query results, send sample only
                    if tool_name in {'get_indexes', 'splunk_get_indexes', 'get_metadata', 'splunk_get_metadata'}:
                        sample_data = actual_results  # Send all metadata
                        data_label = "Complete Data"
                    else:
                        sample_data = actual_results[:sample_size]  # Use session setting
                        data_label = f"Sample Data (first {sample_size} results)"
                    
                    result_snippet = {
                        "summary": result_summary,
                        "data": sample_data
                    }
                    
                    system_feedback = f"""✅ ITERATION {iteration} RESULT: SUCCESS - DATA FOUND

{result_analysis_brief or result_summary.get('findings', [])}

ACCUMULATED INSIGHTS:
{insights_summary}{context_section}{spl_explanation_requirement}

{data_label}:
{json.dumps(result_snippet.get('data'), indent=2)[:2000]}

QUALITY CHECK:
- Does this fully answer "{user_intent}"?
- Should you cross-reference with other data sources?
- Is there a deeper insight you can provide?

OPTIONS:
1. ✅ Provide final answer if user's question is fully addressed
2. 🔍 Execute additional query to enrich the answer
3. 📊 Aggregate/analyze these results with another query

⚠️ CRITICAL: If you want to investigate further, you MUST include a <TOOL_CALL> tag in your response.
Do NOT say "I will execute" or "Let me try" without actually providing the <TOOL_CALL>.
Either provide the final answer OR provide <TOOL_CALL>...</TOOL_CALL> - no in-between statements."""
                
                else:  # Success but no data
                    system_feedback = f"""⚠️ ITERATION {iteration} RESULT: NO DATA

The query executed successfully but returned no results.

ACCUMULATED INSIGHTS:
{insights_summary}{analysis_section}{context_section}{spl_explanation_requirement}

STRATEGIC OPTIONS:
1. 🔍 Try different index from discovery context
2. ⏰ Broaden time range (e.g., -7d instead of -24h)
3. 🎯 Simplify search criteria
4. ✅ Accept "no data" as the legitimate answer

Current user intent understanding: "{user_intent}"

⚠️ CRITICAL: If you want to investigate further, you MUST include a <TOOL_CALL> tag in your response.
Do NOT say "I will execute" or "Let me try" without actually providing the <TOOL_CALL>.
Either provide the final answer OR provide <TOOL_CALL>...</TOOL_CALL> - no in-between statements."""
                
                conversation_history.append({"role": "system", "content": system_feedback})
                
                # Get LLM's next decision
                print(f"🤔 [Iteration {iteration}] Asking LLM for quality assessment...")
                action = "🧠 AI reasoning & quality assessment"
                elapsed = time_module.time() - start_time
                status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                if status_callback:
                    await status_callback(action, iteration, elapsed)
                
                followup_max_tokens = chat_runtime_profile["followup_max_tokens"]
                next_response = await llm_client.generate_response(
                    messages=conversation_history,
                    max_tokens=followup_max_tokens,
                    temperature=max(0.0, runtime_temperature * 0.9)  # Slightly lower temp for more focused decisions
                )
                
                next_tool_call = extract_recoverable_tool_call(
                    next_response,
                    query_tool_name,
                    default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                    default_latest=str(tool_args.get('latest_time', '') or 'now'),
                )
                next_tool_match = bool(next_tool_call)
                missing_spl_explanation = (
                    requires_spl_explanation
                    and not next_tool_match
                    and not response_addresses_spl_explanation(next_response)
                )
                
                # Assess answer quality (independent of whether LLM wants to continue)
                has_actionable_data = result_summary.get('row_count', 0) > 0 and 'No data' not in str(result_summary.get('findings', []))
                quality_score, quality_reasons = assess_answer_quality(
                    next_response,
                    result_summary,
                    has_actionable_data
                )
                
                # Check if LLM is doing post-processing (formatting, conversion)
                formatting_keywords = ['convert', 'format', 'human-readable', 'readable format', 
                                      'timestamp', 'epoch', 'parse', 'translate', 'decode']
                is_formatting = any(kw in next_response.lower() for kw in formatting_keywords)
                
                # Check for convergence (stuck in loop)
                is_converged = detect_convergence(accumulated_insights, all_tool_calls)
                
                # Override convergence if we have data and LLM is formatting it
                if is_converged and has_actionable_data and is_formatting and not next_tool_match:
                    print(f"📝 Post-processing detected - allowing final formatting despite convergence")
                    is_converged = False  # Let it complete the formatting
                
                print(f"📊 Answer Quality: {quality_score}/100 - {', '.join(quality_reasons)}")
                if is_converged:
                    print(f"🔄 Convergence detected - investigation patterns repeating")
                
                # SMART DECISION LOGIC (using session quality_threshold):
                # 1. If high quality answer (>= threshold) - we're done regardless
                # 2. If converged (stuck) BUT doing post-processing - allow one more response
                # 3. If converged (stuck) - stop to avoid infinite loops  
                # 4. If low quality (< threshold/2) AND LLM wants to continue - proceed
                # 5. If low quality but LLM says done - try to force one more attempt
                
                if quality_score >= quality_threshold:
                    # HIGH QUALITY - But check if it's a user-facing answer or just reasoning
                    if has_actionable_data and not next_tool_match:
                        # We have data and LLM stopped - but is the response user-facing?
                        # Check if it's too short or contains internal reasoning keywords
                        is_internal = (len(next_response.strip()) < 100 or 
                                      any(kw in next_response.lower() for kw in 
                                          ['iteration', 'i will', "i'll try", 'let me check', 'next step', 
                                           'investigation', 'i should', 'perhaps i']))
                        
                        if is_internal or missing_spl_explanation:
                            if missing_spl_explanation:
                                print(f"📝 [Iteration {iteration}] High quality but missing required SPL explanation - requesting final user answer")
                            else:
                                print(f"📝 [Iteration {iteration}] High quality but internal reasoning - requesting final user answer")
                            
                            final_prompt = build_final_user_answer_prompt(
                                user_message,
                                insights_summary,
                                require_spl_explanation=requires_spl_explanation,
                            )
                            
                            conversation_history.append({"role": "system", "content": final_prompt})
                            
                            final_max_tokens = chat_runtime_profile["final_max_tokens"]
                            final_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=final_max_tokens,
                                temperature=runtime_temperature
                            )
                            final_answer = final_response
                            print(f"✅ [Iteration {iteration}] Final user answer generated ({len(final_response)} chars)")
                        else:
                            # Response is already user-facing - but double-check for tool calls
                            if '<TOOL_CALL>' in next_response:
                                print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> but primary parse missed it - retrying with recovery parser")
                                try:
                                    extracted_tool_call = extract_recoverable_tool_call(
                                        next_response,
                                        query_tool_name,
                                        default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                        default_latest=str(tool_args.get('latest_time', '') or 'now'),
                                    )
                                    if not extracted_tool_call:
                                        raise ValueError("Malformed tool call payload")
                                    tool_call = extracted_tool_call
                                    clean_response = sanitize_llm_response_text(next_response)
                                    continue  # Execute this tool call in next iteration
                                except Exception as e:
                                    print(f"❌ Failed to recover tool call (HIGH quality, first check): {e}")
                                    # Strip the malformed tool call and use the text explanation
                                    final_answer = sanitize_llm_response_text(next_response)
                                    if not final_answer:
                                        final_answer = "Investigation incomplete due to malformed query format."
                                    break
                            else:
                                print(f"✅ [Iteration {iteration}] High quality answer ({quality_score}/100) - investigation complete")
                                final_answer = next_response
                    else:
                        # Either no data or LLM wants to continue
                        if next_tool_match:
                            print(f"▶️  [Iteration {iteration}] High quality but continuing investigation")
                            tool_call = next_tool_call
                            clean_response = sanitize_llm_response_text(next_response)
                            continue
                        else:
                            # Double-check for tool calls that regex might have missed
                            if '<TOOL_CALL>' in next_response:
                                print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> but primary parse missed it - retrying with recovery parser")
                                try:
                                    extracted_tool_call = extract_recoverable_tool_call(
                                        next_response,
                                        query_tool_name,
                                        default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                        default_latest=str(tool_args.get('latest_time', '') or 'now'),
                                    )
                                    if extracted_tool_call:
                                        tool_call = extracted_tool_call
                                        clean_response = sanitize_llm_response_text(next_response)
                                        continue  # Execute this tool call in next iteration
                                    raise ValueError("Malformed tool call payload")
                                except Exception as e:
                                    print(f"❌ Failed to recover tool call (HIGH quality, second check): {e}")
                                    # Strip the malformed tool call and use the text explanation
                                    final_answer = sanitize_llm_response_text(next_response)
                                    if not final_answer:
                                        final_answer = "Investigation incomplete due to malformed query format."
                                    break
                            else:
                                if missing_spl_explanation:
                                    print(f"📝 [Iteration {iteration}] High quality answer still missing SPL explanation - requesting final user answer")
                                    final_prompt = build_final_user_answer_prompt(
                                        user_message,
                                        insights_summary,
                                        require_spl_explanation=requires_spl_explanation,
                                    )

                                    conversation_history.append({"role": "system", "content": final_prompt})

                                    final_max_tokens = chat_runtime_profile["final_max_tokens"]
                                    final_response = await llm_client.generate_response(
                                        messages=conversation_history,
                                        max_tokens=final_max_tokens,
                                        temperature=runtime_temperature
                                    )
                                    final_answer = final_response
                                    print(f"✅ [Iteration {iteration}] Final user answer with SPL explanation generated ({len(final_response)} chars)")
                                else:
                                    print(f"✅ [Iteration {iteration}] High quality answer ({quality_score}/100) - investigation complete")
                                    final_answer = sanitize_llm_response_text(next_response)
                    
                    if final_answer:
                        break
                
                elif is_converged:
                    # STUCK IN LOOP - Stop to avoid wasting resources
                    print(f"🛑 [Iteration {iteration}] Convergence detected - stopping to avoid loops")
                    final_answer = next_response + f"\n\n_Note: Investigation stopped after {iteration} iterations due to pattern convergence._"
                    break
                
                elif quality_score < (quality_threshold / 2):  # Use half of threshold as "low quality"
                    # LOW QUALITY - Need to continue
                    if next_tool_match:
                        # LLM wants to continue - excellent, let it
                        print(f"▶️  [Iteration {iteration}] Low quality ({quality_score}/100), continuing as requested")
                        # Fall through to tool execution
                    else:
                        # Low quality but LLM thinks it's done - force continuation
                        print(f"⚠️  [Iteration {iteration}] Low quality ({quality_score}/100) but LLM stopped")
                        print(f"    🔄 Forcing continuation...")
                        
                        # Check for continuation intent in natural language
                        continuation_intent = has_continuation_intent(next_response)
                        
                        if continuation_intent or quality_score < (quality_threshold / 3):
                            # Add strict format enforcement message
                            format_enforcement = f"""❗ FORMAT ERROR: Your quality score is {quality_score}/100 (below threshold of {quality_threshold}).

You MUST continue investigating using the exact <TOOL_CALL> format:

<TOOL_CALL>
{{"tool": "{query_tool_name}", "args": {{"query": "your SPL query here"}}}}
</TOOL_CALL>

Based on your previous response, provide your next investigation step NOW using the proper format above.
Do not explain what you will do - DO IT with a tool call."""
                            
                            conversation_history.append({"role": "system", "content": format_enforcement})
                            
                            # Retry with format enforcement
                            action = "🔄 Retrying with stricter format"
                            elapsed = time_module.time() - start_time
                            status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                            if status_callback:
                                await status_callback(action, iteration, elapsed)
                            
                            retry_max_tokens = chat_runtime_profile["retry_max_tokens"]
                            retry_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=retry_max_tokens,
                                temperature=max(0.0, runtime_temperature * 0.7)  # Lower temp for stricter format
                            )
                            
                            retry_tool_call = extract_recoverable_tool_call(
                                retry_response,
                                query_tool_name,
                                default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                default_latest=str(tool_args.get('latest_time', '') or 'now'),
                            )
                            if retry_tool_call:
                                print(f"✅ Retry successful - proper tool call format obtained")
                                next_response = retry_response
                                next_tool_call = retry_tool_call
                                next_tool_match = True
                                # Fall through to tool execution below
                            else:
                                print(f"⚠️  Retry failed - LLM still not providing tool call format")
                                print(f"    Response fragment: {retry_response[:200]}")
                                final_answer = f"Investigation incomplete. After {iteration} iterations, unable to determine next steps.\n\nLast findings:\n{insights_summary}\n\nSuggestion: Try a more specific query or different approach."
                                break
                        else:
                            # No clear continuation intent - accept as final
                            print(f"🏁 [Iteration {iteration}] No continuation intent detected despite low quality")
                            final_answer = sanitize_llm_response_text(next_response)
                            break
                    
                    # Has tool call (either original or from retry) - execute it
                    if next_tool_match:
                        try:
                            extracted_tool_call = next_tool_call or extract_recoverable_tool_call(
                                next_response,
                                query_tool_name,
                                default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                default_latest=str(tool_args.get('latest_time', '') or 'now'),
                            )
                            if not extracted_tool_call:
                                raise ValueError("Malformed tool call payload")
                            tool_call = extracted_tool_call
                            
                            clean_response = sanitize_llm_response_text(next_response)
                            continue  # Execute this tool call in next iteration
                        except Exception as e:
                            print(f"❌ Failed to parse tool call: {e}")
                            final_answer = sanitize_llm_response_text(next_response)
                            break
                
                else:
                    # MODERATE QUALITY (50-69) - Middle ground
                    if next_tool_match:
                        # Moderate quality but LLM wants to refine - allow it (up to 5 iterations)
                        if iteration < 5:
                            print(f"▶️  [Iteration {iteration}] Moderate quality ({quality_score}/100), allowing refinement")
                            try:
                                extracted_tool_call = next_tool_call or extract_recoverable_tool_call(
                                    next_response,
                                    query_tool_name,
                                    default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                    default_latest=str(tool_args.get('latest_time', '') or 'now'),
                                )
                                if not extracted_tool_call:
                                    raise ValueError("Malformed tool call payload")
                                tool_call = extracted_tool_call
                                clean_response = sanitize_llm_response_text(next_response)
                                continue  # Execute this tool call in next iteration
                            except Exception as e:
                                print(f"❌ Failed to parse tool call: {e}")
                                final_answer = sanitize_llm_response_text(next_response)
                                break
                        else:
                            # Too many iterations for moderate quality - accept current
                            print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) after {iteration} iterations - accepting")
                            final_answer = sanitize_llm_response_text(next_response)
                            break
                    else:
                        # Moderate quality, no tool call - check for continuation intent
                        continuation_intent = has_continuation_intent(next_response)
                        
                        if continuation_intent and iteration < 5:
                            # LLM wants to continue but didn't provide tool call - force retry
                            print(f"⚠️  [Iteration {iteration}] Moderate quality ({quality_score}/100) but continuation intent detected")
                            print(f"    🔄 Forcing format retry...")
                            
                            format_enforcement = f"""❗ FORMAT ERROR: You indicated you will continue investigating, but did not provide a <TOOL_CALL>.

Your quality score is {quality_score}/100 (moderate). To proceed, you MUST use the exact format:

<TOOL_CALL>
{{"tool": "{query_tool_name}", "args": {{"query": "your SPL query here"}}}}
</TOOL_CALL>

Based on your previous response, provide your next query NOW using the proper format above."""
                            
                            conversation_history.append({"role": "system", "content": format_enforcement})
                            
                            retry_max_tokens = chat_runtime_profile["retry_max_tokens"]
                            retry_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=retry_max_tokens,
                                temperature=max(0.0, runtime_temperature * 0.7)
                            )
                            
                            retry_tool_call = extract_recoverable_tool_call(
                                retry_response,
                                query_tool_name,
                                default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                default_latest=str(tool_args.get('latest_time', '') or 'now'),
                            )
                            if retry_tool_call:
                                print(f"✅ Retry successful - proper tool call format obtained")
                                next_response = retry_response
                                next_tool_call = retry_tool_call
                                next_tool_match = True
                                # Fall through to tool execution
                                try:
                                    extracted_tool_call = next_tool_call or extract_recoverable_tool_call(
                                        retry_response,
                                        query_tool_name,
                                        default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                        default_latest=str(tool_args.get('latest_time', '') or 'now'),
                                    )
                                    if not extracted_tool_call:
                                        raise ValueError("Malformed tool call payload")
                                    tool_call = extracted_tool_call
                                    clean_response = sanitize_llm_response_text(retry_response)
                                    continue  # Execute this tool call in next iteration
                                except Exception as e:
                                    print(f"❌ Failed to parse tool call: {e}")
                                    final_answer = sanitize_llm_response_text(next_response)
                                    break
                            else:
                                print(f"⚠️  Retry failed - accepting current answer")
                                final_answer = sanitize_llm_response_text(next_response)
                                break
                        else:
                            # Moderate quality, no tool call, no continuation intent
                            # Check if we have data and if response is user-facing
                            if has_actionable_data:
                                # We have data - check if response is internal reasoning
                                is_internal = (len(next_response.strip()) < 100 or 
                                              any(kw in next_response.lower() for kw in 
                                                  ['iteration', 'i will', "i'll try", 'let me check', 'next step', 
                                                   'i will adjust', 'i will refine', "i'll refine", 'i should']))
                                
                                if is_internal or missing_spl_explanation:
                                    if missing_spl_explanation:
                                        print(f"📝 [Iteration {iteration}] Moderate quality with data but missing SPL explanation - requesting final answer")
                                    else:
                                        print(f"📝 [Iteration {iteration}] Moderate quality with data but internal reasoning - requesting final answer")
                                    
                                    final_prompt = build_final_user_answer_prompt(
                                        user_message,
                                        insights_summary,
                                        require_spl_explanation=requires_spl_explanation,
                                    )
                                    
                                    conversation_history.append({"role": "system", "content": final_prompt})
                                    
                                    final_max_tokens = chat_runtime_profile["final_max_tokens"]
                                    final_response = await llm_client.generate_response(
                                        messages=conversation_history,
                                        max_tokens=final_max_tokens,
                                        temperature=runtime_temperature
                                    )
                                    final_answer = final_response
                                    print(f"✅ [Iteration {iteration}] Final user answer generated ({len(final_response)} chars)")
                                else:
                                    # Response is already user-facing - but check for tool calls
                                    if '<TOOL_CALL>' in next_response:
                                        print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> - retrying with recovery parser")
                                        try:
                                            extracted_tool_call = extract_recoverable_tool_call(
                                                next_response,
                                                query_tool_name,
                                                default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                                default_latest=str(tool_args.get('latest_time', '') or 'now'),
                                            )
                                            if not extracted_tool_call:
                                                raise ValueError("Malformed tool call payload")
                                            tool_call = extracted_tool_call
                                            clean_response = sanitize_llm_response_text(next_response)
                                            continue  # Execute this tool call in next iteration
                                        except Exception as e:
                                            print(f"❌ Failed to recover tool call: {e}")
                                            # Strip the malformed tool call and use the text explanation
                                            final_answer = sanitize_llm_response_text(next_response)
                                            if not final_answer:
                                                final_answer = "Investigation incomplete due to malformed query format."
                                            break
                                    else:
                                        if missing_spl_explanation:
                                            print(f"📝 [Iteration {iteration}] Moderate quality answer still missing SPL explanation - requesting final answer")
                                            final_prompt = build_final_user_answer_prompt(
                                                user_message,
                                                insights_summary,
                                                require_spl_explanation=requires_spl_explanation,
                                            )

                                            conversation_history.append({"role": "system", "content": final_prompt})

                                            final_max_tokens = chat_runtime_profile["final_max_tokens"]
                                            final_response = await llm_client.generate_response(
                                                messages=conversation_history,
                                                max_tokens=final_max_tokens,
                                                temperature=runtime_temperature
                                            )
                                            final_answer = final_response
                                            print(f"✅ [Iteration {iteration}] Final user answer with SPL explanation generated ({len(final_response)} chars)")
                                        else:
                                            print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) - accepting answer")
                                            final_answer = sanitize_llm_response_text(next_response)
                            else:
                                # No data - accept response as-is, but check for tool calls
                                if '<TOOL_CALL>' in next_response:
                                    print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> - retrying with recovery parser")
                                    try:
                                        extracted_tool_call = extract_recoverable_tool_call(
                                            next_response,
                                            query_tool_name,
                                            default_earliest=str(tool_args.get('earliest_time', '') or '-24h'),
                                            default_latest=str(tool_args.get('latest_time', '') or 'now'),
                                        )
                                        if not extracted_tool_call:
                                            raise ValueError("Malformed tool call payload")
                                        tool_call = extracted_tool_call
                                        clean_response = sanitize_llm_response_text(next_response)
                                        continue  # Execute this tool call in next iteration
                                    except Exception as e:
                                        print(f"❌ Failed to recover tool call: {e}")
                                        # Strip the malformed tool call and use the text explanation
                                        final_answer = sanitize_llm_response_text(next_response)
                                        if not final_answer:
                                            final_answer = "Investigation incomplete due to malformed query format."
                                        break
                                else:
                                    if missing_spl_explanation:
                                        print(f"📝 [Iteration {iteration}] Moderate quality no-data answer missing SPL explanation - requesting final answer")
                                        final_prompt = build_final_user_answer_prompt(
                                            user_message,
                                            insights_summary,
                                            require_spl_explanation=requires_spl_explanation,
                                        )

                                        conversation_history.append({"role": "system", "content": final_prompt})

                                        final_max_tokens = chat_runtime_profile["final_max_tokens"]
                                        final_response = await llm_client.generate_response(
                                            messages=conversation_history,
                                            max_tokens=final_max_tokens,
                                            temperature=runtime_temperature
                                        )
                                        final_answer = final_response
                                        print(f"✅ [Iteration {iteration}] Final no-data answer with SPL explanation generated ({len(final_response)} chars)")
                                    else:
                                        print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) - accepting answer")
                                        final_answer = sanitize_llm_response_text(next_response)
                            break
            
            # CRITICAL SAFETY CHECK: If final_answer contains <TOOL_CALL>, the LLM isn't done
            # This should never happen, but if it does, strip the tool call and force continuation
            if final_answer and '<TOOL_CALL>' in final_answer:
                print(f"⚠️ WARNING: final_answer contains <TOOL_CALL> tags - LLM finished prematurely!")
                print(f"Response: {final_answer[:200]}...")
                # Strip tool calls from response and return with warning
                final_answer = sanitize_llm_response_text(final_answer)
                if not final_answer:
                    final_answer = "Investigation incomplete. The agent attempted to continue but reached response limits."
            
            # Return comprehensive response with status timeline
            # Include conversation_history so follow-up queries maintain context
            user_facing_final_answer = finalize_user_facing_response_text(
                final_answer,
                DEFAULT_TOOL_INVESTIGATION_RESPONSE,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                all_tool_calls,
                assistant_response=user_facing_final_answer,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                all_tool_calls,
                assistant_response=user_facing_final_answer,
            )
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(all_tool_calls, capability_usage)
            return {
                "response": user_facing_final_answer,
                "initial_response": user_message,
                "tool_calls": all_tool_calls,
                "spl_query": extract_primary_spl_query(all_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": iteration,
                "execution_time": f"{time_module.time() - start_time:.2f}s",
                "insights": accumulated_insights,
                "status_timeline": status_timeline,  # NEW: Real-time action log
                "reasoning_chain": [
                    {
                        "iteration": i, 
                        "tool": tc["tool"], 
                        "status": "error" if tc["summary"].get('type') == 'error' else ("success" if any('results returned' in f for f in tc["summary"].get('findings', [])) else "no_data"),
                        "key_finding": tc["summary"].get('findings', [''])[0] if tc["summary"].get('findings') else ""
                    } 
                    for i, tc in enumerate(all_tool_calls, 1)
                ],
                "conversation_history": conversation_history,  # FIX: Return full conversation for follow-up context
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }
        
        # No tool call, return clean response with any SPL found
        await push_status(status_timeline, "✅ Returning direct answer", 0)
        direct_response = finalize_user_facing_response_text(
            clean_response,
            DEFAULT_DIRECT_CHAT_RESPONSE,
        )
        updated_memory = update_chat_memory(
            chat_session_id,
            user_message,
            assistant_response=direct_response,
            record_user_turn=False,
        )
        follow_on_actions = build_follow_on_actions(
            user_message,
            updated_memory,
            assistant_response=direct_response,
        )
        return {
            "response": direct_response,
            "spl_in_text": spl_in_text,
            "status_timeline": status_timeline,
            "iterations": 0,
            "execution_time": f"{time.time() - request_started_at:.2f}s",
            "discovery_age_warning": discovery_age_warning,
            "chat_session_id": chat_session_id,
            "chat_memory": updated_memory,
            "conversation_history": _build_follow_up_conversation_history(history, user_message, direct_response),
            "capability_usage": capability_usage,
            "has_follow_on": len(follow_on_actions) > 0,
            "follow_on_actions": follow_on_actions
        }
        
    except Exception as e:
        # Log the full error to terminal for debugging
        print(f"ERROR in chat_with_splunk_logic: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": f"Chat failed: {str(e)}"}


@app.post("/chat")
async def chat_with_splunk(request: dict):
    """Handle chat requests (non-streaming version for backward compatibility)."""
    return await chat_with_splunk_logic(request, status_callback=None)


async def execute_mcp_tool_call(tool_call, config):
    """Execute a tool call against the MCP server."""
    try:
        import httpx
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if config.mcp.token:
            headers["Authorization"] = f"Bearer {config.mcp.token}"
            print(f"🔑 MCP Token present: {config.mcp.token[:20]}..." if len(config.mcp.token) > 20 else f"🔑 MCP Token: {config.mcp.token}")
        else:
            print("⚠️ WARNING: No MCP token found in config!")
        
        print(f"🌐 MCP URL: {config.mcp.url}")
        print(f"🔒 SSL Verify: {config.mcp.verify_ssl}")
        
        # Use MCP-specific SSL verification setting from config
        verify_ssl = config.mcp.verify_ssl
        ca_bundle = getattr(config.security, 'ca_bundle_path', None) if hasattr(config, 'security') else None
        
        # Determine SSL verification setting (match discovery engine behavior)
        if ca_bundle and verify_ssl:
            # Use custom CA bundle
            ssl_verify = ca_bundle
            print(f"INFO: SSL verification enabled with custom CA bundle: {ca_bundle}")
        elif verify_ssl:
            # Use system CA bundle (may fail with self-signed certs)
            print("INFO: SSL verification enabled with system CA bundle")
            ssl_verify = True
        else:
            # Disable SSL verification (for self-signed certs)
            ssl_verify = False
            print("INFO: SSL verification disabled for MCP calls (self-signed certificates)")
        
        requested_tool_name = tool_call.get('params', {}).get('name', 'unknown')
        requested_args = tool_call.get('params', {}).get('arguments', {})
        available_tools = await discover_mcp_tools(config)
        resolved_tool_name = resolve_tool_name(requested_tool_name, available_tools)
        default_query_tool_name = resolve_tool_name("splunk_run_query", available_tools)

        if resolved_tool_name not in available_tools:
            if (
                isinstance(requested_args, dict)
                and isinstance(requested_args.get("query"), str)
                and requested_args.get("query", "").strip()
                and default_query_tool_name in available_tools
            ):
                debug_log(
                    f"Remapping unavailable tool '{requested_tool_name}' to '{default_query_tool_name}' because it carries a Splunk query",
                    "warning",
                )
                resolved_tool_name = default_query_tool_name
            else:
                available_preview = ", ".join(sorted(available_tools)) if available_tools else "none"
                debug_log(
                    f"Rejected unavailable MCP tool '{requested_tool_name}'. Available tools: {available_preview}",
                    "warning",
                )
                return {
                    "error": f"Requested tool '{requested_tool_name}' is not available",
                    "detail": f"Available tools: {available_preview}",
                    "status_code": 400,
                    "fatal": False,
                }

        resolved_args = normalize_tool_arguments(resolved_tool_name, requested_args)

        resolved_tool_call = {
            "method": "tools/call",
            "params": {
                "name": resolved_tool_name,
                "arguments": resolved_args
            }
        }

        # Debug: Log the tool call being sent
        tool_name = resolved_tool_name
        print(f"📤 Sending MCP tool call: {tool_name}")
        print(f"   Requested tool: {requested_tool_name}")
        print(f"   Method: {resolved_tool_call.get('method')}")
        print(f"   Params: {resolved_tool_call.get('params', {}).keys()}")
        print(f"   Arguments: {resolved_tool_call.get('params', {}).get('arguments', {})}")
        print(f"   Headers: {list(headers.keys())}")
        print(f"   Has Authorization: {'Authorization' in headers}")
        print(f"   Full URL: {config.mcp.url}")

        async def _post_tool_call(payload):
            async with httpx.AsyncClient(verify=ssl_verify, timeout=30.0) as client:
                print(f"📡 Posting to: {config.mcp.url}")
                return await client.post(
                    config.mcp.url,
                    json=payload,
                    headers=headers
                )

        unknown_tool_signals = ["tool not found", "unknown tool", "invalid tool", "no such tool", "method not found"]
        should_retry_with_refresh = False
        retry_reason = ""

        response = await _post_tool_call(resolved_tool_call)
        print(f"📨 Response Status: {response.status_code}")
        print(f"📨 Response Content-Type: {response.headers.get('content-type', 'unknown')}")

        if response.status_code == 200:
            mcp_response = response.json()

            if isinstance(mcp_response, dict) and mcp_response.get('error'):
                error_text = str(mcp_response.get('error', '')).lower()
                if any(signal in error_text for signal in unknown_tool_signals):
                    should_retry_with_refresh = True
                    retry_reason = str(mcp_response.get('error'))
            elif isinstance(mcp_response, dict) and mcp_response.get('result'):
                result_obj = mcp_response.get('result', {})
                content = result_obj.get('content', []) if isinstance(result_obj, dict) else []
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and isinstance(item.get('text'), str):
                            text = item.get('text', '').lower()
                            if any(signal in text for signal in unknown_tool_signals):
                                should_retry_with_refresh = True
                                retry_reason = item.get('text', '')
                                break
        else:
            error_detail = response.text[:500] if response.text else "No error details"
            error_text = error_detail.lower()
            if any(signal in error_text for signal in unknown_tool_signals):
                should_retry_with_refresh = True
                retry_reason = error_detail

        if should_retry_with_refresh:
            debug_log(f"Refreshing MCP tools after unknown-tool signal: {retry_reason}", "warning")
            refreshed_tools = await discover_mcp_tools(config, force_refresh=True)
            retried_tool_name = resolve_tool_name(requested_tool_name, refreshed_tools)
            retried_args = normalize_tool_arguments(retried_tool_name, requested_args)
            retried_payload = {
                "method": "tools/call",
                "params": {
                    "name": retried_tool_name,
                    "arguments": retried_args
                }
            }
            response = await _post_tool_call(retried_payload)
            print(f"🔁 Retry response status: {response.status_code}")
        
        if response.status_code == 200:
            mcp_response = response.json()

            # Debug: Log the MCP response structure
            debug_log(f"🔍 MCP Response from {tool_name}", "response", {
                "tool": tool_name,
                "status": response.status_code,
                "response_type": str(type(mcp_response)),
                "response_keys": list(mcp_response.keys()) if isinstance(mcp_response, dict) else None
            })

            # Check for 'result' field
            if isinstance(mcp_response, dict) and 'result' in mcp_response:
                result = mcp_response['result']

                structured_content = result.get('structuredContent', {}) if isinstance(result, dict) else {}
                structured_results = structured_content.get('results', []) if isinstance(structured_content, dict) else []
                direct_results = result.get('results', []) if isinstance(result, dict) else []

                # Check for results array (GA structuredContent first)
                if isinstance(structured_results, list):
                    results_count = len(structured_results)
                    debug_log(f"📦 MCP returned {results_count} results (structuredContent)", "response", {
                        "count": results_count,
                        "first_result_sample": structured_results[0] if results_count > 0 else None
                    })
                elif isinstance(direct_results, list):
                    results_count = len(direct_results)
                    debug_log(f"📦 MCP returned {results_count} results", "response", {
                        "count": results_count,
                        "first_result_sample": direct_results[0] if results_count > 0 else None
                    })
                elif isinstance(result, dict):
                    debug_log(f"📄 MCP result content (no results array)", "response", {
                        "content_preview": str(result)[:200]
                    })
                else:
                    debug_log(f"📄 MCP result value: {result}", "response")
            else:
                debug_log(f"⚠️ MCP response missing 'result' field", "warning", {
                    "response_preview": str(mcp_response)[:200]
                })

            return mcp_response

        error_detail = response.text[:200] if response.text else "No error details"
        print(f"❌ MCP ERROR: Status {response.status_code} - {error_detail}")

        # Mark fatal errors that won't be fixed by retrying
        fatal_statuses = {401, 403, 404}  # Auth, forbidden, not found
        is_fatal = response.status_code in fatal_statuses

        return {
            "error": f"MCP call failed: {response.status_code}",
            "detail": error_detail,
            "status_code": response.status_code,
            "fatal": is_fatal  # Signal that retrying won't help
        }
                
    except httpx.HTTPError as e:
        print(f"❌ HTTP ERROR: {type(e).__name__} - {str(e)}")
        return {"error": f"HTTP error: {type(e).__name__}", "detail": str(e)}
    except Exception as e:
        print(f"❌ EXCEPTION: {type(e).__name__} - {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": f"Failed to execute tool call: {type(e).__name__}", "detail": str(e)}


@app.get("/status")
async def get_status():
    """Get current discovery status."""
    global current_discovery_session
    
    if current_discovery_session is None:
        return {"status": "idle"}
    elif current_discovery_session.done():
        if current_discovery_session.exception():
            return {"status": "error", "error": str(current_discovery_session.exception())}
        else:
            return {"status": "completed", "result": current_discovery_session.result()}
    else:
        return {"status": "running"}


@app.get("/api/llm/health")
async def get_llm_health():
    """Get LLM endpoint health metrics (v1.1.0)"""
    try:
        from llm.health_monitor import get_all_health_metrics
        
        metrics = get_all_health_metrics()
        
        if not metrics:
            return {
                "status": "no_data",
                "message": "No LLM requests made yet",
                "endpoints": {}
            }
        
        return {
            "status": "success",
            "endpoints": metrics,
            "summary": {
                "total_endpoints": len(metrics),
                "healthy_count": sum(1 for m in metrics.values() if m["status"] == "healthy"),
                "degraded_count": sum(1 for m in metrics.values() if m["status"] == "degraded"),
                "unhealthy_count": sum(1 for m in metrics.values() if m["status"] == "unhealthy")
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@app.get("/")
async def serve_frontend():
    """Serve the frontend HTML."""
    if FRONTEND_INDEX_PATH.exists():
        return FileResponse(FRONTEND_INDEX_PATH)
    return HTMLResponse(content=get_frontend_html())


if __name__ == "__main__":
    import sys
    import io

    def _is_port_available(port: int, host: str = "0.0.0.0") -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return True
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _find_listener_pid_windows(port: int) -> Optional[int]:
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                return None

            for line in result.stdout.splitlines():
                normalized = " ".join(line.split())
                if not normalized:
                    continue
                if f":{port}" not in normalized:
                    continue
                if "LISTENING" not in normalized.upper():
                    continue

                parts = normalized.split(" ")
                if len(parts) < 5:
                    continue

                try:
                    return int(parts[-1])
                except ValueError:
                    continue
        except Exception:
            return None
        return None

    def _get_process_commandline_windows(pid: int) -> str:
        try:
            ps_command = (
                f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\"; "
                f"if ($p) {{ $p.CommandLine }}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                return ""
            return (result.stdout or "").strip()
        except Exception:
            return ""

    def _is_safe_tool_owned_process(pid: int, workspace_root: str) -> bool:
        if pid <= 0:
            return False
        try:
            if pid == os.getpid():
                return False
        except Exception:
            pass

        cmdline = _get_process_commandline_windows(pid).lower().replace("\\", "/")
        if not cmdline:
            return False

        workspace_norm = workspace_root.lower().replace("\\", "/")
        return ("web_app.py" in cmdline) and (workspace_norm in cmdline)

    def _try_reclaim_preferred_port_windows(port: int, workspace_root: str) -> bool:
        listener_pid = _find_listener_pid_windows(port)
        if listener_pid is None:
            return False

        if not _is_safe_tool_owned_process(listener_pid, workspace_root):
            return False

        try:
            os.kill(listener_pid, 9)
            time.sleep(0.35)
            return _is_port_available(port)
        except Exception:
            return False

    def _resolve_startup_port(preferred_port: int = 8003, max_scan_ports: int = 20) -> int:
        workspace_root = str(Path(__file__).resolve().parent.parent)

        if _is_port_available(preferred_port):
            return preferred_port

        if sys.platform == "win32":
            reclaimed = _try_reclaim_preferred_port_windows(preferred_port, workspace_root)
            if reclaimed and _is_port_available(preferred_port):
                return preferred_port

        for candidate in range(preferred_port + 1, preferred_port + max_scan_ports + 1):
            if _is_port_available(candidate):
                return candidate

        raise RuntimeError(
            f"No open TCP port found in range {preferred_port}-{preferred_port + max_scan_ports}. "
            f"Please free a port and retry."
        )
    
    # Fix encoding issues on Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    startup_port = _resolve_startup_port(preferred_port=8003)
    if startup_port != 8003:
        print(f"Preferred port 8003 unavailable; using fallback port {startup_port}.")
    
    print("Starting Splunk MCP Discovery Tool Web Interface")
    print(f"Access the interface at: http://localhost:{startup_port}")
    print(f"WebSocket endpoint: ws://localhost:{startup_port}/ws")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=startup_port,
        log_level="info",
        reload=False  # Set to True for development
    )

