"""
FastAPI Web Application for Splunk MCP Use Case Discovery Tool

A modern web-based interface providing real-time progress tracking,
animated progress indicators, and comprehensive report management.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import asyncio
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
from discovery.engine import DiscoveryEngine
from discovery.v2_pipeline import DiscoveryV2Pipeline
from llm.factory import LLMClientFactory, normalize_provider_name
from discovery.context_manager import get_context_manager

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

# Module-level LLM client cache for performance
_cached_llm_client = None
_cached_config_hash = None

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
chat_session_settings = {
    # Discovery Settings
    "max_execution_time": 90,        # seconds
    "max_iterations": 5,             # count
    "discovery_freshness_days": 7,   # days
    
    # LLM Behavior
    "max_tokens": 16000,             # tokens per request
    "temperature": 0.7,              # 0.0-2.0
    "context_history": 6,            # messages
    
    # Performance Tuning
    "max_retry_delay": 300,          # seconds
    "max_retries": 5,                # count
    "query_sample_size": 2,          # rows
    
    # Quality Control
    "quality_threshold": 70,         # 0-100 score
    "convergence_detection": 5,      # iterations

    # Demo Augmentation
    "enable_splunk_augmentation": True,
    "enable_rag_context": False,
    "rag_max_chunks": 3,
}

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
        "tracked_terms": [],
        "locations": [],
        "entities": {
            "indexes": [],
            "sourcetypes": [],
            "hosts": [],
            "sources": []
        },
        "time_preferences": [],
        "last_tools_used": []
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

    time_preferences = []
    for token in ["-24h", "-7d", "-30d", "today", "yesterday", "last week", "last month", "now"]:
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


def update_chat_memory(chat_session_id: str, user_message: str, tool_calls: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Update chat memory with latest user message and optional tool activity."""
    memory = load_chat_memory(chat_session_id)
    signals = _extract_memory_signals(user_message)

    if signals.get("intent"):
        memory["primary_intent"] = signals["intent"]
        _append_unique(memory["recent_intents"], [signals["intent"]], limit=8)

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

    return "\n".join(lines)


def build_follow_on_actions(user_message: str, memory: Dict[str, Any], tool_calls: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    """Generate concise follow-on action suggestions for the next interaction step."""
    actions: List[str] = []
    entities = memory.get("entities", {}) if isinstance(memory, dict) else {}
    remembered_index = (entities.get("indexes") or [None])[-1]
    remembered_host = (entities.get("hosts") or [None])[-1]

    if tool_calls:
        last_call = tool_calls[-1] if tool_calls else {}
        summary = last_call.get("summary", {}) if isinstance(last_call, dict) else {}
        row_count = summary.get("row_count", 0)

        if row_count == 0:
            actions.append("Retry with a broader time range, such as earliest=-7d latest=now.")
            if remembered_index:
                actions.append(f"Run a baseline count check on index={remembered_index} to confirm data availability.")
        elif row_count > 0:
            actions.append("Add a timechart view to evaluate trend changes over time.")
            if remembered_index:
                actions.append(f"Drill into index={remembered_index} with top sourcetype and host breakdown.")
            if remembered_host:
                actions.append(f"Pivot on host={remembered_host} to identify related anomalies.")

    if not actions:
        actions.append("Ask a focused plain-language question about one index, host, or sourcetype for deeper analysis.")
        if remembered_index:
            actions.append(f"Try: 'Show me unusual events in index={remembered_index} over the last 24h'.")

    return actions[:3]


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
    """Return compact local retrieval snippets from recent output reports for demo-mode RAG."""
    output_dir = Path("output")
    if not output_dir.exists():
        return ""

    query_terms = _extract_query_terms_for_rag(user_message)
    if not query_terms:
        return ""

    candidate_files = sorted(
        [p for p in output_dir.glob("*") if p.is_file() and p.suffix.lower() in {".md", ".txt", ".json"}],
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )[:8]

    scored_chunks: List[Dict[str, Any]] = []
    for file_path in candidate_files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")[:12000]
        except Exception:
            continue

        blocks = [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]
        for block in blocks:
            lower_block = block.lower()
            hits = sum(1 for term in query_terms if term in lower_block)
            if hits <= 0:
                continue
            scored_chunks.append({
                "file": file_path.name,
                "score": hits,
                "snippet": block[:420]
            })

    if not scored_chunks:
        return ""

    top_chunks = sorted(scored_chunks, key=lambda item: item["score"], reverse=True)[:max(1, min(max_chunks, 6))]
    lines = ["📚 OPTIONAL LOCAL RAG CONTEXT:"]
    for idx, chunk in enumerate(top_chunks, 1):
        lines.append(f"{idx}. [{chunk['file']}] {chunk['snippet']}")
    return "\n".join(lines)


def detect_basic_inventory_intent(user_message: str) -> Optional[str]:
    """Detect common simple inventory intents that should not rely on LLM tool formatting."""
    if not isinstance(user_message, str):
        return None
    message = user_message.lower()

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


def extract_index_from_message(user_message: str) -> Optional[str]:
    """Extract index target from natural language."""
    if not isinstance(user_message, str):
        return None
    patterns = [
        r"index\s*[=:]?\s*([a-zA-Z0-9_\-.]+)",
        r"in\s+index\s+([a-zA-Z0-9_\-.]+)",
        r"for\s+index\s+([a-zA-Z0-9_\-.]+)",
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
1) For data requests, execute tools rather than guessing.
2) If one query returns no data, broaden time range once and try a nearby index.
3) If still no data, explicitly say no data found and show what was tried.
4) Keep answers concise and factual.

Tool call format (required when querying):
<TOOL_CALL>{{"tool": "{query_tool_name}", "args": {{"query": "search index=main | head 5", "earliest_time": "-24h", "latest_time": "now"}}}}</TOOL_CALL>
"""


def _discovery_session_manifest_path() -> Path:
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir / "discovery_sessions.json"


def load_discovery_sessions() -> List[Dict[str, Any]]:
    """Load persisted discovery session catalog."""
    manifest_path = _discovery_session_manifest_path()
    if not manifest_path.exists():
        # Backfill from existing report files for legacy runs
        output_dir = Path("output")
        if not output_dir.exists():
            return []

        sessions_by_timestamp: Dict[str, Dict[str, Any]] = {}
        for file_path in output_dir.glob("*"):
            if not file_path.is_file():
                continue
            match = re.search(r"_(\d{8}_\d{6})\.", file_path.name)
            if not match:
                continue
            timestamp = match.group(1)
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

        reconstructed = sorted(sessions_by_timestamp.values(), key=lambda x: x.get("timestamp", ""), reverse=True)
        if reconstructed:
            save_discovery_sessions(reconstructed)
        return reconstructed

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
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

    artifacts = []
    for file_path in sorted(output_dir.glob("v2_*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if not file_path.is_file():
            continue
        modified_iso = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
        size_bytes = file_path.stat().st_size
        artifacts.append({
            "name": file_path.name,
            "type": file_path.suffix[1:] if file_path.suffix else "unknown",
            "size": size_bytes,
            "size_bytes": size_bytes,
            "modified": modified_iso,
            "modified_at": modified_iso,
            "path": str(file_path)
        })

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
    allowed_extensions = ['.md', '.json', '.txt']
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
        from datetime import datetime
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
    
    reports = []
    for file_path in output_dir.glob("v2_*"):
        if file_path.is_file():
            reports.append({
                "name": file_path.name,
                "path": str(file_path),
                "size": file_path.stat().st_size,
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                "type": file_path.suffix[1:] if file_path.suffix else "unknown"
            })
    
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

    output_dir = Path("output")
    files = []
    for report_name in session.get("report_paths", []):
        report_path = output_dir / report_name
        files.append({
            "name": report_name,
            "exists": report_path.exists(),
            "size": report_path.stat().st_size if report_path.exists() else 0,
            "modified": datetime.fromtimestamp(report_path.stat().st_mtime).isoformat() if report_path.exists() else None
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
        # Security: Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(filename)
        file_path = Path("output") / safe_filename
        
        # Security: Ensure file is within output directory
        if not file_path.resolve().is_relative_to(Path("output").resolve()):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        if file_path.suffix.lower() == ".json":
            with open(file_path, 'r', encoding='utf-8') as f:
                content = json.load(f)
            return {"content": content, "type": "json"}
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
        
        return {"status": "success", "message": "Configuration updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")

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
    
    return {"status": "success", "settings": chat_session_settings.copy()}

@app.post("/api/chat/settings/reset")
async def reset_chat_settings():
    """Reset chat settings to defaults"""
    global chat_session_settings
    
    chat_session_settings = {
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
        "enable_rag_context": False,
        "rag_max_chunks": 3,
    }
    
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
                response = await client.get(
                    'https://api.openai.com/v1/models',
                    headers={'Authorization': f'Bearer {api_key}'},
                )
                response.raise_for_status()
                models_data = response.json()
                models = sorted({m.get('id') for m in models_data.get('data', []) if isinstance(m, dict) and m.get('id')})
                return {'models': [m for m in models if isinstance(m, str)]}

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
async def assess_max_tokens():
    """Assess the actual max_tokens limit by testing the LLM API"""
    try:
        config = config_manager.get()
        provider = normalize_provider_name(config.llm.provider)
        
        if provider in {"openai", "azure", "anthropic", "gemini"} and not config.llm.api_key:
            raise HTTPException(status_code=400, detail="LLM API key not configured")

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
        
        from openai import OpenAI
        client = OpenAI(
            api_key=config.llm.api_key,
            base_url=config.llm.endpoint_url if config.llm.endpoint_url else None
        )
        
        # Try progressively larger max_tokens until we hit the limit
        test_values = [128000, 64000, 32000, 16000, 8000, 4000, 2000, 1000]
        
        for test_max in test_values:
            try:
                response = client.chat.completions.create(
                    model=config.llm.model,
                    messages=[{"role": "user", "content": "Hi"}],
                    max_tokens=test_max,
                    temperature=0.7
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

        # Test 1: Connectivity probe
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                if provider == "openai":
                    probe = await client.get(
                        "https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {api_key}"}
                    )
                    probe.raise_for_status()
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
    
    # Check if summary already exists
    output_dir = Path("output")
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
                existing_summary['from_cache'] = True
                return existing_summary
            print(f"Cached summary {summary_file.name} missing V2 fields; regenerating...")
        except Exception as e:
            print(f"Error loading cached summary: {e}")
            # Continue to regenerate
    
    # Load V2 session artifacts only (legacy artifacts intentionally ignored)
    json_file = output_dir / f"v2_intelligence_blueprint_{timestamp}.json"
    detailed_file = output_dir / f"v2_operator_runbook_{timestamp}.md"
    classification_file = output_dir / f"v2_developer_handoff_{timestamp}.md"
    executive_file = output_dir / f"v2_insights_brief_{timestamp}.md"

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
    try:
        output_dir = Path("output")
        if not output_dir.exists():
            return None

        insights_files = sorted(output_dir.glob("v2_insights_brief_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not insights_files:
            return None

        latest_summary = insights_files[0]
        summary_text = latest_summary.read_text(encoding='utf-8')[:2000]

        timestamp = latest_summary.stem.replace('v2_insights_brief_', '')
        blueprint_path = output_dir / f"v2_intelligence_blueprint_{timestamp}.json"

        structured_insights = None
        if blueprint_path.exists():
            try:
                ai_data = json.loads(blueprint_path.read_text(encoding='utf-8'))
                structured_insights = {
                    'key_findings': [f.get('title') for f in (ai_data.get('finding_ledger', []) or []) if isinstance(f, dict) and f.get('title')][:5],
                    'recommendations': [r.get('title') for r in (ai_data.get('recommendations', []) or []) if isinstance(r, dict) and r.get('title')][:5],
                    'data_patterns': ai_data.get('trend_signals', {})
                }
            except:
                pass
        
        # Get file age
        import time as time_module
        age_seconds = time_module.time() - latest_summary.stat().st_mtime
        age_days = int(age_seconds / 86400)
        
        return {
            'summary_text': summary_text,
            'structured': structured_insights,
            'age_days': age_days,
            'timestamp': timestamp
        }
    except Exception as e:
        print(f"Error loading discovery insights: {e}")
        return None


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

        # Load and update persistent chat memory for this session
        update_chat_memory(chat_session_id, user_message)
        chat_memory = load_chat_memory(chat_session_id)
        memory_context = build_chat_memory_context(chat_memory)
        
        # Get discovery staleness threshold from session settings (days converted to seconds)
        staleness_threshold = chat_session_settings["discovery_freshness_days"] * 86400
        
        # Load latest discovery context if available
        discovery_context = ""
        discovery_age_warning = None
        output_dir = Path("output")
        
        # Find most recent V2 blueprint
        discovery_files = sorted(output_dir.glob("v2_intelligence_blueprint_*.json"), reverse=True)
        if discovery_files:
            try:
                discovery_file = discovery_files[0]
                
                # Parse timestamp from filename: v2_intelligence_blueprint_YYYYMMDD_HHMMSS.json
                timestamp_str = discovery_file.stem.replace('v2_intelligence_blueprint_', '')
                discovery_datetime = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                discovery_age_seconds = (datetime.now() - discovery_datetime).total_seconds()
                
                # Check if discovery is too old
                if discovery_age_seconds > staleness_threshold:
                    days_old = int(discovery_age_seconds / 86400)
                    discovery_age_warning = f"⚠️ Discovery data is {days_old} days old. Consider running a new discovery for up-to-date information."
                
                with discovery_file.open('r', encoding='utf-8') as fp:
                    latest_blueprint = json.load(fp)
                metadata = {
                    "overview": latest_blueprint.get("overview", {}) if isinstance(latest_blueprint, dict) else {}
                }
                
                # Analyze user query to determine if context is needed
                query_lower = user_message.lower()
                simple_greetings = any(word in query_lower for word in ['hi', 'hello', 'hey', 'thanks', 'thank you', 'bye'])
                
                # Check if query needs discovery insights
                needs_insights = any(keyword in query_lower for keyword in [
                    'summary', 'overview', 'recommend', 'best practice', 'optimization',
                    'use case', 'compliance', 'security', 'improve', 'assess'
                ])
                
                # Get overview for all custom LLM requests (lightweight, fast)
                overview = metadata.get('overview', {})
                
                if simple_greetings:
                    # For greetings, just show counts
                    discovery_context = f"\n🔍 Splunk Environment: {overview.get('total_indexes', 0)} indexes, {overview.get('total_sourcetypes', 0)} sourcetypes"
                else:
                    # For real queries on custom LLMs, provide ONLY summary stats (no detailed context)
                    # Local LLMs struggle with large contexts - let them use tool calls to get details
                    discovery_context = f"""
🔍 Splunk Environment Summary:
- Indexes: {overview.get('total_indexes', 0)}
- Sourcetypes: {overview.get('total_sourcetypes', 0)}
- Hosts: {overview.get('total_hosts', 0)}
- Users: {overview.get('total_users', 0)}
- Data (24h): {overview.get('data_volume_24h', 'unknown')}
- Version: {overview.get('splunk_version', 'unknown')}

For detailed information, use tool calls to query Splunk directly."""
                
                # Load discovery insights if needed for strategic questions
                if needs_insights:
                    insights = load_latest_discovery_insights()
                    if insights:
                        discovery_context += f"\n\n📊 DISCOVERY INSIGHTS (from {insights['age_days']} days ago):\n"
                        if insights.get('structured') and insights['structured'].get('key_findings'):
                            discovery_context += "\nKey Findings:\n"
                            for finding in insights['structured']['key_findings'][:3]:
                                discovery_context += f"- {finding}\n"
                        if insights.get('structured') and insights['structured'].get('recommendations'):
                            discovery_context += "\nRecommendations:\n"
                            for rec in insights['structured']['recommendations'][:3]:
                                discovery_context += f"- {rec}\n"
                

                
            except Exception as e:
                print(f"Could not load discovery context: {e}")
                import traceback
                traceback.print_exc()
        else:
            discovery_age_warning = "⚠️ No discovery data found. Run a discovery first to get environment context."

        rag_context = ""
        if bool(chat_session_settings.get("enable_rag_context", False)):
            rag_max_chunks = _safe_int(chat_session_settings.get("rag_max_chunks", 3))
            rag_context = build_lightweight_rag_context(user_message, max_chunks=rag_max_chunks)

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
        provider_name = str(getattr(config.llm, "provider", "")).strip().lower()
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
            latest_status_timeline.append({"iteration": 1, "action": "📁 Validating index existence", "time": 0.0})
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

                updated_memory = update_chat_memory(chat_session_id, user_message, latest_tool_calls)
                follow_on_actions = build_follow_on_actions(user_message, updated_memory, latest_tool_calls)
                return {
                    "response": response_text,
                    "initial_response": user_message,
                    "tool_calls": latest_tool_calls,
                    "iterations": len(latest_tool_calls),
                    "execution_time": "0.00s",
                    "insights": ["Index was validated directly from Splunk index inventory."],
                    "status_timeline": latest_status_timeline,
                    "discovery_age_warning": discovery_age_warning,
                    "chat_session_id": chat_session_id,
                    "chat_memory": updated_memory,
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
            latest_status_timeline.append({"iteration": 2, "action": "🔍 Retrieving latest event", "time": 0.0})
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

            updated_memory = update_chat_memory(chat_session_id, user_message, latest_tool_calls)
            follow_on_actions = build_follow_on_actions(user_message, updated_memory, latest_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": latest_tool_calls,
                "iterations": len(latest_tool_calls),
                "execution_time": "0.00s",
                "insights": ["Used deterministic latest-event flow for index validation and retrieval."],
                "status_timeline": latest_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        if bool(chat_session_settings.get("enable_splunk_augmentation", True)) and detect_edge_processor_template_request(user_message):
            skill_status_timeline: List[Dict[str, Any]] = []
            skill_tool_calls: List[Dict[str, Any]] = []

            knowledge_tool_name = resolve_tool_name("splunk_get_knowledge_objects", available_mcp_tools)
            skill_status_timeline.append({"iteration": 1, "action": "🧭 Fetching knowledge objects", "time": 0.0})

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

            updated_memory = update_chat_memory(chat_session_id, user_message, skill_tool_calls)
            follow_on_actions = build_follow_on_actions(user_message, updated_memory, skill_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": skill_tool_calls,
                "iterations": len(skill_tool_calls),
                "execution_time": "0.00s",
                "insights": ["Used deterministic template lookup for Edge Processor intent."],
                "status_timeline": skill_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
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
                offline_status_timeline.append({"iteration": attempt_idx, "action": "🔍 Searching for latest offline signal", "time": 0.0})
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

            updated_memory = update_chat_memory(chat_session_id, user_message, offline_tool_calls)
            follow_on_actions = build_follow_on_actions(user_message, updated_memory, offline_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": offline_tool_calls,
                "iterations": len(offline_tool_calls),
                "execution_time": "0.00s",
                "insights": ["Used deterministic offline-event lookup with index and time-range fallbacks."],
                "status_timeline": offline_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        basic_intent = detect_basic_inventory_intent(user_message) if bool(chat_session_settings.get("enable_splunk_augmentation", True)) else None
        if basic_intent:
            basic_status_timeline: List[Dict[str, Any]] = []
            basic_tool_calls: List[Dict[str, Any]] = []

            if basic_intent == "list_indexes":
                indexes_tool_name = resolve_tool_name("splunk_get_indexes", available_mcp_tools)
                args = {"row_limit": 200}
                basic_status_timeline.append({"iteration": 1, "action": "📁 Loading indexes", "time": 0.0})
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
                basic_status_timeline.append({"iteration": 1, "action": "🧾 Loading sourcetypes", "time": 0.0})
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
                basic_status_timeline.append({"iteration": 1, "action": "📊 Loading top indexes", "time": 0.0})
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
                basic_status_timeline.append({"iteration": 1, "action": "🚨 Loading top error sources", "time": 0.0})
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
                basic_status_timeline.append({"iteration": 1, "action": "🔐 Loading latest authentication failures", "time": 0.0})
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
                    basic_status_timeline.append({"iteration": 1, "action": f"📏 Counting events for index={target_index}", "time": 0.0})
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
                        basic_status_timeline.append({"iteration": attempt_idx, "action": f"📡 Checking last-seen for {target_host}", "time": 0.0})
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
                basic_status_timeline.append({"iteration": 1, "action": "🖥️ Loading hosts", "time": 0.0})
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
                basic_status_timeline.append({"iteration": 1, "action": "📚 Loading knowledge objects", "time": 0.0})
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

            updated_memory = update_chat_memory(chat_session_id, user_message, basic_tool_calls)
            follow_on_actions = build_follow_on_actions(user_message, updated_memory, basic_tool_calls)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": basic_tool_calls,
                "iterations": len(basic_tool_calls),
                "execution_time": "0.00s",
                "insights": [f"Used deterministic basic intent route: {basic_intent}."],
                "status_timeline": basic_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }
        
        # Initialize LLM client (cached for performance)
        print(f"🔵 [CHAT] Getting LLM client...")
        llm_client = get_or_create_llm_client(config)
        print(f"🔵 [CHAT] LLM client initialized, provider: {config.llm.provider}")
        
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
        # For custom LLM with simple greetings, skip system prompt entirely for speed
        system_prompt = build_compact_chat_prompt(
            query_tool_name=query_tool_name,
            discovery_context=discovery_context,
            rag_context=rag_context,
            memory_context=memory_context,
            available_tools_text=available_tools_text,
            discovery_age_warning=discovery_age_warning
        )

        query_lower = user_message.lower().strip()
        is_greeting = any(phrase in query_lower for phrase in ['hi', 'hello', 'hey', 'how are you', 'thanks', 'thank you', 'bye', 'goodbye'])
        
        if is_custom_provider and is_greeting:
            # Bare minimum for greetings - just the user message
            messages = [{"role": "user", "content": user_message}]
        else:
            # Check if history is already in server format (has 'role' key) or UI format (has 'type' key)
            if history and len(history) > 0 and 'role' in history[0]:
                # Server conversation history - use directly (already has system messages and reasoning)
                messages = history.copy()
                # Add current user message
                messages.append({"role": "user", "content": user_message})
            else:
                # UI history - needs conversion and system prompt
                messages = [{"role": "system", "content": system_prompt}]
                
                # Add recent history for context (use session setting)
                context_limit = chat_session_settings["context_history"]
                for msg in history[-context_limit:] if context_limit > 0 else []:
                    if msg.get('type') == 'user':
                        messages.append({"role": "user", "content": msg['content']})
                    elif msg.get('type') == 'assistant':
                        messages.append({"role": "assistant", "content": msg['content']})
                
                # Add current user message
                messages.append({"role": "user", "content": user_message})
        
        # Get LLM response - use session max_tokens setting (with 15% limit for initial chat)
        chat_max_tokens = min(2000, int(chat_session_settings["max_tokens"] * 0.15))
        print(f"🔵 [CHAT] Calling LLM with {len(messages)} messages, max_tokens={chat_max_tokens}")
        print(f"🔵 [CHAT] Client type: {type(llm_client)}, has generate_response: {hasattr(llm_client, 'generate_response')}")
        print(f"🔵 [CHAT] About to await generate_response...")
        response = await llm_client.generate_response(
            messages=messages,
            max_tokens=chat_max_tokens,
            temperature=config.llm.temperature
        )
        print(f"🔵 [CHAT] Got response: {len(response)} chars")
        
        # Check if response contains tool call or SPL
        tool_call = None
        spl_in_text = None
        clean_response = response
        
        try:
            import re
            
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
            
            # Extract tool call using <TOOL_CALL> tags
            # Extract everything between the tags (handles nested braces correctly)
            if '<TOOL_CALL>' in response and '</TOOL_CALL>' in response:
                start = response.find('<TOOL_CALL>') + len('<TOOL_CALL>')
                end = response.find('</TOOL_CALL>')
                raw_json = response[start:end].strip()
                
                print(f"🔍 Raw JSON: {repr(raw_json[:200])}")

                try:
                    tool_data = parse_tool_call_payload(raw_json)
                    if not isinstance(tool_data, dict):
                        raise ValueError("Invalid tool payload")
                    tool_name = tool_data.get('tool')
                    tool_args = tool_data.get('args', {})
                    
                    # Convert to MCP format
                    tool_call = {
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": tool_args
                        }
                    }
                    
                    # Remove tool call from response for cleaner display
                    clean_response = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', response, flags=re.DOTALL).strip()
                    
                    debug_log(f"Extracted tool call - {tool_name} with args: {tool_args}", "query", tool_args)
                except Exception as e:
                    print(f"❌ JSON Parse Error: {e}")
                    print(f"❌ Raw JSON that failed: {raw_json}")
                    debug_log(f"Tool call JSON parse error: {e}", "error")
            
            # Extract SPL queries from code blocks
            spl_patterns = [
                r'```spl\s*\n(.*?)```',
                r'```splunk\s*\n(.*?)```', 
                r'```\s*\n((?:search\s+)?index=.*?)```',
            ]
            for pattern in spl_patterns:
                match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if match:
                    spl_in_text = match.group(1).strip()
                    debug_log(f"Found SPL in code block", "info")
                    break

            if not tool_call and spl_in_text:
                tool_call = {
                    "method": "tools/call",
                    "params": {
                        "name": query_tool_name,
                        "arguments": {
                            "query": spl_in_text,
                            "earliest_time": "-24h",
                            "latest_time": "now"
                        }
                    }
                }
                clean_response = re.sub(r'```(?:spl|splunk)?\s*\n.*?```', '', response, flags=re.DOTALL | re.IGNORECASE).strip()
                debug_log("Converted SPL code block into executable tool call", "info")
                    
        except Exception as e:
            debug_log(f"Error parsing response: {e}", "error")
            import traceback
            traceback.print_exc()
        
        if tool_call and tool_call.get('method') == 'tools/call':
            # ===== INTELLIGENT AGENTIC LOOP WITH QUALITY-DRIVEN STOPPING =====
            import time as time_module
            
            start_time = time_module.time()
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
            status_timeline = []  # Track all actions for frontend display
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
                    params = call.get('params', {})
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
                
                # Add post-tool context if available
                context_section = f"\n\nRELEVANT CONTEXT:\n{post_tool_context}" if post_tool_context else ""
                
                if has_error:
                    error_msg = result_summary.get('message', 'Unknown error')
                    system_feedback = f"""🔴 ITERATION {iteration} RESULT: ERROR

Error: {error_msg}

ACCUMULATED INSIGHTS SO FAR:
{insights_summary}{context_section}

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

{result_summary.get('findings', [])}

ACCUMULATED INSIGHTS:
{insights_summary}{context_section}

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
{insights_summary}{context_section}

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
                
                followup_max_tokens = min(2500, int(chat_session_settings["max_tokens"] * 0.18))
                next_response = await llm_client.generate_response(
                    messages=conversation_history,
                    max_tokens=followup_max_tokens,
                    temperature=config.llm.temperature * 0.9  # Slightly lower temp for more focused decisions
                )
                
                # Parse LLM's response for tool call
                next_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', next_response, re.DOTALL)
                
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
                        
                        if is_internal:
                            print(f"📝 [Iteration {iteration}] High quality but internal reasoning - requesting final user answer")
                            
                            final_prompt = f"""You successfully investigated the user's question: "{user_message}"

ACCUMULATED FINDINGS:
{insights_summary}

Now provide a COMPLETE, USER-FACING answer that includes:
1. Direct answer to their question with specific data/numbers
2. Key findings and patterns you discovered  
3. Any relevant context or recommendations

Write as if speaking directly to the user (avoid phrases like "I investigated", "I found", etc.)."""
                            
                            conversation_history.append({"role": "system", "content": final_prompt})
                            
                            final_max_tokens = min(3000, int(chat_session_settings["max_tokens"] * 0.25))
                            final_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=final_max_tokens,
                                temperature=config.llm.temperature
                            )
                            final_answer = final_response
                            print(f"✅ [Iteration {iteration}] Final user answer generated ({len(final_response)} chars)")
                        else:
                            # Response is already user-facing - but double-check for tool calls
                            if '<TOOL_CALL>' in next_response:
                                print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> but regex missed it - parsing and continuing")
                                # Extract and execute the tool call
                                next_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', next_response, re.DOTALL)
                                if next_tool_match:
                                    try:
                                        tool_data = json.loads(next_tool_match.group(1))
                                        tool_name = tool_data.get('tool')
                                        tool_args = tool_data.get('args', {})
                                        tool_call = {
                                            "method": "tools/call",
                                            "params": {
                                                "name": tool_name,
                                                "arguments": tool_args
                                            }
                                        }
                                        continue  # Execute this tool call in next iteration
                                    except json.JSONDecodeError as e:
                                        print(f"❌ Failed to parse tool call JSON (HIGH quality, first check): {e}")
                                        print(f"   Malformed JSON: {next_tool_match.group(1)[:200] if next_tool_match else 'N/A'}")
                                        # Strip the malformed tool call and use the text explanation
                                        final_answer = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', next_response, flags=re.DOTALL).strip()
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
                            # Fall through to execute next tool
                        else:
                            # Double-check for tool calls that regex might have missed
                            if '<TOOL_CALL>' in next_response:
                                print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> but regex missed it - parsing and continuing")
                                next_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', next_response, re.DOTALL)
                                if next_tool_match:
                                    try:
                                        tool_data = json.loads(next_tool_match.group(1))
                                        tool_name = tool_data.get('tool')
                                        tool_args = tool_data.get('args', {})
                                        tool_call = {
                                            "method": "tools/call",
                                            "params": {
                                                "name": tool_name,
                                                "arguments": tool_args
                                            }
                                        }
                                        continue  # Execute this tool call in next iteration
                                    except json.JSONDecodeError as e:
                                        print(f"❌ Failed to parse tool call JSON (HIGH quality, second check): {e}")
                                        print(f"   Malformed JSON: {next_tool_match.group(1)[:200] if next_tool_match else 'N/A'}")
                                        # Strip the malformed tool call and use the text explanation
                                        final_answer = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', next_response, flags=re.DOTALL).strip()
                                        if not final_answer:
                                            final_answer = "Investigation incomplete due to malformed query format."
                                        break
                            else:
                                print(f"✅ [Iteration {iteration}] High quality answer ({quality_score}/100) - investigation complete")
                                final_answer = next_response
                    
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
                        continuation_intent = any(keyword in next_response.lower() for keyword in 
                                                 ["i'll proceed", "i will proceed", "let me try", "i'll check", 
                                                  "i will check", "next step", "let me search", "i'll search"])
                        
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
                            
                            retry_max_tokens = min(2000, int(chat_session_settings["max_tokens"] * 0.15))
                            retry_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=retry_max_tokens,
                                temperature=config.llm.temperature * 0.7  # Lower temp for stricter format
                            )
                            
                            # Check if retry has proper format
                            retry_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', retry_response, re.DOTALL)
                            if retry_tool_match:
                                print(f"✅ Retry successful - proper tool call format obtained")
                                next_response = retry_response
                                next_tool_match = retry_tool_match
                                # Fall through to tool execution below
                            else:
                                print(f"⚠️  Retry failed - LLM still not providing tool call format")
                                print(f"    Response fragment: {retry_response[:200]}")
                                final_answer = f"Investigation incomplete. After {iteration} iterations, unable to determine next steps.\n\nLast findings:\n{insights_summary}\n\nSuggestion: Try a more specific query or different approach."
                                break
                        else:
                            # No clear continuation intent - accept as final
                            print(f"🏁 [Iteration {iteration}] No continuation intent detected despite low quality")
                            final_answer = next_response
                            break
                    
                    # Has tool call (either original or from retry) - execute it
                    if next_tool_match:
                        try:
                            tool_data = json.loads(next_tool_match.group(1))
                            tool_name = tool_data.get('tool')
                            tool_args = tool_data.get('args', {})
                            
                            tool_call = {
                                "method": "tools/call",
                                "params": {
                                    "name": tool_name,
                                    "arguments": tool_args
                                }
                            }
                            
                            clean_response = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', next_response, flags=re.DOTALL).strip()
                            continue  # Execute this tool call in next iteration
                        except json.JSONDecodeError as e:
                            print(f"❌ Failed to parse tool call: {e}")
                            final_answer = next_response
                            break
                
                else:
                    # MODERATE QUALITY (50-69) - Middle ground
                    if next_tool_match:
                        # Moderate quality but LLM wants to refine - allow it (up to 5 iterations)
                        if iteration < 5:
                            print(f"▶️  [Iteration {iteration}] Moderate quality ({quality_score}/100), allowing refinement")
                            try:
                                tool_data = json.loads(next_tool_match.group(1))
                                tool_name = tool_data.get('tool')
                                tool_args = tool_data.get('args', {})
                                
                                tool_call = {
                                    "method": "tools/call",
                                    "params": {
                                        "name": tool_name,
                                        "arguments": tool_args
                                    }
                                }
                                continue  # Execute this tool call in next iteration
                            except json.JSONDecodeError as e:
                                print(f"❌ Failed to parse tool call: {e}")
                                final_answer = next_response
                                break
                        else:
                            # Too many iterations for moderate quality - accept current
                            print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) after {iteration} iterations - accepting")
                            final_answer = next_response
                            break
                    else:
                        # Moderate quality, no tool call - check for continuation intent
                        continuation_intent = any(keyword in next_response.lower() for keyword in 
                                                 ["i'll proceed", "i will proceed", "let me try", "i'll check", 
                                                  "i will check", "next step", "let me search", "i'll search",
                                                  "i'll execute", "i will execute", "i'll query", "i will query",
                                                  "let me retrieve", "i'll retrieve", "i will retrieve"])
                        
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
                            
                            retry_max_tokens = min(2000, int(chat_session_settings["max_tokens"] * 0.15))
                            retry_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=retry_max_tokens,
                                temperature=config.llm.temperature * 0.7
                            )
                            
                            retry_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', retry_response, re.DOTALL)
                            if retry_tool_match:
                                print(f"✅ Retry successful - proper tool call format obtained")
                                next_response = retry_response
                                next_tool_match = retry_tool_match
                                # Fall through to tool execution
                                try:
                                    tool_data = json.loads(retry_tool_match.group(1))
                                    tool_name = tool_data.get('tool')
                                    tool_args = tool_data.get('args', {})
                                    
                                    tool_call = {
                                        "method": "tools/call",
                                        "params": {
                                            "name": tool_name,
                                            "arguments": tool_args
                                        }
                                    }
                                    continue  # Execute this tool call in next iteration
                                except json.JSONDecodeError as e:
                                    print(f"❌ Failed to parse tool call: {e}")
                                    final_answer = next_response
                                    break
                            else:
                                print(f"⚠️  Retry failed - accepting current answer")
                                final_answer = next_response
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
                                
                                if is_internal:
                                    print(f"📝 [Iteration {iteration}] Moderate quality with data but internal reasoning - requesting final answer")
                                    
                                    final_prompt = f"""You successfully investigated the user's question: "{user_message}"

ACCUMULATED FINDINGS:
{insights_summary}

Now provide a COMPLETE, USER-FACING answer that includes:
1. Direct answer to their question with specific data/numbers
2. Key findings and patterns you discovered  
3. Any relevant context or recommendations

Write as if speaking directly to the user (avoid phrases like "I investigated", "I found", "I will", etc.)."""
                                    
                                    conversation_history.append({"role": "system", "content": final_prompt})
                                    
                                    final_max_tokens = min(3000, int(chat_session_settings["max_tokens"] * 0.25))
                                    final_response = await llm_client.generate_response(
                                        messages=conversation_history,
                                        max_tokens=final_max_tokens,
                                        temperature=config.llm.temperature
                                    )
                                    final_answer = final_response
                                    print(f"✅ [Iteration {iteration}] Final user answer generated ({len(final_response)} chars)")
                                else:
                                    # Response is already user-facing - but check for tool calls
                                    if '<TOOL_CALL>' in next_response:
                                        print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> - parsing and continuing")
                                        next_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', next_response, re.DOTALL)
                                        if next_tool_match:
                                            try:
                                                tool_data = json.loads(next_tool_match.group(1))
                                                tool_name = tool_data.get('tool')
                                                tool_args = tool_data.get('args', {})
                                                tool_call = {
                                                    "method": "tools/call",
                                                    "params": {
                                                        "name": tool_name,
                                                        "arguments": tool_args
                                                    }
                                                }
                                                continue  # Execute this tool call in next iteration
                                            except json.JSONDecodeError as e:
                                                print(f"❌ Failed to parse tool call JSON: {e}")
                                                print(f"   Malformed JSON: {next_tool_match.group(1)[:200] if next_tool_match else 'N/A'}")
                                                # Strip the malformed tool call and use the text explanation
                                                final_answer = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', next_response, flags=re.DOTALL).strip()
                                                if not final_answer:
                                                    final_answer = "Investigation incomplete due to malformed query format."
                                                break
                                    else:
                                        print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) - accepting answer")
                                        final_answer = next_response
                            else:
                                # No data - accept response as-is, but check for tool calls
                                if '<TOOL_CALL>' in next_response:
                                    print(f"⚠️ [Iteration {iteration}] Response contains <TOOL_CALL> - parsing and continuing")
                                    next_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*\})\s*</TOOL_CALL>', next_response, re.DOTALL)
                                    if next_tool_match:
                                        try:
                                            tool_data = json.loads(next_tool_match.group(1))
                                            tool_name = tool_data.get('tool')
                                            tool_args = tool_data.get('args', {})
                                            tool_call = {
                                                "method": "tools/call",
                                                "params": {
                                                    "name": tool_name,
                                                    "arguments": tool_args
                                                }
                                            }
                                            continue  # Execute this tool call in next iteration
                                        except json.JSONDecodeError as e:
                                            print(f"❌ Failed to parse tool call JSON: {e}")
                                            print(f"   Malformed JSON: {next_tool_match.group(1)[:200] if next_tool_match else 'N/A'}")
                                            # Strip the malformed tool call and use the text explanation
                                            final_answer = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', next_response, flags=re.DOTALL).strip()
                                            if not final_answer:
                                                final_answer = "Investigation incomplete due to malformed query format."
                                            break
                                else:
                                    print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) - accepting answer")
                                    final_answer = next_response
                            break
            
            # CRITICAL SAFETY CHECK: If final_answer contains <TOOL_CALL>, the LLM isn't done
            # This should never happen, but if it does, strip the tool call and force continuation
            if final_answer and '<TOOL_CALL>' in final_answer:
                print(f"⚠️ WARNING: final_answer contains <TOOL_CALL> tags - LLM finished prematurely!")
                print(f"Response: {final_answer[:200]}...")
                # Strip tool calls from response and return with warning
                final_answer = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', final_answer, flags=re.DOTALL).strip()
                if not final_answer:
                    final_answer = "Investigation incomplete. The agent attempted to continue but reached response limits."
            
            # Return comprehensive response with status timeline
            # Include conversation_history so follow-up queries maintain context
            updated_memory = update_chat_memory(chat_session_id, user_message, all_tool_calls)
            follow_on_actions = build_follow_on_actions(user_message, updated_memory, all_tool_calls)
            return {
                "response": final_answer or "Investigation complete. See findings above.",
                "initial_response": user_message,
                "tool_calls": all_tool_calls,
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
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }
        
        # No tool call, return clean response with any SPL found
        updated_memory = update_chat_memory(chat_session_id, user_message)
        follow_on_actions = build_follow_on_actions(user_message, updated_memory)
        return {
            "response": clean_response,
            "spl_in_text": spl_in_text,
            "discovery_age_warning": discovery_age_warning,
            "chat_session_id": chat_session_id,
            "chat_memory": updated_memory,
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
    return HTMLResponse(content=get_frontend_html())


def get_frontend_html():
    """Generate the frontend HTML with embedded React app."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Splunk MCP Discovery Tool</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .animated-gradient {
            background: linear-gradient(-45deg, #667eea, #764ba2, #667eea, #764ba2);
            background-size: 400% 400%;
            animation: gradientShift 3s ease infinite;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .pulse-ring {
            animation: pulse-ring 1.25s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
        }
        
        @keyframes pulse-ring {
            0% { transform: scale(0.33); }
            80%, 100% { opacity: 0; }
        }
        
        .progress-bar {
            transition: width 0.3s ease;
        }
        
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .slide-in {
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from { transform: translateX(-100%); }
            to { transform: translateX(0); }
        }
        
        .scroll-container {
            scrollbar-width: thin;
            scrollbar-color: #667eea #f1f5f9;
        }
        
        .scroll-container::-webkit-scrollbar {
            width: 8px;
        }
        
        .scroll-container::-webkit-scrollbar-track {
            background: #f1f5f9;
            border-radius: 4px;
        }
        
        .scroll-container::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 4px;
        }
        
        .scroll-container::-webkit-scrollbar-thumb:hover {
            background: #5a67d8;
        }

        [data-theme='dark'] .settings-modal-shell {
            color: #e5e7eb;
        }

        [data-theme='dark'] .settings-modal-shell .text-gray-900 { color: #f3f4f6 !important; }
        [data-theme='dark'] .settings-modal-shell .text-gray-800 { color: #e5e7eb !important; }
        [data-theme='dark'] .settings-modal-shell .text-gray-700 { color: #d1d5db !important; }
        [data-theme='dark'] .settings-modal-shell .text-gray-600 { color: #cbd5e1 !important; }
        [data-theme='dark'] .settings-modal-shell .text-gray-500 { color: #94a3b8 !important; }
        [data-theme='dark'] .settings-modal-shell .text-gray-400 { color: #94a3b8 !important; }

        [data-theme='dark'] .settings-modal-shell .bg-white { background-color: #1f2937 !important; }
        [data-theme='dark'] .settings-modal-shell .bg-gray-50 { background-color: #111827 !important; }
        [data-theme='dark'] .settings-modal-shell .bg-gray-100 { background-color: #1f2937 !important; }
        [data-theme='dark'] .settings-modal-shell .bg-amber-50 { background-color: #3f2c12 !important; }
        [data-theme='dark'] .settings-modal-shell .bg-emerald-50 { background-color: #0f3b30 !important; }
        [data-theme='dark'] .settings-modal-shell .from-green-50,
        [data-theme='dark'] .settings-modal-shell .to-emerald-50,
        [data-theme='dark'] .settings-modal-shell .from-purple-50,
        [data-theme='dark'] .settings-modal-shell .to-indigo-50 { background-image: none !important; background-color: #1f2937 !important; }

        [data-theme='dark'] .settings-modal-shell .border-gray-100,
        [data-theme='dark'] .settings-modal-shell .border-gray-200,
        [data-theme='dark'] .settings-modal-shell .border-gray-300 { border-color: #4b5563 !important; }

        [data-theme='dark'] .settings-modal-shell input,
        [data-theme='dark'] .settings-modal-shell select,
        [data-theme='dark'] .settings-modal-shell textarea {
            background-color: #111827 !important;
            color: #f3f4f6 !important;
            border-color: #4b5563 !important;
        }

        [data-theme='dark'] .settings-modal-shell input::placeholder,
        [data-theme='dark'] .settings-modal-shell textarea::placeholder {
            color: #94a3b8 !important;
        }

        [data-theme='dark'] .settings-modal-shell code {
            background-color: #0f172a !important;
            color: #e2e8f0 !important;
        }

        [data-theme='dark'] .connection-popover {
            border: 1px solid #4b5563;
        }

        [data-theme='dark'] .connection-popover .text-gray-900 { color: #f3f4f6 !important; }
        [data-theme='dark'] .connection-popover .text-gray-800 { color: #e5e7eb !important; }
        [data-theme='dark'] .connection-popover .text-gray-700 { color: #d1d5db !important; }
        [data-theme='dark'] .connection-popover .text-gray-600 { color: #cbd5e1 !important; }
        [data-theme='dark'] .connection-popover .text-gray-500 { color: #94a3b8 !important; }
        [data-theme='dark'] .connection-popover .bg-white { background-color: #1f2937 !important; }
        [data-theme='dark'] .connection-popover .bg-gray-50 { background-color: #111827 !important; }
        [data-theme='dark'] .connection-popover .from-purple-50,
        [data-theme='dark'] .connection-popover .to-indigo-50,
        [data-theme='dark'] .connection-popover .from-green-50,
        [data-theme='dark'] .connection-popover .to-emerald-50,
        [data-theme='dark'] .connection-popover .from-blue-50,
        [data-theme='dark'] .connection-popover .to-cyan-50 { background-image: none !important; background-color: #111827 !important; }
        [data-theme='dark'] .connection-popover .border-gray-200,
        [data-theme='dark'] .connection-popover .border-gray-100,
        [data-theme='dark'] .connection-popover .border-indigo-100,
        [data-theme='dark'] .connection-popover .border-green-100,
        [data-theme='dark'] .connection-popover .border-blue-100 { border-color: #374151 !important; }

        [data-theme='dark'] .chat-settings-modal-shell {
            color: #e5e7eb;
        }

        [data-theme='dark'] .chat-settings-modal-shell .text-gray-900 { color: #f3f4f6 !important; }
        [data-theme='dark'] .chat-settings-modal-shell .text-gray-800 { color: #e5e7eb !important; }
        [data-theme='dark'] .chat-settings-modal-shell .text-gray-700 { color: #d1d5db !important; }
        [data-theme='dark'] .chat-settings-modal-shell .text-gray-600 { color: #cbd5e1 !important; }
        [data-theme='dark'] .chat-settings-modal-shell .text-gray-500 { color: #94a3b8 !important; }

        [data-theme='dark'] .chat-settings-modal-shell .bg-white { background-color: #1f2937 !important; }
        [data-theme='dark'] .chat-settings-modal-shell .bg-gray-50 { background-color: #111827 !important; }

        [data-theme='dark'] .chat-settings-modal-shell .from-green-50,
        [data-theme='dark'] .chat-settings-modal-shell .to-emerald-50,
        [data-theme='dark'] .chat-settings-modal-shell .from-purple-50,
        [data-theme='dark'] .chat-settings-modal-shell .to-indigo-50,
        [data-theme='dark'] .chat-settings-modal-shell .from-amber-50,
        [data-theme='dark'] .chat-settings-modal-shell .to-yellow-50,
        [data-theme='dark'] .chat-settings-modal-shell .from-blue-50,
        [data-theme='dark'] .chat-settings-modal-shell .to-cyan-50,
        [data-theme='dark'] .chat-settings-modal-shell .from-indigo-50,
        [data-theme='dark'] .chat-settings-modal-shell .to-violet-50 {
            background-image: none !important;
            background-color: #111827 !important;
        }

        [data-theme='dark'] .chat-settings-modal-shell .border-gray-200,
        [data-theme='dark'] .chat-settings-modal-shell .border-gray-300,
        [data-theme='dark'] .chat-settings-modal-shell .border-green-200,
        [data-theme='dark'] .chat-settings-modal-shell .border-purple-200,
        [data-theme='dark'] .chat-settings-modal-shell .border-amber-200,
        [data-theme='dark'] .chat-settings-modal-shell .border-blue-200,
        [data-theme='dark'] .chat-settings-modal-shell .border-indigo-200,
        [data-theme='dark'] .chat-settings-modal-shell .border-indigo-100 {
            border-color: #4b5563 !important;
        }

        [data-theme='dark'] .chat-settings-modal-shell input,
        [data-theme='dark'] .chat-settings-modal-shell select,
        [data-theme='dark'] .chat-settings-modal-shell textarea {
            background-color: #111827 !important;
            color: #f3f4f6 !important;
            border-color: #4b5563 !important;
        }
    </style>
</head>
<body class="bg-gray-50">
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect, useRef } = React;

        const generateChatSessionId = () => {
            const now = new Date();
            const stamp = now.toISOString().replace(/[-:T\\.Z]/g, '').slice(0, 14);
            const rand = Math.random().toString(36).slice(2, 8);
            return `chat_${stamp}_${rand}`;
        };

        const normalizeProvider = (provider) => {
            const value = String(provider || 'openai').toLowerCase().trim();
            if (value === 'custom endpoint') return 'custom';
            if (value === 'azure openai') return 'azure';
            if (value === 'claude') return 'anthropic';
            if (value === 'google' || value === 'google ai') return 'gemini';
            return value;
        };
        
        // Error Boundary to catch React rendering errors
        class ErrorBoundary extends React.Component {
            constructor(props) {
                super(props);
                this.state = { hasError: false, error: null, errorInfo: null };
            }
            
            static getDerivedStateFromError(error) {
                return { hasError: true };
            }
            
            componentDidCatch(error, errorInfo) {
                console.error('React Error Boundary caught:', error, errorInfo);
                this.setState({ error, errorInfo });
            }
            
            render() {
                if (this.state.hasError) {
                    return (
                        <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                            <div className="bg-white rounded-lg shadow-xl p-8 max-w-2xl">
                                <h1 className="text-2xl font-bold text-red-600 mb-4">
                                    <i className="fas fa-exclamation-triangle mr-2"></i>
                                    Application Error
                                </h1>
                                <p className="text-gray-700 mb-4">
                                    Something went wrong. Please refresh the page to continue.
                                </p>
                                <div className="bg-gray-100 p-4 rounded mb-4 overflow-auto max-h-64">
                                    <pre className="text-sm text-red-600">
                                        {this.state.error && this.state.error.toString()}
                                    </pre>
                                </div>
                                <button
                                    onClick={() => window.location.reload()}
                                    className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
                                >
                                    <i className="fas fa-sync-alt mr-2"></i>
                                    Reload Page
                                </button>
                            </div>
                        </div>
                    );
                }
                return this.props.children;
            }
        }
        
        function App() {
            const THEME_PREFERENCE_KEY = 'dt4sms_theme_preference';
            const [isConnected, setIsConnected] = useState(false);
            const [discoveryStatus, setDiscoveryStatus] = useState('idle');
            const [messages, setMessages] = useState([]);
            const [progress, setProgress] = useState({ percentage: 0, description: '' });
            const [reports, setReports] = useState([]);
            const [sessionCatalog, setSessionCatalog] = useState([]);
            const [discoveryDashboard, setDiscoveryDashboard] = useState(null);
            const [v2Intelligence, setV2Intelligence] = useState(null);
            const [v2Artifacts, setV2Artifacts] = useState({ has_data: false, artifacts: [], count: 0 });
            const [workflowTab, setWorkflowTab] = useState('admin');
            const [compareSelection, setCompareSelection] = useState({ current: 'latest', baseline: 'previous' });
            const [discoveryCompare, setDiscoveryCompare] = useState(null);
            const [runbookPayload, setRunbookPayload] = useState(null);
            const [selectedReport, setSelectedReport] = useState(null);
            const [reportContent, setReportContent] = useState(null);
            const [expandedSessions, setExpandedSessions] = useState({});
            const [expandedYears, setExpandedYears] = useState({});
            const [expandedMonths, setExpandedMonths] = useState({});
            const [expandedDays, setExpandedDays] = useState({});
            const [isChatOpen, setIsChatOpen] = useState(false);
            const [chatMessages, setChatMessages] = useState([]);
            const [chatInput, setChatInput] = useState('');
            const [isTyping, setIsTyping] = useState(false);
            const [chatStatus, setChatStatus] = useState(''); // Real-time status during investigation
            const [isChatSettingsOpen, setIsChatSettingsOpen] = useState(false);
            const [chatSettings, setChatSettings] = useState(null); // Loaded from API
            const [serverConversationHistory, setServerConversationHistory] = useState(null); // Server's full conversation with reasoning
            const [chatSessionId, setChatSessionId] = useState(generateChatSessionId());
            const [workspaceTab, setWorkspaceTab] = useState('mission');

            const [connectionInfo, setConnectionInfo] = useState(null);
            
            // Discovery timer state
            const [discoveryStartTime, setDiscoveryStartTime] = useState(null);
            const [elapsedTime, setElapsedTime] = useState(0);
            
            // Summary modal state
            const [isSummaryModalOpen, setIsSummaryModalOpen] = useState(false);
            const [summaryData, setSummaryData] = useState(null);
            const [isLoadingSummary, setIsLoadingSummary] = useState(false);
            const [currentSessionId, setCurrentSessionId] = useState(null);
            const [activeTab, setActiveTab] = useState('summary'); // 'summary', 'queries', 'tasks'
            const [queryFilter, setQueryFilter] = useState('all'); // 'all', 'ai_finding', 'template'
            const [summaryProgress, setSummaryProgress] = useState({
                stage: 'idle',
                progress: 0,
                message: 'Not started'
            });
            
            // Settings modal state
            const [isSettingsOpen, setIsSettingsOpen] = useState(false);
            const [config, setConfig] = useState(null);
            const [selectedProvider, setSelectedProvider] = useState('openai');
            const [isCredentialModalOpen, setIsCredentialModalOpen] = useState(false);
            const [isConnectionModalOpen, setIsConnectionModalOpen] = useState(false);
            const [connectionModalPosition, setConnectionModalPosition] = useState({ top: 72, left: 16, pointerLeft: 28 });
            const [credentialName, setCredentialName] = useState('');
            const [savedCredentials, setSavedCredentials] = useState({});
            const [loadedCredentialName, setLoadedCredentialName] = useState(null); // Track which credential is currently loaded
            const [isUpdateMode, setIsUpdateMode] = useState(false); // Track if modal is in update mode
            const [isLoadingCredential, setIsLoadingCredential] = useState(false); // Flag to prevent clearing during load
            const [apiKeyPlaceholder, setApiKeyPlaceholder] = useState('Enter API key'); // Track placeholder state
            const [showConfigForm, setShowConfigForm] = useState(false); // Show/hide configuration form
            const [availableModels, setAvailableModels] = useState([]); // Available models from API
            const [isLoadingModels, setIsLoadingModels] = useState(false); // Loading state for model fetch
            const [selectedModel, setSelectedModel] = useState(''); // Currently selected model
            
            // MCP Configuration Vault State
            const [savedMCPConfigs, setSavedMCPConfigs] = useState({});
            const [loadedMCPConfigName, setLoadedMCPConfigName] = useState(null); // Track which MCP config is currently loaded
            const [isMCPSaveModalOpen, setIsMCPSaveModalOpen] = useState(false); // MCP save modal visibility
            const [mcpConfigName, setMCPConfigName] = useState(''); // MCP config name for saving
            const [mcpConfigDescription, setMCPConfigDescription] = useState(''); // MCP config description
            const [showMCPConfigForm, setShowMCPConfigForm] = useState(false); // Show/hide MCP configuration form
            const [mcpTokenPlaceholder, setMCPTokenPlaceholder] = useState('Enter token'); // Track token placeholder state
            const [showSuggestedQueries, setShowSuggestedQueries] = useState(false);
            const [themePreference, setThemePreference] = useState(() => {
                try {
                    const savedTheme = localStorage.getItem(THEME_PREFERENCE_KEY);
                    if (savedTheme === 'light' || savedTheme === 'dark' || savedTheme === 'system') {
                        return savedTheme;
                    }
                } catch (error) {
                    console.error('Failed to read theme preference:', error);
                }
                return 'system';
            });
            const [resolvedTheme, setResolvedTheme] = useState('light');

            const isMissionTab = workspaceTab === 'mission';
            const isIntelligenceTab = workspaceTab === 'intelligence';
            const isArtifactsTab = workspaceTab === 'artifacts';
            const isDarkTheme = resolvedTheme === 'dark';
            const panelClass = isDarkTheme ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
            const panelMutedClass = isDarkTheme ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200';
            const headingClass = isDarkTheme ? 'text-gray-100' : 'text-gray-900';
            const subtextClass = isDarkTheme ? 'text-gray-300' : 'text-gray-600';
            const mutedTextClass = isDarkTheme ? 'text-gray-400' : 'text-gray-500';
            const v2Blueprint = v2Intelligence?.blueprint || null;
            const v2Overview = v2Blueprint?.overview || {};
            const v2CapabilityGraph = v2Blueprint?.capability_graph || {};
            const v2CoverageGaps = Array.isArray(v2Blueprint?.coverage_gaps) ? v2Blueprint.coverage_gaps : [];
            const v2FindingLedger = Array.isArray(v2Blueprint?.finding_ledger) ? v2Blueprint.finding_ledger : [];
            const v2UseCases = Array.isArray(v2Blueprint?.suggested_use_cases) ? v2Blueprint.suggested_use_cases : [];
            const summaryStageOrder = {
                idle: 0,
                loading: 1,
                loading_reports: 1,
                generating_queries: 2,
                identifying_unknowns: 2,
                generating_summary: 3,
                creating_summary: 3,
                generating_tasks: 4,
                saving: 5,
                complete: 6,
                error: 0
            };
            const currentSummaryStep = summaryStageOrder[summaryProgress.stage] || 0;
            const isSummaryStepDone = (step) => summaryProgress.stage === 'complete' || currentSummaryStep > step;
            const isSummaryStepActive = (step) => summaryProgress.stage !== 'complete' && currentSummaryStep === step;

            const suggestedChatQueries = [
                'Give me a narrative overview of what our Splunk environment appears to prioritize operationally.',
                'What story do the current data sources tell about platform usage, reliability, and potential blind spots?',
                'If you were onboarding a new security lead, what should they review first and why?',
                'Describe likely risk trends we should monitor weekly, and how to validate whether they are improving.',
                'Identify where data quality issues could silently undermine detections or reporting confidence.',
                'Propose a practical 30-day hardening plan with quick wins, medium-term tasks, and measurable outcomes.',
                'Suggest a recursive analysis loop we can run each week to catch drift, anomalies, and hidden failure modes.',
                'Translate the discovery output into executive-ready priorities with business impact and verification steps.'
            ];
            
            // Function to track when settings have been modified
            const handleSettingsChange = () => {
                // Don't clear the loaded credential name - we need it to show "Update Active Connection" button
                // The button logic will handle whether it's an update or new save
            };
            
            // Function specifically for API key changes
            const handleApiKeyChange = () => {
                setApiKeyPlaceholder('Enter API key');
                handleSettingsChange();
            };
            
            // Poll for summarization progress
            useEffect(() => {
                if (!isLoadingSummary || !currentSessionId) return;
                
                const interval = setInterval(async () => {
                    try {
                        const response = await fetch(`/summarize-progress/${currentSessionId}`);
                        const progress = await response.json();
                        setSummaryProgress((prev) => {
                            if (!progress || typeof progress !== 'object') {
                                return prev;
                            }
                            const monotonicProgress = Math.max(prev?.progress || 0, progress?.progress || 0);
                            return {
                                ...progress,
                                progress: monotonicProgress
                            };
                        });
                    } catch (error) {
                        console.error('Progress check failed:', error);
                    }
                }, 500); // Poll every 500ms
                
                return () => clearInterval(interval);
            }, [isLoadingSummary, currentSessionId]);
            
            // Task tracking state - stored in localStorage
            const [taskProgress, setTaskProgress] = useState(() => {
                const saved = localStorage.getItem('splunk_task_progress');
                return saved ? JSON.parse(saved) : {};
            });
            
            // Save task progress to localStorage whenever it changes
            useEffect(() => {
                localStorage.setItem('splunk_task_progress', JSON.stringify(taskProgress));
            }, [taskProgress]);

            useEffect(() => {
                try {
                    localStorage.setItem(THEME_PREFERENCE_KEY, themePreference);
                } catch (error) {
                    console.error('Failed to persist theme preference:', error);
                }
            }, [themePreference]);

            useEffect(() => {
                const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

                const updateResolvedTheme = () => {
                    const nextTheme = themePreference === 'system'
                        ? (mediaQuery.matches ? 'dark' : 'light')
                        : themePreference;
                    setResolvedTheme(nextTheme);
                };

                updateResolvedTheme();

                if (themePreference === 'system') {
                    const handleMediaChange = () => updateResolvedTheme();
                    if (mediaQuery.addEventListener) {
                        mediaQuery.addEventListener('change', handleMediaChange);
                    } else {
                        mediaQuery.addListener(handleMediaChange);
                    }

                    return () => {
                        if (mediaQuery.removeEventListener) {
                            mediaQuery.removeEventListener('change', handleMediaChange);
                        } else {
                            mediaQuery.removeListener(handleMediaChange);
                        }
                    };
                }
            }, [themePreference]);

            useEffect(() => {
                document.documentElement.setAttribute('data-theme', resolvedTheme);
            }, [resolvedTheme]);
            
            // Toggle step completion
            const toggleStepCompletion = (sessionId, taskIndex, stepNumber) => {
                setTaskProgress(prev => {
                    const key = `${sessionId}_task${taskIndex}`;
                    const current = prev[key] || { completedSteps: [], status: 'not-started' };
                    const completedSteps = new Set(current.completedSteps);
                    
                    if (completedSteps.has(stepNumber)) {
                        completedSteps.delete(stepNumber);
                    } else {
                        completedSteps.add(stepNumber);
                    }
                    
                    const totalSteps = summaryData?.admin_tasks?.[taskIndex]?.steps?.length || 0;
                    const status = completedSteps.size === 0 ? 'not-started' :
                                   completedSteps.size === totalSteps ? 'completed' : 'in-progress';
                    
                    return {
                        ...prev,
                        [key]: {
                            completedSteps: Array.from(completedSteps),
                            status,
                            lastUpdated: new Date().toISOString()
                        }
                    };
                });
            };
            
            // Get task progress
            const getTaskProgress = (sessionId, taskIndex) => {
                const key = `${sessionId}_task${taskIndex}`;
                return taskProgress[key] || { completedSteps: [], status: 'not-started' };
            };
            
            // Calculate completion percentage
            const getTaskCompletionPercentage = (sessionId, taskIndex, totalSteps) => {
                const progress = getTaskProgress(sessionId, taskIndex);
                if (totalSteps === 0) return 0;
                return Math.round((progress.completedSteps.length / totalSteps) * 100);
            };
            
            // Verification state
            const [verificationResults, setVerificationResults] = useState({});
            const [verifyingTask, setVerifyingTask] = useState(null);
            
            // Remediation state
            const [remediationData, setRemediationData] = useState({});
            const [loadingRemediation, setLoadingRemediation] = useState(null);
            const [verificationHistory, setVerificationHistory] = useState({});
            const [showHistory, setShowHistory] = useState(null);
            
            // Get remediation for failed/partial verification
            const getRemediation = async (sessionId, taskIndex, taskDetails, verificationResult) => {
                setLoadingRemediation(taskIndex);
                
                try {
                    const response = await fetch('/get-remediation', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            session_id: sessionId,
                            task_index: taskIndex,
                            task_details: taskDetails,
                            verification_result: verificationResult
                        })
                    });
                    
                    const result = await response.json();
                    
                    setRemediationData(prev => ({
                        ...prev,
                        [`${sessionId}_task${taskIndex}`]: result
                    }));
                    
                } catch (error) {
                    console.error('Failed to get remediation:', error);
                } finally {
                    setLoadingRemediation(null);
                }
            };
            
            // Load verification history
            const loadVerificationHistory = async (sessionId, taskIndex) => {
                try {
                    const response = await fetch(`/verification-history/${sessionId}/${taskIndex}`);
                    const result = await response.json();
                    
                    setVerificationHistory(prev => ({
                        ...prev,
                        [`${sessionId}_task${taskIndex}`]: result
                    }));
                    
                } catch (error) {
                    console.error('Failed to load verification history:', error);
                }
            };
            
            // Run verification for a task
            const runVerification = async (sessionId, taskIndex, task) => {
                setVerifyingTask(taskIndex);
                
                try {
                    const response = await fetch('/verify-task', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            session_id: sessionId,
                            task_index: taskIndex,
                            verification_spl: task.verification_spl,
                            expected_outcome: task.expected_outcome
                        })
                    });
                    
                    const result = await response.json();
                    
                    // Store verification result
                    setVerificationResults(prev => ({
                        ...prev,
                        [`${sessionId}_task${taskIndex}`]: result
                    }));
                    
                } catch (error) {
                    console.error('Verification failed:', error);
                    setVerificationResults(prev => ({
                        ...prev,
                        [`${sessionId}_task${taskIndex}`]: {
                            status: 'error',
                            message: `Failed to run verification: ${error.message}`,
                            results: null
                        }
                    }));
                } finally {
                    setVerifyingTask(null);
                }
            };
            
            // Get verification result for a task
            const getVerificationResult = (sessionId, taskIndex) => {
                return verificationResults[`${sessionId}_task${taskIndex}`];
            };
            
            // Resizable panel state
            const [discoveryLogHeight, setDiscoveryLogHeight] = useState(480); // 50% taller than original 320px
            const [reportViewerHeight, setReportViewerHeight] = useState(560); // 70vh ≈ 560px
            const [isResizingLog, setIsResizingLog] = useState(false);
            const [isResizingReport, setIsResizingReport] = useState(false);
            
            const wsRef = useRef(null);
            const messagesEndRef = useRef(null);
            const chatEndRef = useRef(null);
            const chatInputRef = useRef(null);
            
            const scrollToBottom = () => {
                messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
            };
            
            useEffect(scrollToBottom, [messages]);
            
            // Auto-focus chat input when chat opens
            useEffect(() => {
                if (isChatOpen && chatInputRef.current) {
                    setTimeout(() => chatInputRef.current.focus(), 100);
                }
            }, [isChatOpen]);
            
            useEffect(() => {
                connectWebSocket();
                loadReports();
                loadDiscoveryDashboard();
                loadV2Intelligence();
                loadV2Artifacts();
                loadDiscoveryCompare('latest', 'previous');
                loadRunbookPayload('latest', 'admin');
                loadConfig(); // Load config to get active LLM connection info
                
                return () => {
                    if (wsRef.current) {
                        wsRef.current.close();
                    }
                };
            }, []);

            useEffect(() => {
                if (discoveryDashboard && discoveryDashboard.has_data) {
                    loadRunbookPayload(compareSelection.current, workflowTab);
                }
            }, [workflowTab]);

            useEffect(() => {
                if (isIntelligenceTab) {
                    loadV2Intelligence();
                }
                if (isArtifactsTab) {
                    loadV2Artifacts();
                }
            }, [workspaceTab]);
            
            // Timer effect - updates elapsed time every second when discovery is running
            useEffect(() => {
                if (discoveryStatus === 'running' && discoveryStartTime) {
                    const interval = setInterval(() => {
                        const elapsed = Math.floor((Date.now() - discoveryStartTime) / 1000);
                        setElapsedTime(elapsed);
                    }, 1000);
                    
                    return () => clearInterval(interval);
                } else if (discoveryStatus !== 'running') {
                    setElapsedTime(0);
                }
            }, [discoveryStatus, discoveryStartTime]);
            
            const connectWebSocket = () => {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${window.location.host}/ws`;
                
                wsRef.current = new WebSocket(wsUrl);
                
                wsRef.current.onopen = () => {
                    setIsConnected(true);
                    addMessage('system', 'Connected to discovery engine');
                };
                
                wsRef.current.onmessage = (event) => {
                    const message = JSON.parse(event.data);
                    handleWebSocketMessage(message);
                };
                
                wsRef.current.onclose = () => {
                    setIsConnected(false);
                    setTimeout(connectWebSocket, 3000); // Reconnect after 3s
                };
            };
            
            const handleWebSocketMessage = (message) => {
                switch (message.type) {
                    case 'banner':
                        addMessage('banner', message.data);
                        break;
                    case 'phase':
                        addMessage('phase', message.data);
                        break;
                    case 'success':
                    case 'error':
                    case 'warning':
                    case 'info':
                        addMessage(message.type, message.data);
                        break;
                    case 'progress':
                        setProgress(message.data);
                        break;
                    case 'overview':
                        addMessage('overview', message.data);
                        break;
                    case 'classification':
                        addMessage('classification', message.data);
                        break;
                    case 'recommendations':
                        addMessage('recommendations', message.data);
                        break;
                    case 'use_cases':
                        addMessage('use_cases', message.data);
                        break;
                    case 'completion':
                        addMessage('completion', message.data);
                        setProgress({ percentage: 100, description: 'Discovery completed. Finalizing UI...' });
                        setDiscoveryStatus('completed');
                        setDiscoveryStartTime(null);
                        setElapsedTime(0);
                        loadReports();
                        loadDiscoveryDashboard();
                        loadV2Intelligence();
                        loadV2Artifacts();
                        loadDiscoveryCompare('latest', 'previous');
                        loadRunbookPayload('latest', workflowTab);
                        break;
                    case 'rate_limit':
                        addMessage('rate_limit', message.data);
                        break;
                }
            };
            
            const addMessage = (type, data) => {
                setMessages(prev => [...prev, {
                    id: Date.now() + Math.random(),
                    type,
                    data,
                    timestamp: new Date().toISOString()
                }]);
            };
            
            const startDiscovery = async () => {
                // Check if using local LLM by examining endpoint URL
                // Local = localhost, 127.0.0.1, or credential name hints
                const endpointUrl = config?.llm?.endpoint_url?.toLowerCase() || '';
                const credentialName = config?.active_credential_name?.toLowerCase() || '';
                
                const isLocalLLM = endpointUrl.includes('localhost') ||
                                   endpointUrl.includes('127.0.0.1') ||
                                   endpointUrl.includes(':8000') ||  // Common vLLM port
                                   endpointUrl.includes(':11434') || // Common Ollama port
                                   credentialName.includes('local') ||
                                   credentialName.includes('vllm') ||
                                   credentialName.includes('ollama');
                
                if (isLocalLLM) {
                    const confirmed = window.confirm(
                        '⚠️ Local LLM Detected\\n\\n' +
                        'Discovery with local LLMs can take 5-10 minutes or more depending on your hardware. ' +
                        'You can abort the operation at any time using the "Abort" button.\\n\\n' +
                        'For faster results, consider using OpenAI or Anthropic.\\n\\n' +
                        'Continue with discovery?'
                    );
                    
                    if (!confirmed) {
                        return;
                    }
                }
                
                setDiscoveryStatus('starting');
                setMessages([]);
                setProgress({ percentage: 0, description: 'Initializing...' });
                setDiscoveryStartTime(Date.now());
                setElapsedTime(0);
                
                try {
                    const response = await fetch('/start-discovery', { method: 'POST' });
                    const result = await response.json();
                    
                    if (result.error) {
                        addMessage('error', { message: result.error });
                        setDiscoveryStatus('error');
                        setDiscoveryStartTime(null);
                    } else {
                        setDiscoveryStatus('running');
                    }
                } catch (error) {
                    addMessage('error', { message: `Failed to start discovery: ${error.message}` });
                    setDiscoveryStatus('error');
                    setDiscoveryStartTime(null);
                }
            };
            
            const abortDiscovery = async () => {
                const confirmed = window.confirm('Are you sure you want to abort the discovery process?');
                
                if (!confirmed) {
                    return;
                }
                
                try {
                    const response = await fetch('/abort-discovery', { method: 'POST' });
                    const result = await response.json();
                    
                    if (result.error) {
                        addMessage('error', { message: result.error });
                    } else {
                        addMessage('warning', { message: '⚠️ Discovery aborted by user' });
                        setDiscoveryStatus('idle');
                        setDiscoveryStartTime(null);
                        setElapsedTime(0);
                    }
                } catch (error) {
                    addMessage('error', { message: `Failed to abort discovery: ${error.message}` });
                }
            };
            
            // Format elapsed time as MM:SS
            const formatElapsedTime = (seconds) => {
                const mins = Math.floor(seconds / 60);
                const secs = seconds % 60;
                return `${mins}:${secs.toString().padStart(2, '0')}`;
            };
            
            const loadReports = async () => {
                try {
                    const response = await fetch('/reports');
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    const result = await response.json();
                    console.log('Loaded reports:', result);
                    setReports(result.reports || []);
                    setSessionCatalog(result.sessions || []);
                } catch (error) {
                    console.error('Failed to load reports:', error);
                    // Don't crash the UI - just show empty reports
                    setReports([]);
                    setSessionCatalog([]);
                }
            };

            const loadDiscoveryDashboard = async () => {
                try {
                    const response = await fetch('/api/discovery/dashboard');
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    const result = await response.json();
                    setDiscoveryDashboard(result);
                } catch (error) {
                    console.error('Failed to load discovery dashboard:', error);
                    setDiscoveryDashboard(null);
                }
            };

            const loadV2Intelligence = async () => {
                try {
                    const response = await fetch('/api/v2/intelligence');
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    const result = await response.json();
                    setV2Intelligence(result);
                } catch (error) {
                    console.error('Failed to load V2 intelligence:', error);
                    setV2Intelligence({ has_data: false, message: error.message || 'Failed to load V2 intelligence.' });
                }
            };

            const loadV2Artifacts = async () => {
                try {
                    const response = await fetch('/api/v2/artifacts');
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    const result = await response.json();
                    setV2Artifacts(result);
                } catch (error) {
                    console.error('Failed to load V2 artifacts:', error);
                    setV2Artifacts({ has_data: false, artifacts: [], count: 0, message: error.message || 'Failed to load V2 artifacts.' });
                }
            };

            const refreshIntelligenceWorkspace = () => {
                loadDiscoveryDashboard();
                loadV2Intelligence();
            };

            const refreshArtifactsWorkspace = () => {
                loadReports();
                loadV2Artifacts();
            };

            const loadDiscoveryCompare = async (current = 'latest', baseline = 'previous') => {
                try {
                    const params = new URLSearchParams();
                    if (current) params.set('current', current);
                    if (baseline) params.set('baseline', baseline);
                    const response = await fetch(`/api/discovery/compare?${params.toString()}`);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    const result = await response.json();
                    setDiscoveryCompare(result);
                } catch (error) {
                    console.error('Failed to load discovery compare:', error);
                    setDiscoveryCompare({ has_data: false, message: error.message || 'Failed to load compare data.' });
                }
            };

            const loadRunbookPayload = async (timestamp = 'latest', persona = workflowTab) => {
                try {
                    const params = new URLSearchParams();
                    if (timestamp) params.set('timestamp', timestamp);
                    if (persona) params.set('persona', persona);
                    const response = await fetch(`/api/discovery/runbook?${params.toString()}`);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    const result = await response.json();
                    setRunbookPayload(result);
                } catch (error) {
                    console.error('Failed to load runbook payload:', error);
                    setRunbookPayload({ has_data: false, message: error.message || 'Failed to load runbook.' });
                }
            };

            const refreshCompareSelection = () => {
                loadDiscoveryCompare(compareSelection.current, compareSelection.baseline);
            };

            const refreshRunbook = () => {
                loadRunbookPayload(compareSelection.current, workflowTab);
            };
            
            const loadConnectionInfo = async () => {
                try {
                    const response = await fetch('/connection-info');
                    const result = await response.json();
                    setConnectionInfo(result);
                } catch (error) {
                    console.error('Failed to load connection info:', error);
                }
            };
            
            // Settings functions
            const openSettings = async () => {
                await loadConfig();
                setIsSettingsOpen(true);
                // Load credentials and MCP configs after modal opens
                setTimeout(() => {
                    loadCredentials();
                    loadMCPConfigs();
                }, 100);
            };
            
            const closeSettings = () => {
                setIsSettingsOpen(false);
            };
            
            const loadConfig = async () => {
                try {
                    const response = await fetch('/api/config');
                    const data = await response.json();
                    setConfig(data);
                    // Initialize selected provider from config
                    setSelectedProvider(normalizeProvider(data.llm.provider || 'openai'));
                    // Set API key placeholder based on whether key exists
                    setApiKeyPlaceholder(data.llm.api_key === '***' ? '(Already Configured)' : 'Enter API key');
                    // Set MCP token placeholder based on whether token exists
                    setMCPTokenPlaceholder(data.mcp.token === '***' ? '(Already Configured)' : 'Enter token');
                    
                    // Auto-load active credential if one is set (but prevent infinite loop)
                    if (data.active_credential_name && !isLoadingCredential) {
                        await loadCredentialIntoSettings(data.active_credential_name);
                    }
                    
                    // Auto-load active MCP config if one is set (just show it's active, don't auto-open form)
                    if (data.active_mcp_config_name) {
                        setLoadedMCPConfigName(data.active_mcp_config_name);
                    }
                } catch (error) {
                    console.error('Failed to load config:', error);
                }
            };
            
            const loadCredentials = async () => {
                try {
                    const response = await fetch('/api/credentials');
                    const credentials = await response.json();
                    setSavedCredentials(credentials);
                    
                    const credList = document.getElementById('credentials-list');
                    if (!credList) return;
                    
                    if (Object.keys(credentials).length === 0) {
                        credList.innerHTML = `
                            <div class="text-center py-12 bg-white rounded-lg border-2 border-dashed border-gray-300">
                                <i class="fas fa-plug text-purple-300 text-5xl mb-4"></i>
                                <p class="text-base font-bold text-gray-700 mb-2">No Connections Yet</p>
                                <p class="text-sm text-gray-500 mb-4">Get started by creating your first AI model connection</p>
                                <p class="text-xs text-gray-400 italic">Click "Create New Connection" above</p>
                            </div>
                        `;
                        return;
                    }
                    
                    // Sort credentials to show active one first
                    const activeCredName = config?.active_credential_name;
                    const credArray = Object.values(credentials).sort((a, b) => {
                        if (a.name === activeCredName) return -1;
                        if (b.name === activeCredName) return 1;
                        return 0;
                    });
                    
                    credList.innerHTML = credArray.map(cred => {
                        const provider = normalizeProvider(cred.provider);
                        const providerIcon = provider === 'openai' ? 'fa-openai' :
                                           provider === 'azure' ? 'fa-cloud' :
                                           provider === 'anthropic' ? 'fa-robot' :
                                           provider === 'gemini' ? 'fa-gem' :
                                           provider === 'custom' ? 'fa-server' : 'fa-brain';
                        const providerColor = provider === 'openai' ? 'text-green-600' :
                                              provider === 'azure' ? 'text-blue-600' :
                                              provider === 'anthropic' ? 'text-orange-600' :
                                              provider === 'gemini' ? 'text-indigo-600' : 'text-purple-600';
                        const isActive = cred.name === activeCredName;
                        
                        return `
                            <div class="group bg-white rounded-lg p-4 border-2 ${isActive ? 'border-amber-500 shadow-lg' : 'border-gray-200 hover:border-purple-400'} hover:shadow-lg transition-all">
                                <div class="flex items-start justify-between gap-4">
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center gap-2 mb-2">
                                            <i class="fab ${providerIcon} ${providerColor} text-lg"></i>
                                            <h5 class="text-base font-bold text-gray-900 truncate">${cred.name}</h5>
                                            ${isActive ? '<span class="ml-2 px-2 py-0.5 bg-amber-500 text-gray-900 text-xs font-bold rounded-full uppercase">Active</span>' : ''}
                                        </div>
                                        <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-cog w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Provider:</span> ${cred.provider}</span>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-brain w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Model:</span> ${cred.model}</span>
                                            </div>
                                            ${cred.endpoint_url ? `
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-link w-4 text-gray-400"></i>
                                                <span class="truncate"><span class="font-semibold text-gray-700">Endpoint:</span> <code class="text-xs bg-gray-100 px-1 rounded">${cred.endpoint_url}</code></span>
                                            </div>` : ''}
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-sliders-h w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Settings:</span> ${cred.max_tokens} tokens, ${cred.temperature} temp</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex flex-col gap-2 shrink-0">
                                        <button
                                            onclick="loadCredentialIntoSettings('${cred.name.replace(/'/g, "\\'")}')"
                                            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                            title="Load this credential into the settings form above"
                                        >
                                            <i class="fas fa-download mr-2"></i>Load
                                        </button>
                                        <button
                                            onclick="deleteCredential('${cred.name.replace(/'/g, "\\'")}')"
                                            class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                            title="Permanently delete this saved credential"
                                        >
                                            <i class="fas fa-trash-alt mr-2"></i>Delete
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('');
                } catch (error) {
                    console.error('Failed to load credentials:', error);
                    const credList = document.getElementById('credentials-list');
                    if (credList) {
                        credList.innerHTML = `
                            <div class="text-center py-10">
                                <i class="fas fa-exclamation-triangle text-red-400 text-4xl mb-4"></i>
                                <p class="text-base font-semibold text-red-700">Failed to load credentials</p>
                                <p class="text-sm text-gray-600 mt-2">${error.message}</p>
                            </div>
                        `;
                    }
                }
            };
            
            window.loadCredentialIntoSettings = async (name) => {
                try {
                    // Set flag to prevent clearing during load
                    setIsLoadingCredential(true);
                    
                    // Show loading indicator only if credentials list is visible (settings panel open)
                    const credList = document.getElementById('credentials-list');
                    let originalHTML = '';
                    if (credList) {
                        originalHTML = credList.innerHTML;
                        credList.innerHTML = `
                            <div class="text-center py-10">
                                <i class="fas fa-spinner fa-spin text-purple-600 text-4xl mb-4"></i>
                                <p class="text-base font-semibold text-gray-700">Loading credential...</p>
                                <p class="text-sm text-gray-500 mt-2">${name}</p>
                            </div>
                        `;
                    }
                    
                    const response = await fetch(`/api/credentials/${name}/load`, { method: 'POST' });
                    const result = await response.json();
                    
                    if (response.ok) {
                        // Update form fields with smooth transition
                        const newConfig = result.config;
                        
                        // Update React state first to trigger re-render
                        setConfig(newConfig);
                        setSelectedProvider(normalizeProvider(newConfig.llm.provider));
                        setLoadedCredentialName(name); // Track which credential is loaded
                        setApiKeyPlaceholder('(Already Configured)'); // Update placeholder
                        setShowConfigForm(true); // Show the config form when loading a credential
                        setSelectedModel(newConfig.llm.model); // Set the selected model
                        setAvailableModels([]); // Clear fetched models when loading credential
                        
                        // Then update form fields
                        setTimeout(() => {
                            const normalizedProvider = normalizeProvider(newConfig.llm.provider);
                            document.getElementById('llm-provider').value = normalizedProvider;
                            const modelInput = document.getElementById('llm-model');
                            if (modelInput) {
                                modelInput.value = newConfig.llm.model;
                            }
                            document.getElementById('llm-max-tokens').value = newConfig.llm.max_tokens;
                            document.getElementById('llm-temperature').value = newConfig.llm.temperature;
                            
                            // Update API Key field - force placeholder update
                            const apiKeyInput = document.getElementById('llm-api-key');
                            if (apiKeyInput) {
                                apiKeyInput.value = '';
                            }
                            
                            // Update endpoint URL if custom provider
                            if (newConfig.llm.endpoint_url && document.getElementById('llm-endpoint-url')) {
                                document.getElementById('llm-endpoint-url').value = newConfig.llm.endpoint_url;
                            }
                            
                        }, 50);
                        
                        // Reload config and credentials list to update active status
                        await loadConfig();
                        await loadCredentials();
                        
                        // Clear loading flag after config is reloaded to prevent infinite loop
                        setIsLoadingCredential(false);
                        
                        // Show success message
                        const successDiv = document.createElement('div');
                        successDiv.className = 'fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce';
                        successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-check-circle text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Credential Loaded!</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(successDiv);
                        setTimeout(() => {
                            successDiv.style.animation = 'none';
                            successDiv.style.opacity = '0';
                            successDiv.style.transition = 'opacity 0.3s';
                            setTimeout(() => successDiv.remove(), 300);
                        }, 2500);
                    } else {
                        if (credList) {
                            credList.innerHTML = originalHTML;
                        }
                        setIsLoadingCredential(false);
                        alert(`Failed to load credential: ${result.detail}`);
                    }
                } catch (error) {
                    if (credList) {
                        credList.innerHTML = originalHTML;
                    }
                    setIsLoadingCredential(false);
                    alert(`Error loading credential: ${error.message}`);
                    await loadCredentials();
                }
            };
            
            window.deleteCredential = async (name) => {
                // Custom confirmation dialog
                const confirmed = confirm(`⚠️ Delete Credential\\n\\nAre you sure you want to delete '${name}'?\\n\\nThis action cannot be undone.`);
                if (!confirmed) return;
                
                try {
                    const response = await fetch(`/api/credentials/${name}`, { method: 'DELETE' });
                    if (response.ok) {
                        await loadCredentials();
                        
                        // Show success message
                        const successDiv = document.createElement('div');
                        successDiv.className = 'fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50';
                        successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-trash-alt text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Credential Deleted</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(successDiv);
                        setTimeout(() => {
                            successDiv.style.opacity = '0';
                            successDiv.style.transition = 'opacity 0.3s';
                            setTimeout(() => successDiv.remove(), 300);
                        }, 2500);
                    } else {
                        const error = await response.json();
                        alert(`Failed to delete: ${error.detail}`);
                    }
                } catch (error) {
                    alert(`Error: ${error.message}`);
                }
            };
            
            // MCP Configuration Vault Functions
            const loadMCPConfigs = async () => {
                try {
                    const response = await fetch('/api/mcp-configs');
                    const mcpConfigs = await response.json();
                    setSavedMCPConfigs(mcpConfigs);
                    
                    const mcpList = document.getElementById('mcp-configs-list');
                    if (!mcpList) return;
                    
                    if (Object.keys(mcpConfigs).length === 0) {
                        mcpList.innerHTML = `
                            <div class="text-center py-12 bg-white rounded-lg border-2 border-dashed border-gray-300">
                                <i class="fas fa-server text-green-300 text-5xl mb-4"></i>
                                <p class="text-base font-bold text-gray-700 mb-2">No Saved Configurations</p>
                                <p class="text-sm text-gray-500 mb-4">Save your current MCP server settings for quick access</p>
                                <p class="text-xs text-gray-400 italic">Click "Save Current Config" above</p>
                            </div>
                        `;
                        return;
                    }
                    
                    // Sort configs to show active one first
                    const activeMCPName = config?.active_mcp_config_name;
                    const mcpArray = Object.values(mcpConfigs).sort((a, b) => {
                        if (a.name === activeMCPName) return -1;
                        if (b.name === activeMCPName) return 1;
                        return a.name.localeCompare(b.name);
                    });
                    
                    mcpList.innerHTML = mcpArray.map(mcp => `
                        <div class="group bg-white rounded-lg p-4 border-2 ${mcp.name === activeMCPName ? 'border-green-400 shadow-lg' : 'border-gray-200'} hover:border-green-400 hover:shadow-lg transition-all">
                            <div class="flex items-start justify-between gap-4">
                                <div class="flex-1 min-w-0">
                                    <div class="flex items-center gap-2 mb-2">
                                        <i class="fas fa-server text-green-600 text-lg"></i>
                                        <h5 class="text-base font-bold text-gray-900 truncate">${mcp.name}</h5>
                                        ${mcp.name === activeMCPName ? '<span class="px-2 py-0.5 bg-green-100 text-green-700 text-xs font-bold rounded-full">ACTIVE</span>' : ''}
                                    </div>
                                    ${mcp.description ? `<p class="text-sm text-gray-600 mb-2 pl-1">${mcp.description}</p>` : ''}
                                    <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                                        <div class="flex items-center gap-2">
                                            <i class="fas fa-link w-4 text-gray-400"></i>
                                            <span><span class="font-semibold text-gray-700">URL:</span> ${mcp.url}</span>
                                        </div>
                                        <div class="flex items-center gap-2">
                                            <i class="fas fa-shield-alt w-4 text-gray-400"></i>
                                            <span><span class="font-semibold text-gray-700">SSL:</span> ${mcp.verify_ssl ? 'Enabled' : 'Disabled'}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex flex-col gap-2 shrink-0">
                                    <button 
                                        onclick="testMCPConfig('${mcp.name}')"
                                        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                        title="Test connection to this MCP server"
                                    >
                                        <i class="fas fa-network-wired mr-2"></i>Test
                                    </button>
                                    <button 
                                        onclick="loadMCPConfigIntoSettings('${mcp.name}')"
                                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                        title="Load this configuration into active settings"
                                    >
                                        <i class="fas fa-download mr-2"></i>Load
                                    </button>
                                    <button 
                                        onclick="deleteMCPConfig('${mcp.name}')"
                                        class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                        title="Permanently delete this saved configuration"
                                    >
                                        <i class="fas fa-trash-alt mr-2"></i>Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                } catch (error) {
                    console.error('Failed to load MCP configs:', error);
                    const mcpList = document.getElementById('mcp-configs-list');
                    if (mcpList) {
                        mcpList.innerHTML = `
                            <div class="text-center py-10">
                                <i class="fas fa-exclamation-triangle text-red-400 text-4xl mb-4"></i>
                                <p class="text-base font-semibold text-red-700">Failed to load MCP configurations</p>
                                <p class="text-sm text-gray-600 mt-2">${error.message}</p>
                            </div>
                        `;
                    }
                }
            };
            
            window.loadMCPConfigIntoSettings = async (name) => {
                try {
                    const mcpList = document.getElementById('mcp-configs-list');
                    const originalHTML = mcpList.innerHTML;
                    mcpList.innerHTML = `
                        <div class="text-center py-10">
                            <i class="fas fa-spinner fa-spin text-green-600 text-4xl mb-4"></i>
                            <p class="text-base font-semibold text-gray-700">Loading configuration...</p>
                            <p class="text-sm text-gray-500 mt-2">${name}</p>
                        </div>
                    `;
                    
                    const response = await fetch(`/api/mcp-configs/${name}/load`, { method: 'POST' });
                    if (response.ok) {
                        const result = await response.json();
                        const newConfig = result.config;
                        
                        // Update React state first
                        setConfig(newConfig);
                        setLoadedMCPConfigName(name);
                        setShowMCPConfigForm(true); // Show the form when loading a config
                        setMCPTokenPlaceholder('(Already Configured)'); // Set placeholder for loaded config
                        
                        // Update form fields with the loaded config
                        setTimeout(() => {
                            const mcpUrlInput = document.getElementById('mcp-url');
                            const mcpTokenInput = document.getElementById('mcp-token');
                            
                            if (mcpUrlInput) mcpUrlInput.value = newConfig.mcp.url;
                            if (mcpTokenInput) mcpTokenInput.value = ''; // Clear token field (masked in backend)
                            // verify_ssl checkbox is now controlled by React state
                        }, 50);
                        
                        await loadConfig();
                        await loadMCPConfigs();
                        
                        // Show success notification
                        const successDiv = document.createElement('div');
                        successDiv.className = 'fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce';
                        successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-check-circle text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Configuration Loaded!</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(successDiv);
                        setTimeout(() => {
                            successDiv.style.animation = 'none';
                            successDiv.style.opacity = '0';
                            successDiv.style.transition = 'opacity 0.3s';
                            setTimeout(() => successDiv.remove(), 300);
                        }, 2500);
                    } else {
                        mcpList.innerHTML = originalHTML;
                        const result = await response.json();
                        alert(`Failed to load configuration: ${result.detail}`);
                    }
                } catch (error) {
                    alert(`Error loading configuration: ${error.message}`);
                    await loadMCPConfigs();
                }
            };
            
            window.deleteMCPConfig = async (name) => {
                const confirmed = confirm(`⚠️ Delete MCP Configuration\\n\\nAre you sure you want to delete '${name}'?\\n\\nThis action cannot be undone.`);
                if (!confirmed) return;
                
                try {
                    const response = await fetch(`/api/mcp-configs/${name}`, { method: 'DELETE' });
                    if (response.ok) {
                        await loadMCPConfigs();
                        
                        // Show success message
                        const successDiv = document.createElement('div');
                        successDiv.className = 'fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50';
                        successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-trash-alt text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Configuration Deleted</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(successDiv);
                        setTimeout(() => {
                            successDiv.style.opacity = '0';
                            successDiv.style.transition = 'opacity 0.3s';
                            setTimeout(() => successDiv.remove(), 300);
                        }, 2500);
                    } else {
                        const error = await response.json();
                        alert(`Failed to delete: ${error.detail}`);
                    }
                } catch (error) {
                    alert(`Error: ${error.message}`);
                }
            };
            
            window.testMCPConfig = async (name) => {
                const mcpList = document.getElementById('mcp-configs-list');
                const originalHTML = mcpList.innerHTML;
                
                try {
                    // Show testing state
                    const testingDiv = document.createElement('div');
                    testingDiv.className = 'fixed top-6 right-6 bg-blue-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50';
                    testingDiv.innerHTML = `
                        <div class="flex items-center gap-3">
                            <i class="fas fa-spinner fa-spin text-2xl"></i>
                            <div>
                                <p class="font-bold text-base">Testing Connection...</p>
                                <p class="text-sm opacity-90">${name}</p>
                            </div>
                        </div>
                    `;
                    document.body.appendChild(testingDiv);
                    
                    const response = await fetch(`/api/mcp-configs/${name}/test`, { method: 'POST' });
                    const result = await response.json();
                    
                    // Remove testing notification
                    testingDiv.remove();
                    
                    // Show result notification
                    const resultDiv = document.createElement('div');
                    let bgColor = 'bg-green-600';
                    let icon = 'fa-check-circle';
                    
                    if (result.status === 'error') {
                        bgColor = 'bg-red-600';
                        icon = 'fa-times-circle';
                    } else if (result.status === 'warning') {
                        bgColor = 'bg-yellow-600';
                        icon = 'fa-exclamation-triangle';
                    }
                    
                    resultDiv.className = `fixed top-6 right-6 ${bgColor} text-white px-6 py-4 rounded-xl shadow-2xl z-50`;
                    resultDiv.innerHTML = `
                        <div class="flex items-center gap-3">
                            <i class="fas ${icon} text-2xl"></i>
                            <div>
                                <p class="font-bold text-base">${result.status === 'success' ? 'Connection Successful!' : result.status === 'warning' ? 'Connection Warning' : 'Connection Failed'}</p>
                                <p class="text-sm opacity-90">${result.message}</p>
                            </div>
                        </div>
                    `;
                    document.body.appendChild(resultDiv);
                    setTimeout(() => {
                        resultDiv.style.opacity = '0';
                        resultDiv.style.transition = 'opacity 0.3s';
                        setTimeout(() => resultDiv.remove(), 300);
                    }, 4000);
                    
                } catch (error) {
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50';
                    errorDiv.innerHTML = `
                        <div class="flex items-center gap-3">
                            <i class="fas fa-times-circle text-2xl"></i>
                            <div>
                                <p class="font-bold text-base">Test Failed</p>
                                <p class="text-sm opacity-90">${error.message}</p>
                            </div>
                        </div>
                    `;
                    document.body.appendChild(errorDiv);
                    setTimeout(() => {
                        errorDiv.style.opacity = '0';
                        errorDiv.style.transition = 'opacity 0.3s';
                        setTimeout(() => errorDiv.remove(), 300);
                    }, 4000);
                }
            };
            
            const saveSettings = async (settings) => {
                try {
                    const response = await fetch('/api/config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(settings)
                    });
                    
                    if (response.ok) {
                        alert('Settings saved successfully!');
                        closeSettings();
                        await loadConfig();
                    } else {
                        const error = await response.json();
                        alert(`Failed to save settings: ${error.detail || 'Unknown error'}`);
                    }
                } catch (error) {
                    alert(`Error: ${error.message}`);
                }
            };
            
            const openConnectionModal = (event) => {
                const target = event?.currentTarget;
                const modalWidth = 320;
                const viewportPadding = 12;

                if (target && typeof target.getBoundingClientRect === 'function') {
                    const rect = target.getBoundingClientRect();
                    const preferredLeft = rect.left + (rect.width / 2) - (modalWidth / 2);
                    const maxLeft = Math.max(viewportPadding, window.innerWidth - modalWidth - viewportPadding);
                    const clampedLeft = Math.min(Math.max(preferredLeft, viewportPadding), maxLeft);
                    const anchorCenterX = rect.left + (rect.width / 2);
                    const pointerOffset = anchorCenterX - clampedLeft - 8;
                    const pointerLeft = Math.min(Math.max(pointerOffset, 16), modalWidth - 24);

                    setConnectionModalPosition({
                        top: rect.bottom + 10,
                        left: clampedLeft,
                        pointerLeft
                    });
                }

                loadConnectionInfo();
                setIsConnectionModalOpen(true);
            };

            const isSummaryArtifact = (reportName) => {
                if (!reportName || typeof reportName !== 'string') return false;
                return reportName.startsWith('v2_ai_summary_') || reportName.startsWith('ai_summary_');
            };
            
            // Group reports hierarchically by Year > Month > Day > Session
            const groupReportsByHierarchy = (reports) => {
                const sessions = {};
                
                reports.forEach(report => {
                    // Extract timestamp from filename (e.g., "recommendations_20251026_181253.md")
                    const match = report.name.match(/_([0-9]{8}_[0-9]{6})\\./);
                    if (match) {
                        const timestamp = match[1];
                        if (!sessions[timestamp]) {
                            sessions[timestamp] = {
                                timestamp,
                                displayName: formatSessionName(timestamp),
                                reports: [],
                                hasSummary: false,
                                date: parseTimestamp(timestamp)
                            };
                        }
                        sessions[timestamp].reports.push(report);
                        
                        // Check if this is a summary artifact
                        if (isSummaryArtifact(report.name)) {
                            sessions[timestamp].hasSummary = true;
                        }
                    }
                });
                
                // Build hierarchy: Year > Month > Day > Sessions
                const hierarchy = {};
                const today = new Date();
                const currentYear = today.getFullYear();
                const currentMonth = today.getMonth();
                const currentDay = today.getDate();
                
                Object.values(sessions).forEach(session => {
                    const date = session.date;
                    const year = date.getFullYear();
                    const month = date.getMonth();
                    const day = date.getDate();
                    
                    // Determine if we need to show year
                    const showYear = year !== currentYear;
                    
                    // Determine if we need to show month (show if not current month or if showing year)
                    const showMonth = showYear || month !== currentMonth;
                    
                    // Create keys
                    const yearKey = `year_${year}`;
                    const monthKey = `${yearKey}_month_${month}`;
                    const dayKey = `${monthKey}_day_${day}`;
                    
                    // Initialize hierarchy levels
                    if (!hierarchy[yearKey]) {
                        hierarchy[yearKey] = {
                            type: 'year',
                            year: year,
                            display: year.toString(),
                            visible: showYear,
                            months: {}
                        };
                    }
                    
                    if (!hierarchy[yearKey].months[monthKey]) {
                        hierarchy[yearKey].months[monthKey] = {
                            type: 'month',
                            month: month,
                            display: date.toLocaleDateString('en-US', { month: 'long', year: 'numeric' }),
                            visible: showMonth,
                            days: {}
                        };
                    }
                    
                    if (!hierarchy[yearKey].months[monthKey].days[dayKey]) {
                        const isToday = year === currentYear && month === currentMonth && day === currentDay;
                        const dayName = isToday ? 'Today' : date.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
                        
                        hierarchy[yearKey].months[monthKey].days[dayKey] = {
                            type: 'day',
                            day: day,
                            display: dayName,
                            isToday: isToday,
                            sessions: []
                        };
                    }
                    
                    hierarchy[yearKey].months[monthKey].days[dayKey].sessions.push(session);
                });
                
                return hierarchy;
            };
            
            const parseTimestamp = (timestamp) => {
                // Convert "20251026_181253" to Date object
                const dateStr = timestamp.substring(0, 8);
                const timeStr = timestamp.substring(9);
                
                const year = parseInt(dateStr.substring(0, 4));
                const month = parseInt(dateStr.substring(4, 6)) - 1;
                const day = parseInt(dateStr.substring(6, 8));
                const hour = parseInt(timeStr.substring(0, 2));
                const minute = parseInt(timeStr.substring(2, 4));
                
                return new Date(year, month, day, hour, minute);
            };
            
            // Group reports by session timestamp (legacy - for backward compatibility)
            const groupReportsBySession = (reports) => {
                const sessions = {};
                
                reports.forEach(report => {
                    // Extract timestamp from filename (e.g., "recommendations_20251026_181253.md")
                    const match = report.name.match(/_([0-9]{8}_[0-9]{6})\\./);
                    if (match) {
                        const timestamp = match[1];
                        if (!sessions[timestamp]) {
                            sessions[timestamp] = {
                                timestamp,
                                displayName: formatSessionName(timestamp),
                                reports: [],
                                hasSummary: false
                            };
                        }
                        sessions[timestamp].reports.push(report);
                        
                        // Check if this is a summary artifact
                        if (isSummaryArtifact(report.name)) {
                            sessions[timestamp].hasSummary = true;
                        }
                    } else {
                        // Handle reports without timestamp
                        const sessionKey = 'other';
                        if (!sessions[sessionKey]) {
                            sessions[sessionKey] = {
                                timestamp: sessionKey,
                                displayName: 'Other Reports',
                                reports: [],
                                hasSummary: false
                            };
                        }
                        sessions[sessionKey].reports.push(report);
                    }
                });
                
                // Sort sessions by timestamp (newest first)
                const sortedSessions = Object.values(sessions).sort((a, b) => {
                    if (a.timestamp === 'other') return 1;
                    if (b.timestamp === 'other') return -1;
                    return b.timestamp.localeCompare(a.timestamp);
                });
                
                return sortedSessions;
            };
            
            const formatSessionName = (timestamp) => {
                // Convert "20251026_181253" to "Oct 26, 2025, 6:12 PM"
                const dateStr = timestamp.substring(0, 8);
                const timeStr = timestamp.substring(9);
                
                const year = dateStr.substring(0, 4);
                const month = dateStr.substring(4, 6);
                const day = dateStr.substring(6, 8);
                const hour = timeStr.substring(0, 2);
                const minute = timeStr.substring(2, 4);
                
                const date = new Date(year, month - 1, day, hour, minute);
                return date.toLocaleDateString('en-US', { 
                    month: 'short', 
                    day: 'numeric', 
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            };
            
            const formatSessionTime = (timestamp) => {
                // Convert "20251026_181253" to just "6:12 PM"
                const timeStr = timestamp.substring(9);
                const dateStr = timestamp.substring(0, 8);
                
                const year = dateStr.substring(0, 4);
                const month = dateStr.substring(4, 6);
                const day = dateStr.substring(6, 8);
                const hour = timeStr.substring(0, 2);
                const minute = timeStr.substring(2, 4);
                
                const date = new Date(year, month - 1, day, hour, minute);
                return date.toLocaleTimeString('en-US', { 
                    hour: '2-digit',
                    minute: '2-digit'
                });
            };
            
            const toggleSession = (timestamp) => {
                setExpandedSessions(prev => ({
                    ...prev,
                    [timestamp]: !prev[timestamp]
                }));
            };
            
            const toggleYear = (yearKey) => {
                setExpandedYears(prev => ({
                    ...prev,
                    [yearKey]: !prev[yearKey]
                }));
            };
            
            const toggleMonth = (monthKey) => {
                setExpandedMonths(prev => ({
                    ...prev,
                    [monthKey]: !prev[monthKey]
                }));
            };
            
            const toggleDay = (dayKey) => {
                setExpandedDays(prev => ({
                    ...prev,
                    [dayKey]: !prev[dayKey]
                }));
            };
            
            // Auto-scroll chat messages to bottom
            useEffect(() => {
                if (chatMessages.length > 0) {
                    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
                }
            }, [chatMessages]);
            
            // Load chat settings when settings modal opens
            useEffect(() => {
                if (isChatSettingsOpen && !chatSettings) {
                    loadChatSettings();
                }
            }, [isChatSettingsOpen]);
            
            const loadChatSettings = async () => {
                try {
                    const response = await fetch('/api/chat/settings');
                    const data = await response.json();
                    setChatSettings(data);
                } catch (error) {
                    console.error('Error loading chat settings:', error);
                }
            };
            
            const updateSetting = async (key, value) => {
                const updatedSettings = { ...chatSettings, [key]: value };
                setChatSettings(updatedSettings);
                
                // Save to backend immediately
                try {
                    await fetch('/api/chat/settings', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ [key]: value })
                    });
                } catch (error) {
                    console.error('Error updating setting:', error);
                }
            };
            
            const resetChatSettings = async () => {
                try {
                    const response = await fetch('/api/chat/settings/reset', {
                        method: 'POST'
                    });
                    const data = await response.json();
                    setChatSettings(data.settings);
                } catch (error) {
                    console.error('Error resetting settings:', error);
                }
            };
            
            const sendChatMessage = async (overrideMessage = null) => {
                if (isTyping) return;

                const resolvedOverride = typeof overrideMessage === 'string' ? overrideMessage : '';
                const userMessage = (resolvedOverride || chatInput || '').trim();
                if (!userMessage) return;
                setChatInput('');
                setIsTyping(true);
                
                // Add user message
                setChatMessages(prev => [...prev, {
                    id: Date.now(),
                    type: 'user',
                    content: userMessage,
                    timestamp: new Date().toISOString()
                }]);
                
                try {
                    // Use streaming endpoint for real-time status updates
                    // If we have server conversation history (includes reasoning), use that instead of UI messages
                    const historyToSend = serverConversationHistory || 
                                         chatMessages.slice(-10).map(msg => ({
                                             type: msg.type,
                                             content: msg.content
                                         }));
                    
                    const response = await fetch('/chat/stream', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            message: userMessage,
                            history: historyToSend,
                            chat_session_id: chatSessionId
                        })
                    });
                    
                    // Handle Server-Sent Events
                    const reader = response.body.getReader();
                    const decoder = new TextDecoder();
                    let buffer = '';
                    
                    while (true) {
                        const {done, value} = await reader.read();
                        if (done) break;
                        
                        buffer += decoder.decode(value, {stream: true});
                        const lines = buffer.split('\\n');
                        buffer = lines.pop(); // Keep incomplete line in buffer
                        
                        for (const line of lines) {
                            if (line.startsWith('data: ')) {
                                const data = JSON.parse(line.slice(6));
                                
                                if (data.type === 'status') {
                                    // Update live status
                                    setChatStatus(data.action);
                                } else if (data.type === 'response') {
                                    // Final response received
                                    const result = data.data;
                                    setChatStatus(''); // Clear status
                                    
                                    if (result.error) {
                                        setChatMessages(prev => [...prev, {
                                            id: Date.now() + 1,
                                            type: 'error',
                                            content: result.error,
                                            timestamp: new Date().toISOString()
                                        }]);
                                    } else {
                                        // Add discovery age warning if present
                                        const messages = [];
                                        
                                        if (result.discovery_age_warning) {
                                            messages.push({
                                                id: Date.now() + 0.5,
                                                type: 'warning',
                                                content: result.discovery_age_warning,
                                                timestamp: new Date().toISOString()
                                            });
                                        }
                                        
                                        messages.push({
                                            id: Date.now() + 1,
                                            type: 'assistant',
                                            content: result.response,
                                            timestamp: new Date().toISOString(),
                                            mcp_data: result.mcp_data,
                                            tool_used: result.tool_used,
                                            spl_query: result.spl_query,
                                            spl_in_text: result.spl_in_text,
                                            has_follow_on: result.has_follow_on,
                                            follow_on_actions: result.follow_on_actions,
                                            status_timeline: result.status_timeline,
                                            iterations: result.iterations,
                                            execution_time: result.execution_time
                                        });
                                        
                                        // Store server's conversation history for follow-up queries
                                        if (result.conversation_history) {
                                            setServerConversationHistory(result.conversation_history);
                                        }
                                        if (result.chat_session_id) {
                                            setChatSessionId(result.chat_session_id);
                                        }
                                        
                                        setChatMessages(prev => [...prev, ...messages]);
                                    }
                                } else if (data.type === 'error') {
                                    // Error received
                                    setChatStatus('');
                                    setChatMessages(prev => [...prev, {
                                        id: Date.now() + 1,
                                        type: 'error',
                                        content: data.error,
                                        timestamp: new Date().toISOString()
                                    }]);
                                }
                            }
                        }
                    }
                    
                } catch (error) {
                    console.error('Chat error:', error);
                    setChatStatus('');
                    setChatMessages(prev => [...prev, {
                        id: Date.now() + 1,
                        type: 'error',
                        content: `Failed to send message: ${error.message}`,
                        timestamp: new Date().toISOString()
                    }]);
                } finally {
                    setIsTyping(false);
                    setChatStatus('');
                    // Re-focus input after sending
                    setTimeout(() => chatInputRef.current?.focus(), 100);
                }
            };

            const useSuggestedQuery = (query) => {
                setChatInput(query);
                if (chatInputRef.current) {
                    setTimeout(() => chatInputRef.current.focus(), 0);
                }
            };

            const sendSuggestedQuery = async (query) => {
                await sendChatMessage(query);
            };
            
            const loadReport = async (filename) => {
                try {
                    const response = await fetch(`/reports/${filename}`);
                    const result = await response.json();
                    
                    if (result.error) {
                        addMessage('error', { message: result.error });
                        return;
                    }
                    
                    // Force re-render by clearing first, then setting
                    setSelectedReport(null);
                    setReportContent(null);
                    
                    // Use setTimeout to ensure state updates are processed
                    setTimeout(() => {
                        setSelectedReport(filename);
                        setReportContent(result);
                    }, 10);
                } catch (error) {
                    console.error('Error loading report:', error);
                    addMessage('error', { message: `Failed to load report: ${error.message}` });
                }
            };
            
            // Summary modal functions
            const openSummaryModal = async (sessionId) => {
                // Check if using local LLM by examining endpoint URL
                // Local = localhost, 127.0.0.1, or credential name hints
                const endpointUrl = config?.llm?.endpoint_url?.toLowerCase() || '';
                const credentialName = config?.active_credential_name?.toLowerCase() || '';
                
                const isLocalLLM = endpointUrl.includes('localhost') ||
                                   endpointUrl.includes('127.0.0.1') ||
                                   endpointUrl.includes(':8000') ||  // Common vLLM port
                                   endpointUrl.includes(':11434') || // Common Ollama port
                                   credentialName.includes('local') ||
                                   credentialName.includes('vllm') ||
                                   credentialName.includes('ollama');
                
                if (isLocalLLM) {
                    const confirmed = window.confirm(
                        '⚠️ Local LLM Detected\\n\\n' +
                        'AI-powered summarization with local LLMs can take 3-5 minutes or more. ' +
                        'Progress updates will show estimated times for each stage.\\n\\n' +
                        'For faster results, consider using OpenAI or Anthropic.\\n\\n' +
                        'Continue with summarization?'
                    );
                    
                    if (!confirmed) {
                        return;
                    }
                }
                
                setCurrentSessionId(sessionId);
                setIsSummaryModalOpen(true);
                setIsLoadingSummary(true);
                setSummaryData(null);
                
                try {
                    const response = await fetch('/summarize-session', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ timestamp: sessionId })
                    });

                    let result = null;
                    const contentType = response.headers.get('content-type') || '';

                    if (contentType.includes('application/json')) {
                        result = await response.json();
                    } else {
                        const rawText = await response.text();
                        try {
                            result = JSON.parse(rawText);
                        } catch {
                            throw new Error(`Summarization failed (${response.status}): ${rawText.slice(0, 200) || 'Non-JSON server response'}`);
                        }
                    }

                    if (!response.ok) {
                        throw new Error(result?.error || result?.detail || `Summarization failed (${response.status})`);
                    }

                    if (result?.error) {
                        addMessage('error', { message: result.error });
                        setIsSummaryModalOpen(false);
                        return;
                    }
                    
                    setSummaryData(result);
                } catch (error) {
                    console.error('Error loading summary:', error);
                    addMessage('error', { message: `Failed to generate summary: ${error.message}` });
                    setIsSummaryModalOpen(false);
                } finally {
                    setIsLoadingSummary(false);
                }
            };
            
            const closeSummaryModal = () => {
                setIsSummaryModalOpen(false);
                setSummaryData(null);
                setCurrentSessionId(null);
            };
            
            const copyToClipboard = (text) => {
                navigator.clipboard.writeText(text).then(() => {
                    addMessage('success', { message: 'Copied to clipboard!' });
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    addMessage('error', { message: 'Failed to copy to clipboard' });
                });
            };
            
            const exportReport = (filename, content) => {
                const blob = new Blob([content], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            };
            
            // Resize handlers for panels
            const handleLogMouseDown = (e) => {
                setIsResizingLog(true);
                e.preventDefault();
            };
            
            const handleReportMouseDown = (e) => {
                setIsResizingReport(true);
                e.preventDefault();
            };
            
            useEffect(() => {
                const handleMouseMove = (e) => {
                    if (isResizingLog) {
                        const newHeight = Math.max(200, Math.min(800, e.clientY - 300)); // Min 200px, max 800px
                        setDiscoveryLogHeight(newHeight);
                    }
                    if (isResizingReport) {
                        const newHeight = Math.max(300, Math.min(1000, e.clientY - 400)); // Min 300px, max 1000px
                        setReportViewerHeight(newHeight);
                    }
                };
                
                const handleMouseUp = () => {
                    setIsResizingLog(false);
                    setIsResizingReport(false);
                };
                
                if (isResizingLog || isResizingReport) {
                    document.addEventListener('mousemove', handleMouseMove);
                    document.addEventListener('mouseup', handleMouseUp);
                    document.body.style.cursor = 'ns-resize';
                    document.body.style.userSelect = 'none';
                }
                
                return () => {
                    document.removeEventListener('mousemove', handleMouseMove);
                    document.removeEventListener('mouseup', handleMouseUp);
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                };
            }, [isResizingLog, isResizingReport]);
            
            const renderMessage = (message) => {
                const { type, data } = message;
                
                switch (type) {
                    case 'banner':
                        return (
                            <div className="bg-gradient-to-r from-purple-600 to-blue-600 text-white p-6 rounded-lg fade-in">
                                <h1 className="text-2xl font-bold">{data.title}</h1>
                                <p className="text-purple-100">{data.subtitle}</p>
                                <p className="text-sm text-purple-200 mt-2">Started: {data.start_time}</p>
                            </div>
                        );
                    
                    case 'phase':
                        return (
                            <div className={`border-l-4 p-4 slide-in ${isDarkTheme ? 'bg-indigo-950 border-indigo-500' : 'bg-indigo-50 border-indigo-500'}`}>
                                <h2 className={`text-lg font-semibold ${isDarkTheme ? 'text-indigo-200' : 'text-indigo-900'}`}>{data.title}</h2>
                            </div>
                        );
                    
                    case 'success':
                        return (
                            <div className={`flex items-center p-2 rounded fade-in ${isDarkTheme ? 'text-emerald-300 bg-emerald-950' : 'text-green-700 bg-green-50'}`}>
                                <i className="fas fa-check-circle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'error':
                        return (
                            <div className={`flex items-center p-3 rounded fade-in ${isDarkTheme ? 'text-red-200 bg-red-950' : 'text-red-700 bg-red-50'}`}>
                                <i className="fas fa-exclamation-circle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'warning':
                        return (
                            <div className={`flex items-center p-3 rounded fade-in ${isDarkTheme ? 'text-amber-200 bg-amber-950' : 'text-yellow-700 bg-yellow-50'}`}>
                                <i className="fas fa-exclamation-triangle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'info':
                        return (
                            <div className={`flex items-center p-2 rounded fade-in ${isDarkTheme ? 'text-blue-300 bg-blue-950' : 'text-blue-700'}`}>
                                <i className="fas fa-info-circle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'overview':
                        return (
                            <div className={`p-4 rounded-lg fade-in border ${isDarkTheme ? 'bg-slate-800 border-slate-700' : 'bg-blue-50 border-blue-200'}`}>
                                <h3 className={`font-semibold mb-2 ${isDarkTheme ? 'text-blue-200' : 'text-blue-900'}`}>Environment Overview</h3>
                                <div className={`grid grid-cols-2 gap-2 text-sm ${isDarkTheme ? 'text-slate-200' : 'text-slate-800'}`}>
                                    <div className={isDarkTheme ? 'bg-slate-700 rounded px-2 py-1' : ''}>Indexes: {data.total_indexes}</div>
                                    <div className={isDarkTheme ? 'bg-slate-700 rounded px-2 py-1' : ''}>Source Types: {data.total_sourcetypes}</div>
                                    <div className={isDarkTheme ? 'bg-slate-700 rounded px-2 py-1' : ''}>Data Volume: {data.data_volume_24h}</div>
                                    <div className={isDarkTheme ? 'bg-slate-700 rounded px-2 py-1' : ''}>Active Sources: {data.active_sources}</div>
                                </div>
                            </div>
                        );
                    
                    case 'rate_limit':
                        if (data.event === 'rate_limit_start') {
                            return (
                                <div className={`border p-4 rounded-lg fade-in ${isDarkTheme ? 'bg-amber-950 border-amber-700' : 'bg-yellow-50 border-yellow-200'}`}>
                                    <div className={`flex items-center ${isDarkTheme ? 'text-amber-200' : 'text-yellow-700'}`}>
                                        <i className="fas fa-clock mr-2"></i>
                                        <span>Rate limit encountered - waiting {data.details.delay}s (attempt {data.details.retry_count}/{data.details.max_retries})</span>
                                    </div>
                                </div>
                            );
                        } else if (data.event === 'rate_limit_countdown') {
                            return (
                                <div className={`p-3 rounded border ${isDarkTheme ? 'bg-amber-950 border-amber-700' : 'bg-yellow-50 border-yellow-200'}`}>
                                    <div className={`flex items-center justify-between text-sm ${isDarkTheme ? 'text-amber-200' : 'text-yellow-700'}`}>
                                        <span>Waiting...</span>
                                        <span>{Math.ceil(data.details.remaining_seconds)}s remaining</span>
                                    </div>
                                    <div className={`w-full rounded-full h-2 mt-2 ${isDarkTheme ? 'bg-amber-900' : 'bg-yellow-200'}`}>
                                        <div 
                                            className={`h-2 rounded-full progress-bar ${isDarkTheme ? 'bg-amber-400' : 'bg-yellow-500'}`}
                                            style={{ width: `${data.details.percentage}%` }}
                                        ></div>
                                    </div>
                                </div>
                            );
                        } else if (data.event === 'rate_limit_complete') {
                            return (
                                <div className={`flex items-center p-2 rounded fade-in ${isDarkTheme ? 'text-emerald-300 bg-emerald-950' : 'text-green-700 bg-green-50'}`}>
                                    <i className="fas fa-check-circle mr-2"></i>
                                    <span>Rate limit wait complete - resuming</span>
                                </div>
                            );
                        }
                        break;
                    
                    case 'completion':
                        return (
                            <div className={`border p-4 rounded-lg fade-in ${isDarkTheme ? 'bg-emerald-950 border-emerald-700' : 'bg-green-50 border-green-200'}`}>
                                <div className={`flex items-center mb-2 ${isDarkTheme ? 'text-emerald-200' : 'text-green-700'}`}>
                                    <i className="fas fa-trophy mr-2"></i>
                                    <span className="font-semibold">Discovery Complete!</span>
                                </div>
                                <p className={`text-sm ${isDarkTheme ? 'text-emerald-300' : 'text-green-600'}`}>Duration: {data.duration || 'N/A'}</p>
                                <p className={`text-sm ${isDarkTheme ? 'text-emerald-300' : 'text-green-600'}`}>Generated {data.report_count || 0} reports</p>
                            </div>
                        );
                    
                    default:
                        return (
                            <div className={`fade-in ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                <pre className={`text-xs p-2 rounded ${isDarkTheme ? 'bg-gray-800 border border-gray-700' : 'bg-gray-50 border border-gray-200'}`}>{JSON.stringify(data, null, 2)}</pre>
                            </div>
                        );
                }
            };
            
            return (
                <div className={`min-h-screen ${isDarkTheme ? 'bg-gray-900 text-gray-100' : 'bg-gray-50 text-gray-900'}`}>
                    {/* Unified Static Top Bar */}
                    <header className={`${isDarkTheme ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} sticky top-0 z-50 shadow-sm border-b`}>
                        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                            <div className="flex flex-wrap lg:flex-nowrap justify-between items-center gap-3 py-2 sm:py-3">
                                <div className="flex items-center">
                                    <i className="fas fa-search text-xl sm:text-2xl text-indigo-600 mr-2 sm:mr-3"></i>
                                    <h1 className={`text-lg sm:text-xl font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>Splunk MCP Discovery Tool</h1>
                                </div>

                                <div className="flex-1 min-w-[320px] flex items-center justify-center">
                                    <div className={`w-full max-w-3xl rounded-lg px-2 py-1.5 ${isDarkTheme ? 'bg-indigo-950/70 border border-indigo-700' : 'bg-indigo-50 border border-indigo-200'}`}>
                                        <div className="flex flex-wrap items-center justify-center gap-2">
                                            <div className="inline-flex rounded-lg border border-indigo-300 overflow-hidden text-[11px] sm:text-xs bg-indigo-900">
                                                <button
                                                    onClick={() => setWorkspaceTab('mission')}
                                                    className={`px-3 sm:px-4 py-1.5 ${isMissionTab ? 'bg-white text-indigo-900 font-semibold' : 'bg-transparent text-indigo-200 hover:bg-indigo-700'}`}
                                                    title="Mission tab: pipeline execution, progress, and live log"
                                                >
                                                    Mission
                                                </button>
                                                <button
                                                    onClick={() => {
                                                        setWorkspaceTab('intelligence');
                                                        refreshIntelligenceWorkspace();
                                                    }}
                                                    className={`px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isIntelligenceTab ? 'bg-white text-indigo-900 font-semibold' : 'bg-transparent text-indigo-200 hover:bg-indigo-700'}`}
                                                    title="Intelligence tab: KPI trends, compare, and persona workflows"
                                                >
                                                    Intelligence
                                                </button>
                                                <button
                                                    onClick={() => {
                                                        setWorkspaceTab('artifacts');
                                                        refreshArtifactsWorkspace();
                                                    }}
                                                    className={`px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isArtifactsTab ? 'bg-white text-indigo-900 font-semibold' : 'bg-transparent text-indigo-200 hover:bg-indigo-700'}`}
                                                    title="Artifacts tab: reports, exports, and summaries"
                                                >
                                                    Artifacts
                                                </button>
                                            </div>

                                            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 text-[11px] sm:text-xs">
                                                {isMissionTab && (
                                                    <button
                                                        onClick={discoveryStatus === 'running' ? abortDiscovery : startDiscovery}
                                                        className={`px-2.5 sm:px-3 py-1.5 rounded ${discoveryStatus === 'running' ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-indigo-600 hover:bg-indigo-700 text-white'}`}
                                                        title={discoveryStatus === 'running' ? 'Abort active discovery pipeline' : 'Run full V2 discovery pipeline'}
                                                    >
                                                        {discoveryStatus === 'running' ? (
                                                            <><i className="fas fa-stop mr-1"></i>Abort Discovery</>
                                                        ) : (
                                                            <><i className="fas fa-rocket mr-1"></i>Run V2 Discovery</>
                                                        )}
                                                    </button>
                                                )}
                                                {isIntelligenceTab && (
                                                    <button
                                                        onClick={refreshIntelligenceWorkspace}
                                                        className="px-2.5 sm:px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white"
                                                        title="Refresh intelligence KPIs and trends"
                                                    >
                                                        <i className="fas fa-brain mr-1"></i>Refresh Intelligence
                                                    </button>
                                                )}
                                                {isArtifactsTab && (
                                                    <button
                                                        onClick={refreshArtifactsWorkspace}
                                                        className="px-2.5 sm:px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-700 text-white"
                                                        title="Reload exported artifacts and reports"
                                                    >
                                                        <i className="fas fa-folder-open mr-1"></i>Reload Artifacts
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => setIsChatOpen(true)}
                                                    className="px-2.5 sm:px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 text-white"
                                                    title="Open chat workspace with deterministic query support"
                                                >
                                                    <i className="fas fa-comments mr-1"></i>Open Chat
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="flex items-center flex-wrap justify-end gap-2 sm:gap-3">
                                    <div 
                                        className={`flex items-center cursor-pointer px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg transition-colors ${isDarkTheme ? 'hover:bg-gray-700' : 'hover:bg-gray-100'}`}
                                        onClick={openConnectionModal}
                                        title="View MCP connection details"
                                    >
                                        <div className={`w-3 h-3 rounded-full mr-2 ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
                                        <span className={`text-xs sm:text-sm ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                            {isConnected ? 'MCP Connected' : 'MCP Disconnected'}
                                        </span>
                                    </div>
                                    <div 
                                        className={`flex items-center px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg border ${isDarkTheme ? 'bg-gray-800 border-purple-500' : 'bg-white border-purple-200'}`}
                                        title="Active LLM connection"
                                    >
                                        <i className="fas fa-brain text-purple-600 mr-2"></i>
                                        <div className="flex flex-col">
                                            <span className={`text-xs leading-tight ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>LLM:</span>
                                            <span className={`text-xs sm:text-sm font-medium leading-tight ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                {config?.active_credential_name || config?.llm?.model || 'Not configured'}
                                            </span>
                                        </div>
                                    </div>
                                    <button
                                        onClick={openSettings}
                                        className={`px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg border font-medium ${isDarkTheme ? 'bg-gray-700 hover:bg-gray-600 text-gray-100 border-gray-600' : 'bg-gray-100 hover:bg-gray-200 text-gray-700 border-gray-300'}`}
                                        title="Open settings"
                                        aria-label="Open settings"
                                    >
                                        <i className="fas fa-cog"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </header>
                    
                    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">

                        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                            {/* Main Content Area */}
                            <div className="lg:col-span-3">
                                {/* Discovery Intelligence Hub */}
                                {isMissionTab && (
                                <div className={`rounded-lg shadow-sm p-6 mb-6 border ${panelClass}`}>
                                    <div className="flex items-center justify-between mb-4">
                                        <div>
                                            <h2 className={`text-lg font-semibold ${headingClass}`}>Discovery Intelligence Hub</h2>
                                            <p className={`text-sm ${subtextClass}`}>Actionable view for admins, analysts, and executives</p>
                                        </div>
                                        <button
                                            onClick={loadDiscoveryDashboard}
                                            className="text-indigo-600 hover:text-indigo-800"
                                            title="Refresh intelligence view"
                                        >
                                            <i className="fas fa-sync"></i>
                                        </button>
                                    </div>

                                    {!discoveryDashboard || !discoveryDashboard.has_data ? (
                                        <div className={`text-sm rounded p-4 border ${panelMutedClass} ${mutedTextClass}`}>
                                            No discovery intelligence available yet. Run discovery to generate KPI trends and persona playbooks.
                                        </div>
                                    ) : (
                                        <>
                                            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mb-4">
                                                <div className="bg-indigo-50 rounded p-3">
                                                    <div className="text-xs text-indigo-700">Readiness</div>
                                                    <div className="text-xl font-bold text-indigo-900">{discoveryDashboard.kpis?.readiness_score || 0}/100</div>
                                                    <div className="text-xs text-indigo-600">Δ {discoveryDashboard.trends?.readiness_delta ?? 0}</div>
                                                </div>
                                                <div className="bg-blue-50 rounded p-3">
                                                    <div className="text-xs text-blue-700">Indexes</div>
                                                    <div className="text-xl font-bold text-blue-900">{discoveryDashboard.kpis?.total_indexes || 0}</div>
                                                    <div className="text-xs text-blue-600">Δ {discoveryDashboard.trends?.indexes_delta ?? 0}</div>
                                                </div>
                                                <div className="bg-green-50 rounded p-3">
                                                    <div className="text-xs text-green-700">Sourcetypes</div>
                                                    <div className="text-xl font-bold text-green-900">{discoveryDashboard.kpis?.total_sourcetypes || 0}</div>
                                                    <div className="text-xs text-green-600">Δ {discoveryDashboard.trends?.sourcetypes_delta ?? 0}</div>
                                                </div>
                                                <div className="bg-amber-50 rounded p-3">
                                                    <div className="text-xs text-amber-700">Recommendations</div>
                                                    <div className="text-xl font-bold text-amber-900">{discoveryDashboard.kpis?.recommendation_count || 0}</div>
                                                    <div className="text-xs text-amber-600">Δ {discoveryDashboard.trends?.recommendations_delta ?? 0}</div>
                                                </div>
                                                <div className="bg-purple-50 rounded p-3">
                                                    <div className="text-xs text-purple-700">MCP Tools</div>
                                                    <div className="text-xl font-bold text-purple-900">{discoveryDashboard.kpis?.tool_count || 0}</div>
                                                    <div className="text-xs text-purple-600">Coverage snapshot</div>
                                                </div>
                                            </div>

                                            <div className={`border rounded p-3 mb-4 ${isDarkTheme ? 'border-gray-600' : 'border-gray-200'}`}>
                                                <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-3">
                                                    <div>
                                                        <h3 className={`text-sm font-semibold ${headingClass}`}>Session Compare</h3>
                                                        <p className={`text-xs ${mutedTextClass}`}>Track changes between two discovery runs</p>
                                                    </div>
                                                    <div className="flex flex-wrap items-center gap-2 text-xs">
                                                        <select
                                                            value={compareSelection.current}
                                                            onChange={(e) => setCompareSelection(prev => ({ ...prev, current: e.target.value }))}
                                                            className={`border rounded px-2 py-1 ${isDarkTheme ? 'border-gray-600 bg-gray-700 text-gray-100' : 'border-gray-300 bg-white text-gray-900'}`}
                                                        >
                                                            <option value="latest">Latest Session</option>
                                                            {sessionCatalog.map((session) => (
                                                                <option key={`current-${session.timestamp}`} value={session.timestamp}>
                                                                    {session.timestamp}
                                                                </option>
                                                            ))}
                                                        </select>
                                                        <span className={mutedTextClass}>vs</span>
                                                        <select
                                                            value={compareSelection.baseline}
                                                            onChange={(e) => setCompareSelection(prev => ({ ...prev, baseline: e.target.value }))}
                                                            className={`border rounded px-2 py-1 ${isDarkTheme ? 'border-gray-600 bg-gray-700 text-gray-100' : 'border-gray-300 bg-white text-gray-900'}`}
                                                        >
                                                            <option value="previous">Previous Session</option>
                                                            {sessionCatalog.map((session) => (
                                                                <option key={`baseline-${session.timestamp}`} value={session.timestamp}>
                                                                    {session.timestamp}
                                                                </option>
                                                            ))}
                                                        </select>
                                                        <button
                                                            onClick={refreshCompareSelection}
                                                            className="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white rounded"
                                                        >
                                                            Compare
                                                        </button>
                                                    </div>
                                                </div>

                                                {!discoveryCompare || !discoveryCompare.has_data ? (
                                                    <div className={`text-xs mt-3 ${mutedTextClass}`}>
                                                        {discoveryCompare?.message || 'Compare data will appear once at least two sessions exist.'}
                                                    </div>
                                                ) : (
                                                    <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mt-3 text-xs">
                                                        <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                            <div className={mutedTextClass}>Readiness Δ</div>
                                                            <div className={`font-semibold ${headingClass}`}>{discoveryCompare.metrics?.readiness?.delta ?? 0}</div>
                                                        </div>
                                                        <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                            <div className={mutedTextClass}>Indexes Δ</div>
                                                            <div className={`font-semibold ${headingClass}`}>{discoveryCompare.metrics?.indexes?.delta ?? 0}</div>
                                                        </div>
                                                        <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                            <div className={mutedTextClass}>Sourcetypes Δ</div>
                                                            <div className={`font-semibold ${headingClass}`}>{discoveryCompare.metrics?.sourcetypes?.delta ?? 0}</div>
                                                        </div>
                                                        <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                            <div className={mutedTextClass}>Recommendations Δ</div>
                                                            <div className={`font-semibold ${headingClass}`}>{discoveryCompare.metrics?.recommendations?.delta ?? 0}</div>
                                                        </div>
                                                        <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                            <div className={mutedTextClass}>Tools Δ</div>
                                                            <div className={`font-semibold ${headingClass}`}>{discoveryCompare.metrics?.tools?.delta ?? 0}</div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>

                                            <div className="border border-gray-200 rounded p-3">
                                                <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                                                    <div className="inline-flex rounded border border-gray-300 overflow-hidden text-xs">
                                                        <button
                                                            onClick={() => setWorkflowTab('admin')}
                                                            className={`px-3 py-1 ${workflowTab === 'admin' ? 'bg-indigo-600 text-white' : 'bg-white text-gray-700'}`}
                                                        >
                                                            Admin
                                                        </button>
                                                        <button
                                                            onClick={() => setWorkflowTab('analyst')}
                                                            className={`px-3 py-1 border-l border-gray-300 ${workflowTab === 'analyst' ? 'bg-indigo-600 text-white' : 'bg-white text-gray-700'}`}
                                                        >
                                                            Analyst
                                                        </button>
                                                        <button
                                                            onClick={() => setWorkflowTab('executive')}
                                                            className={`px-3 py-1 border-l border-gray-300 ${workflowTab === 'executive' ? 'bg-indigo-600 text-white' : 'bg-white text-gray-700'}`}
                                                        >
                                                            Executive
                                                        </button>
                                                    </div>

                                                    <div className="flex items-center gap-2 text-xs">
                                                        <button
                                                            onClick={refreshRunbook}
                                                            className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded"
                                                        >
                                                            Generate Runbook
                                                        </button>
                                                        <button
                                                            onClick={() => {
                                                                if (runbookPayload?.markdown && runbookPayload?.filename) {
                                                                    exportReport(runbookPayload.filename, runbookPayload.markdown);
                                                                }
                                                            }}
                                                            disabled={!runbookPayload?.markdown}
                                                            className={`px-3 py-1 rounded ${runbookPayload?.markdown ? 'bg-indigo-600 hover:bg-indigo-700 text-white' : 'bg-gray-200 text-gray-500 cursor-not-allowed'}`}
                                                        >
                                                            Export Runbook
                                                        </button>
                                                    </div>
                                                </div>

                                                {workflowTab === 'admin' && (
                                                    <ul className="text-xs text-gray-700 space-y-2">
                                                        {(discoveryDashboard.latest?.personas?.admin?.actions || []).slice(0, 6).map((action, idx) => (
                                                            <li key={idx} className="bg-gray-50 rounded px-3 py-2">
                                                                <div className="font-medium text-gray-900">{action.title}</div>
                                                                <div className="text-gray-500">Effort: {action.effort || 'unknown'}</div>
                                                                <div className="text-gray-600 mt-1">{action.next_step}</div>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                )}

                                                {workflowTab === 'analyst' && (
                                                    <ul className="text-xs text-gray-700 space-y-2">
                                                        {(discoveryDashboard.latest?.personas?.analyst?.hypotheses || []).slice(0, 6).map((track, idx) => (
                                                            <li key={idx} className="bg-gray-50 rounded px-3 py-2">
                                                                <div className="font-medium text-gray-900">{track.title}</div>
                                                                <div className="text-gray-600 mt-1">{track.question}</div>
                                                                <div className="text-gray-500 mt-1">Metric: {track.success_metric || 'N/A'}</div>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                )}

                                                {workflowTab === 'executive' && (
                                                    <div className={`text-xs ${subtextClass}`}>
                                                        <div className={`${isDarkTheme ? 'bg-gray-700 text-gray-100' : 'bg-gray-50 text-gray-700'} rounded px-3 py-2 mb-2`}>
                                                            {discoveryDashboard.latest?.personas?.executive?.headline || 'No executive brief available.'}
                                                        </div>
                                                        <ul className={`list-disc pl-4 space-y-1 ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>
                                                            {(discoveryDashboard.latest?.personas?.executive?.next_90_day_focus || []).slice(0, 6).map((item, idx) => (
                                                                <li key={idx}>{item}</li>
                                                            ))}
                                                        </ul>
                                                    </div>
                                                )}

                                                {runbookPayload && runbookPayload.has_data && (
                                                    <div className={`mt-3 text-xs ${mutedTextClass}`}>
                                                        Ready: {runbookPayload.title || 'Runbook'} ({runbookPayload.filename || 'runbook.md'})
                                                    </div>
                                                )}
                                            </div>
                                        </>
                                    )}
                                </div>
                                )}

                                {isIntelligenceTab && (
                                    <div className={`rounded-lg shadow-sm p-6 mb-6 border ${panelClass}`}>
                                        <div className="flex items-center justify-between mb-4">
                                            <div>
                                                <h2 className={`text-lg font-semibold ${headingClass}`}>V2 Intelligence Blueprint</h2>
                                                <p className={`text-sm ${subtextClass}`}>Coverage gaps, capability map, and evidence ledger from latest V2 run</p>
                                            </div>
                                            <button
                                                onClick={loadV2Intelligence}
                                                className="text-indigo-600 hover:text-indigo-800"
                                                title="Refresh V2 intelligence"
                                            >
                                                <i className="fas fa-sync"></i>
                                            </button>
                                        </div>

                                        {!v2Intelligence || !v2Intelligence.has_data ? (
                                            <div className={`text-sm rounded p-4 border ${panelMutedClass} ${mutedTextClass}`}>
                                                {v2Intelligence?.message || 'No V2 intelligence blueprint available yet. Run V2 discovery to generate the blueprint.'}
                                            </div>
                                        ) : (
                                            <>
                                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                                                    <div className={`${isDarkTheme ? 'bg-indigo-900 border border-indigo-700' : 'bg-indigo-50'} rounded p-3`}>
                                                        <div className={`${isDarkTheme ? 'text-indigo-200' : 'text-indigo-700'} text-xs`}>Indexes</div>
                                                        <div className={`${isDarkTheme ? 'text-indigo-100' : 'text-indigo-900'} text-xl font-bold`}>{v2Overview.total_indexes || 0}</div>
                                                    </div>
                                                    <div className={`${isDarkTheme ? 'bg-blue-900 border border-blue-700' : 'bg-blue-50'} rounded p-3`}>
                                                        <div className={`${isDarkTheme ? 'text-blue-200' : 'text-blue-700'} text-xs`}>Sourcetypes</div>
                                                        <div className={`${isDarkTheme ? 'text-blue-100' : 'text-blue-900'} text-xl font-bold`}>{v2Overview.total_sourcetypes || 0}</div>
                                                    </div>
                                                    <div className={`${isDarkTheme ? 'bg-green-900 border border-green-700' : 'bg-green-50'} rounded p-3`}>
                                                        <div className={`${isDarkTheme ? 'text-green-200' : 'text-green-700'} text-xs`}>Hosts</div>
                                                        <div className={`${isDarkTheme ? 'text-green-100' : 'text-green-900'} text-xl font-bold`}>{v2Overview.total_hosts || 0}</div>
                                                    </div>
                                                    <div className={`${isDarkTheme ? 'bg-purple-900 border border-purple-700' : 'bg-purple-50'} rounded p-3`}>
                                                        <div className={`${isDarkTheme ? 'text-purple-200' : 'text-purple-700'} text-xs`}>Splunk Version</div>
                                                        <div className={`${isDarkTheme ? 'text-purple-100' : 'text-purple-900'} text-sm font-semibold truncate`}>{v2Overview.splunk_version || 'unknown'}</div>
                                                    </div>
                                                </div>

                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                                    <div className={`border rounded p-3 ${isDarkTheme ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                                        <h3 className={`text-sm font-semibold mb-2 ${headingClass}`}>Coverage Gaps</h3>
                                                        {v2CoverageGaps.length === 0 ? (
                                                            <div className={`text-xs ${mutedTextClass}`}>No high-priority gaps were identified.</div>
                                                        ) : (
                                                            <ul className="space-y-2 text-xs">
                                                                {v2CoverageGaps.slice(0, 6).map((gap, idx) => (
                                                                    <li key={idx} className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                                        <div className={`font-medium ${headingClass}`}>{gap.gap || 'Coverage gap'}</div>
                                                                        <div className={`mt-1 ${subtextClass}`}>{gap.why_it_matters || 'No description provided.'}</div>
                                                                        <div className={`mt-1 uppercase ${mutedTextClass}`}>Priority: {gap.priority || 'medium'}</div>
                                                                    </li>
                                                                ))}
                                                            </ul>
                                                        )}
                                                    </div>

                                                    <div className={`border rounded p-3 ${isDarkTheme ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                                        <h3 className={`text-sm font-semibold mb-2 ${headingClass}`}>Capability Graph</h3>
                                                        <div className={`text-xs space-y-2 ${subtextClass}`}>
                                                            <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                                <div className={`font-medium mb-1 ${headingClass}`}>Data Surface</div>
                                                                <div>Indexes: {v2CapabilityGraph?.data_surface?.indexes || 0}</div>
                                                                <div>Sourcetypes: {v2CapabilityGraph?.data_surface?.sourcetypes || 0}</div>
                                                                <div>Sources: {v2CapabilityGraph?.data_surface?.sources || 0}</div>
                                                            </div>
                                                            <div className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                                <div className={`font-medium mb-1 ${headingClass}`}>Operations Surface</div>
                                                                <div>Users: {v2CapabilityGraph?.operations_surface?.users || 0}</div>
                                                                <div>Knowledge Objects: {v2CapabilityGraph?.operations_surface?.knowledge_objects || 0}</div>
                                                                <div>KV Collections: {v2CapabilityGraph?.operations_surface?.kv_collections || 0}</div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>

                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    <div className={`border rounded p-3 ${isDarkTheme ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                                        <h3 className={`text-sm font-semibold mb-2 ${headingClass}`}>Finding Ledger</h3>
                                                        {v2FindingLedger.length === 0 ? (
                                                            <div className={`text-xs ${mutedTextClass}`}>No ledger entries available.</div>
                                                        ) : (
                                                            <ul className="space-y-2 text-xs">
                                                                {v2FindingLedger.slice(0, 6).map((entry, idx) => (
                                                                    <li key={idx} className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                                        <div className={`font-medium ${headingClass}`}>Step {entry.step || 0}: {entry.title || 'Discovery step'}</div>
                                                                        <div className={`mt-1 ${subtextClass}`}>{(entry.findings || []).slice(0, 2).join(' | ') || 'No notable findings logged.'}</div>
                                                                    </li>
                                                                ))}
                                                            </ul>
                                                        )}
                                                    </div>

                                                    <div className={`border rounded p-3 ${isDarkTheme ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                                        <h3 className={`text-sm font-semibold mb-2 ${headingClass}`}>Suggested Use Cases</h3>
                                                        {v2UseCases.length === 0 ? (
                                                            <div className={`text-xs ${mutedTextClass}`}>No suggested use cases were generated.</div>
                                                        ) : (
                                                            <ul className="space-y-2 text-xs">
                                                                {v2UseCases.slice(0, 6).map((item, idx) => (
                                                                    <li key={idx} className={`${isDarkTheme ? 'bg-gray-700' : 'bg-gray-50'} rounded p-2`}>
                                                                        <div className={`font-medium ${headingClass}`}>{item.title || item.name || `Use Case ${idx + 1}`}</div>
                                                                        <div className={`mt-1 ${subtextClass}`}>{item.description || item.use_case || 'No description available.'}</div>
                                                                    </li>
                                                                ))}
                                                            </ul>
                                                        )}
                                                    </div>
                                                </div>
                                            </>
                                        )}
                                    </div>
                                )}

                                {/* Progress Bar */}
                                {isMissionTab && discoveryStatus === 'running' && (
                                    <div className={`rounded-lg shadow-sm p-6 mb-6 border ${panelClass}`}>
                                        <div className="flex items-center justify-between mb-2">
                                            <h2 className={`text-lg font-medium ${headingClass}`}>Discovery Progress</h2>
                                            <span className={`text-sm ${mutedTextClass}`}>{Math.round(progress.percentage)}%</span>
                                        </div>
                                        <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
                                            <div 
                                                className="bg-indigo-600 h-3 rounded-full progress-bar"
                                                style={{ width: `${progress.percentage}%` }}
                                            ></div>
                                        </div>
                                        <p className={`text-sm ${subtextClass}`}>{progress.description}</p>
                                    </div>
                                )}
                                
                                {/* Messages */}
                                {isMissionTab && (
                                <div className={`rounded-lg shadow-sm mb-6 border ${panelClass}`}>
                                    <div className={`p-6 border-b ${isDarkTheme ? 'border-gray-700' : 'border-gray-200'}`}>
                                        <h2 className={`text-lg font-medium ${headingClass}`}>Discovery Log</h2>
                                    </div>
                                    <div 
                                        className="p-6 overflow-y-auto scroll-container"
                                        style={{ height: `${discoveryLogHeight}px` }}
                                    >
                                        <div className="space-y-4">
                                            {messages.map((message) => (
                                                <div key={message.id}>
                                                    {renderMessage(message)}
                                                </div>
                                            ))}
                                            <div ref={messagesEndRef} />
                                        </div>
                                    </div>
                                    {/* Resize handle */}
                                    <div 
                                        className={`h-2 border-t cursor-ns-resize flex items-center justify-center group ${isDarkTheme ? 'bg-gray-700 border-gray-600 hover:bg-gray-600' : 'bg-gray-100 border-gray-200 hover:bg-gray-200'}`}
                                        onMouseDown={handleLogMouseDown}
                                    >
                                        <div className="w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500"></div>
                                    </div>
                                </div>
                                )}
                                
                                {/* Report Viewer */}
                                {(isMissionTab || isArtifactsTab) && selectedReport && reportContent && (
                                    <div className={`rounded-lg shadow-sm border ${panelClass}`}>
                                        <div className={`p-6 border-b ${isDarkTheme ? 'border-gray-700' : 'border-gray-200'}`}>
                                            <div className="flex justify-between items-center">
                                                <h3 className={`text-lg font-medium ${headingClass}`}>{selectedReport}</h3>
                                                <button
                                                    onClick={() => exportReport(selectedReport, 
                                                        reportContent.type === 'json' 
                                                            ? JSON.stringify(reportContent.content, null, 2)
                                                            : reportContent.content
                                                    )}
                                                    className="text-indigo-600 hover:text-indigo-800"
                                                >
                                                    <i className="fas fa-download mr-1"></i>
                                                    Export
                                                </button>
                                            </div>
                                        </div>
                                        <div 
                                            className="p-6 overflow-y-auto scroll-container"
                                            style={{ height: `${reportViewerHeight}px` }}
                                        >
                                            {reportContent.type === 'json' ? (
                                                <pre className={`text-sm whitespace-pre-wrap font-mono ${isDarkTheme ? 'text-gray-100' : 'text-gray-800'}`}>
                                                    {JSON.stringify(reportContent.content, null, 2)}
                                                </pre>
                                            ) : (
                                                <div className="prose prose-sm max-w-none">
                                                    <pre className={`text-sm whitespace-pre-wrap font-sans leading-relaxed break-words ${isDarkTheme ? 'text-gray-100' : 'text-gray-800'}`}>
                                                        {reportContent.content}
                                                    </pre>
                                                </div>
                                            )}
                                        </div>
                                        {/* Resize handle */}
                                        <div 
                                            className={`h-2 border-t cursor-ns-resize flex items-center justify-center group ${isDarkTheme ? 'bg-gray-700 border-gray-600 hover:bg-gray-600' : 'bg-gray-100 border-gray-200 hover:bg-gray-200'}`}
                                            onMouseDown={handleReportMouseDown}
                                        >
                                            <div className="w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500"></div>
                                        </div>
                                    </div>
                                )}
                            </div>
                            
                            {/* Reports Sidebar */}
                            {(isMissionTab || isArtifactsTab) && (
                            <div className="lg:col-span-1 min-w-0">
                                {/* Reports List */}
                                <div className={`rounded-lg shadow-sm border overflow-hidden min-w-0 ${panelClass}`}>
                                    <div className={`p-6 border-b ${isDarkTheme ? 'border-gray-700' : 'border-gray-200'}`}>
                                        <div className="flex justify-between items-center">
                                            <div>
                                                <h2 className={`text-lg font-medium ${headingClass}`}>{isArtifactsTab ? 'V2 Artifacts' : 'Generated Reports'}</h2>
                                                <p className={`text-xs mt-1 ${mutedTextClass}`}>
                                                    {isArtifactsTab ? `${v2Artifacts?.count || 0} artifact(s)` : `${sessionCatalog.length} discovery session(s)`}
                                                </p>
                                            </div>
                                            <button
                                                onClick={isArtifactsTab ? refreshArtifactsWorkspace : loadReports}
                                                className="text-indigo-600 hover:text-indigo-800"
                                            >
                                                <i className="fas fa-refresh"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div className={`divide-y overflow-x-hidden min-w-0 ${isDarkTheme ? 'divide-gray-700' : 'divide-gray-200'}`}>
                                        {isArtifactsTab ? (
                                            !v2Artifacts?.has_data || (v2Artifacts?.artifacts || []).length === 0 ? (
                                                <p className={`p-6 text-center ${mutedTextClass}`}>No V2 artifacts generated yet</p>
                                            ) : (
                                                <div>
                                                    {(v2Artifacts.artifacts || []).map((artifact) => (
                                                        <div
                                                            key={artifact.name}
                                                            className={`p-4 border-b ${isDarkTheme ? 'border-gray-700 hover:bg-gray-700' : 'border-gray-200 hover:bg-gray-50'} ${selectedReport === artifact.name ? (isDarkTheme ? 'bg-indigo-900 border-r-4 border-indigo-400' : 'bg-indigo-50 border-r-4 border-indigo-500') : ''}`}
                                                        >
                                                            <div className="flex items-start justify-between gap-2">
                                                                <button
                                                                    onClick={() => loadReport(artifact.name)}
                                                                    className="text-left flex-1"
                                                                    title={`Open ${artifact.name}`}
                                                                >
                                                                    <div className={`text-sm font-medium break-all ${headingClass}`}>{artifact.name}</div>
                                                                    <div className={`text-xs mt-1 ${mutedTextClass}`}>
                                                                        {(((artifact.size_bytes ?? artifact.size ?? 0) / 1024).toFixed(1))} KB • {new Date(artifact.modified_at || artifact.modified || Date.now()).toLocaleString()}
                                                                    </div>
                                                                </button>
                                                                <div className="flex items-center gap-2">
                                                                    <span className={`px-2 py-1 text-xs rounded ${artifact.type === 'json' ? (isDarkTheme ? 'bg-blue-900 text-blue-100' : 'bg-blue-100 text-blue-800') : (isDarkTheme ? 'bg-green-900 text-green-100' : 'bg-green-100 text-green-800')}`}>
                                                                        {(artifact.type || 'file').toUpperCase()}
                                                                    </span>
                                                                    <button
                                                                        onClick={() => copyToClipboard(artifact.path || artifact.name)}
                                                                        className={`text-xs px-2 py-1 rounded ${isDarkTheme ? 'bg-gray-700 hover:bg-gray-600 text-gray-100' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
                                                                        title="Copy file path"
                                                                    >
                                                                        <i className="fas fa-copy"></i>
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )
                                        ) : reports.length === 0 ? (
                                            <p className={`p-6 text-center ${mutedTextClass}`}>No reports generated yet</p>
                                        ) : (
                                            (() => {
                                                const hierarchy = groupReportsByHierarchy(reports);
                                                return Object.entries(hierarchy).sort((a, b) => b[1].year - a[1].year).map(([yearKey, yearData]) => (
                                                    <div key={yearKey}>
                                                        {/* Year Header - Only show if not current year */}
                                                        {yearData.visible && (
                                                            <div 
                                                                className={`p-3 border-b cursor-pointer font-semibold ${isDarkTheme ? 'bg-indigo-900 border-gray-700 hover:bg-indigo-800' : 'bg-gradient-to-r from-indigo-100 to-purple-100 border-gray-200'}`}
                                                                onClick={() => toggleYear(yearKey)}
                                                            >
                                                                <div className="flex items-center">
                                                                    <i className={`fas ${expandedYears[yearKey] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-2 text-xs ${isDarkTheme ? 'text-indigo-200' : 'text-indigo-600'}`}></i>
                                                                    <span className={`text-sm ${isDarkTheme ? 'text-indigo-100' : 'text-indigo-900'}`}>{yearData.display}</span>
                                                                </div>
                                                            </div>
                                                        )}
                                                        
                                                        {/* Month Level */}
                                                        {(!yearData.visible || expandedYears[yearKey]) && Object.entries(yearData.months).sort((a, b) => b[1].month - a[1].month).map(([monthKey, monthData]) => (
                                                            <div key={monthKey}>
                                                                {/* Month Header - Only show if not current month or if year is visible */}
                                                                {monthData.visible && (
                                                                    <div 
                                                                        className={`p-3 border-b cursor-pointer ${isDarkTheme ? 'bg-blue-900 border-gray-700 hover:bg-blue-800' : 'bg-gradient-to-r from-blue-50 to-indigo-50 border-gray-200'}`}
                                                                        onClick={() => toggleMonth(monthKey)}
                                                                        style={{paddingLeft: yearData.visible ? '1.5rem' : '0.75rem'}}
                                                                    >
                                                                        <div className="flex items-center">
                                                                            <i className={`fas ${expandedMonths[monthKey] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-2 text-xs ${isDarkTheme ? 'text-blue-200' : 'text-blue-600'}`}></i>
                                                                            <span className={`text-sm font-medium ${isDarkTheme ? 'text-blue-100' : 'text-blue-900'}`}>{monthData.display}</span>
                                                                        </div>
                                                                    </div>
                                                                )}
                                                                
                                                                {/* Day Level */}
                                                                {(!monthData.visible || expandedMonths[monthKey]) && Object.entries(monthData.days).sort((a, b) => b[1].day - a[1].day).map(([dayKey, dayData]) => (
                                                                    <div key={dayKey}>
                                                                        {/* Day Header */}
                                                                        <div 
                                                                            className={`p-3 border-b cursor-pointer ${dayData.isToday ? (isDarkTheme ? 'bg-green-900' : 'bg-green-50') : (isDarkTheme ? 'bg-gray-800' : 'bg-gray-50')} ${isDarkTheme ? 'hover:bg-gray-700 border-gray-700' : 'hover:bg-gray-100 border-gray-200'}`}
                                                                            onClick={() => toggleDay(dayKey)}
                                                                            style={{paddingLeft: monthData.visible ? (yearData.visible ? '3rem' : '1.5rem') : (yearData.visible ? '1.5rem' : '0.75rem')}}
                                                                        >
                                                                            <div className="flex items-center">
                                                                                <i className={`fas ${expandedDays[dayKey] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-2 text-xs ${dayData.isToday ? (isDarkTheme ? 'text-green-200' : 'text-green-600') : mutedTextClass}`}></i>
                                                                                <span className={`text-sm ${dayData.isToday ? (isDarkTheme ? 'text-green-100 font-semibold' : 'text-green-900 font-semibold') : (isDarkTheme ? 'text-gray-100 font-medium' : 'text-gray-900 font-medium')}`}>{dayData.display}</span>
                                                                                <span className={`ml-2 text-xs ${mutedTextClass}`}>({dayData.sessions.length})</span>
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        {/* Sessions under this day */}
                                                                        {expandedDays[dayKey] && dayData.sessions.map((session) => {
                                                                            const summaryArtifact = (session.reports || []).find((report) => isSummaryArtifact(report.name));
                                                                            return (
                                                                            <div key={session.timestamp}>
                                                                                {/* Session Header */}
                                                                                <div 
                                                                                    className={`p-4 border-b cursor-pointer transition-colors overflow-hidden ${isDarkTheme ? 'bg-gray-800 hover:bg-gray-700 border-gray-700' : 'bg-white hover:bg-gray-50 border-gray-200'}`}
                                                                                    onClick={() => toggleSession(session.timestamp)}
                                                                                    style={{paddingLeft: monthData.visible ? (yearData.visible ? '3rem' : '2rem') : (yearData.visible ? '2rem' : '1.25rem')}}
                                                                                >
                                                                                    <div className="flex flex-col gap-2">
                                                                                        <div className="flex items-start flex-1 min-w-0">
                                                                                            <i className={`fas ${expandedSessions[session.timestamp] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-3 text-xs mt-1 ${mutedTextClass}`}></i>
                                                                                            <div className="flex-1 min-w-0">
                                                                                                <h3 className={`text-sm font-semibold mb-1 tracking-wide ${headingClass}`}>{formatSessionTime(session.timestamp)}</h3>
                                                                                                <div className={`flex items-center gap-2 text-xs flex-wrap ${mutedTextClass}`}>
                                                                                                    <span className={`flex items-center px-2 py-0.5 rounded ${isDarkTheme ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600'}`}>
                                                                                                        <i className="fas fa-file-alt mr-1"></i>
                                                                                                        {session.reports.length} reports
                                                                                                    </span>
                                                                                                    {session.hasSummary && (
                                                                                                        <span className={`flex items-center px-2 py-0.5 rounded-full font-medium ${isDarkTheme ? 'bg-emerald-900 text-emerald-100 border border-emerald-700' : 'bg-emerald-100 text-emerald-800 border border-emerald-200'}`}>
                                                                                                            <i className="fas fa-check-circle mr-1"></i>
                                                                                                            Summarized
                                                                                                        </span>
                                                                                                    )}
                                                                                                    {summaryArtifact?.modified && (
                                                                                                        <span className={`hidden xl:flex items-center px-2 py-0.5 rounded ${isDarkTheme ? 'bg-gray-700 text-gray-400' : 'bg-gray-100 text-gray-500'}`}>
                                                                                                            <i className="fas fa-clock mr-1"></i>
                                                                                                            {new Date(summaryArtifact.modified).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                                                                                        </span>
                                                                                                    )}
                                                                                                </div>
                                                                                            </div>
                                                                                        </div>
                                                                                        <div className="flex items-center w-full">
                                                                                            <button
                                                                                                onClick={(e) => {
                                                                                                    e.stopPropagation();
                                                                                                    openSummaryModal(session.timestamp);
                                                                                                }}
                                                                                                className={`w-full text-xs px-3 py-1.5 rounded-md font-medium inline-flex justify-center items-center space-x-1 whitespace-nowrap shadow-sm transition-colors ${session.hasSummary ? 'bg-emerald-600 hover:bg-emerald-700 text-white' : 'bg-indigo-600 hover:bg-indigo-700 text-white'}`}
                                                                                                title={session.hasSummary ? 'View saved summary' : 'Generate summary with LLM'}
                                                                                            >
                                                                                                <i className={`fas ${session.hasSummary ? 'fa-eye' : 'fa-magic'}`}></i>
                                                                                                <span>{session.hasSummary ? 'View Summary' : 'Summarize'}</span>
                                                                                            </button>
                                                                                        </div>
                                                                                    </div>
                                                                                </div>
                                                                                
                                                                                {/* Session Reports */}
                                                                                {expandedSessions[session.timestamp] && (
                                                                                    <div className={`divide-y ${isDarkTheme ? 'divide-gray-700' : 'divide-gray-100'}`}>
                                                                                        {session.reports.map((report) => (
                                                                                            <div
                                                                                                key={report.name}
                                                                                                className={`p-4 cursor-pointer ${isDarkTheme ? 'hover:bg-gray-700' : 'hover:bg-gray-50'} ${
                                                                                                    selectedReport === report.name ? (isDarkTheme ? 'bg-indigo-900 border-r-4 border-indigo-400' : 'bg-indigo-50 border-r-4 border-indigo-500') : ''
                                                                                                }`}
                                                                                                onClick={() => loadReport(report.name)}
                                                                                                style={{paddingLeft: monthData.visible ? (yearData.visible ? '4rem' : '3rem') : (yearData.visible ? '3rem' : '2rem')}}
                                                                                            >
                                                                                                <div className="flex items-center justify-between gap-2 min-w-0">
                                                                                                    <div className="flex-1 min-w-0">
                                                                                                        <p className={`text-sm font-medium truncate ${headingClass}`} title={report.name}>
                                                                                                            {report.name.replace(/_[0-9]{8}_[0-9]{6}/, '')}
                                                                                                        </p>
                                                                                                        <p className={`text-xs ${mutedTextClass}`}>{(report.size / 1024).toFixed(1)} KB</p>
                                                                                                    </div>
                                                                                                    <div className="flex items-center space-x-2 shrink-0">
                                                                                                        <span className={`px-2 py-1 text-xs rounded ${
                                                                                                            report.type === 'json'
                                                                                                                ? (isDarkTheme ? 'bg-blue-900 text-blue-100' : 'bg-blue-100 text-blue-800')
                                                                                                                : (isDarkTheme ? 'bg-green-900 text-green-100' : 'bg-green-100 text-green-800')
                                                                                                        }`}>
                                                                                                            {report.type.toUpperCase()}
                                                                                                        </span>
                                                                                                    </div>
                                                                                                </div>
                                                                                            </div>
                                                                                        ))}
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        );})}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        ))}
                                                    </div>
                                                ));
                                            })()
                                        )}
                                    </div>
                                </div>
                            </div>
                            )}
                        </div>
                    </div>
                    
                    {/* Connection Info Modal */}
                    {isConnectionModalOpen && (
                        <div 
                            className="fixed inset-0 z-50" 
                            onClick={() => setIsConnectionModalOpen(false)}
                        >
                            {/* Position modal directly below the connection indicator in the header */}
                            <div 
                                className={`connection-popover absolute rounded-xl shadow-2xl w-80 ${isDarkTheme ? 'bg-gray-800 border border-gray-600' : 'bg-white border border-gray-200'}`}
                                onClick={(e) => e.stopPropagation()}
                                style={{
                                    top: `${connectionModalPosition.top}px`,
                                    left: `${connectionModalPosition.left}px`,
                                    boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
                                }}
                            >
                                {/* Speech bubble pointer - pointing to connection indicator above */}
                                <div
                                    className={`absolute -top-2 w-4 h-4 rotate-45 border-l border-t ${isDarkTheme ? 'bg-gray-800 border-gray-600' : 'bg-white border-gray-200'}`}
                                    style={{ left: `${connectionModalPosition.pointerLeft}px` }}
                                ></div>
                                
                                {/* Modal Header */}
                                <div className={`p-4 border-b flex justify-between items-center relative z-10 rounded-t-xl ${isDarkTheme ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                    <div className="flex items-center">
                                        <i className="fas fa-plug text-lg text-indigo-600 mr-2"></i>
                                        <h2 className={`text-base font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>Connection Details</h2>
                                    </div>
                                    <button
                                        onClick={() => setIsConnectionModalOpen(false)}
                                        className={`${isDarkTheme ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-600'} transition-colors`}
                                    >
                                        <i className="fas fa-times"></i>
                                    </button>
                                </div>
                                
                                {/* Modal Content */}
                                <div className="p-4 space-y-3">
                                    {connectionInfo ? (
                                        connectionInfo.error ? (
                                            <div className="text-sm text-red-600">
                                                <i className="fas fa-exclamation-triangle mr-2"></i>
                                                {connectionInfo.error}
                                            </div>
                                        ) : (
                                            <>
                                                {/* LLM Section */}
                                                <div className="bg-gradient-to-br from-purple-50 to-indigo-50 rounded-lg p-3 border border-indigo-100">
                                                    <h3 className="text-sm font-semibold text-gray-900 mb-2 flex items-center">
                                                        <i className="fas fa-brain text-purple-600 mr-2 text-xs"></i>
                                                        LLM Configuration
                                                    </h3>
                                                    <div className="space-y-1.5">
                                                        <div className="flex items-start">
                                                            <span className="text-xs font-medium text-gray-500 w-16">Provider:</span>
                                                            <span className="text-xs text-gray-900 font-semibold">{connectionInfo.llm?.provider || 'Unknown'}</span>
                                                        </div>
                                                        <div className="flex items-start">
                                                            <span className="text-xs font-medium text-gray-500 w-16">Model:</span>
                                                            <span className="text-xs text-gray-900 font-mono bg-white px-1.5 py-0.5 rounded border border-indigo-200">{connectionInfo.llm?.model || 'Unknown'}</span>
                                                        </div>
                                                        <div className="flex items-start">
                                                            <span className="text-xs font-medium text-gray-500 w-16">Endpoint:</span>
                                                            <span className="text-xs text-gray-700 break-all flex-1">{connectionInfo.llm?.endpoint || 'Unknown'}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                {/* MCP Section - Simplified to just endpoint */}
                                                <div className="bg-gradient-to-br from-green-50 to-emerald-50 rounded-lg p-3 border border-green-100">
                                                    <h3 className="text-sm font-semibold text-gray-900 mb-2 flex items-center">
                                                        <i className="fas fa-server text-green-600 mr-2 text-xs"></i>
                                                        MCP Server
                                                    </h3>
                                                    <div className="flex items-start">
                                                        <span className="text-xs font-medium text-gray-500 w-16">Endpoint:</span>
                                                        <span className="text-xs text-gray-700 font-mono bg-white px-1.5 py-0.5 rounded border border-green-200 break-all flex-1">{connectionInfo.mcp?.endpoint || 'Unknown'}</span>
                                                    </div>
                                                </div>
                                                
                                                {/* Status */}
                                                <div className="flex items-center justify-center p-2.5 bg-green-50 rounded-lg border border-green-200">
                                                    <i className="fas fa-check-circle text-green-600 mr-2"></i>
                                                    <span className="text-xs font-medium text-green-800">All connections active</span>
                                                </div>
                                            </>
                                        )
                                    ) : (
                                        <div className="flex items-center justify-center p-6">
                                            <i className="fas fa-spinner fa-spin text-lg text-gray-400 mr-2"></i>
                                            <span className="text-xs text-gray-500">Loading...</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Chat Modal */}
                    {isChatOpen && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                            <div className={`rounded-xl shadow-2xl w-full max-w-4xl h-5/6 flex flex-col ${isDarkTheme ? 'bg-gray-800 border border-gray-700' : 'bg-white'}`}>
                                {/* Chat Header */}
                                <div className={`p-6 border-b flex justify-between items-center ${isDarkTheme ? 'border-gray-700' : 'border-gray-200'}`}>
                                    <div className="flex items-center">
                                        <i className="fas fa-comments text-2xl text-green-600 mr-3"></i>
                                        <h2 className={`text-xl font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>Chat with Splunk</h2>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <button
                                            onClick={() => setIsChatSettingsOpen(true)}
                                            className={`px-3 py-1 text-sm ${isDarkTheme ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}
                                            title="Chat settings"
                                        >
                                            <i className="fas fa-cog"></i>
                                        </button>
                                        <button
                                            onClick={() => {
                                                setChatMessages([]);
                                                setServerConversationHistory(null);
                                                setChatSessionId(generateChatSessionId());
                                            }}
                                            className={`px-3 py-1 text-sm ${isDarkTheme ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}
                                            title="Clear chat"
                                        >
                                            <i className="fas fa-trash"></i>
                                        </button>
                                        <button
                                            onClick={() => setIsChatOpen(false)}
                                            className={`${isDarkTheme ? 'text-gray-400 hover:text-gray-100' : 'text-gray-500 hover:text-gray-700'}`}
                                        >
                                            <i className="fas fa-times text-xl"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Chat Messages */}
                                <div className={`flex-1 overflow-y-auto p-6 space-y-4 ${isDarkTheme ? 'bg-gray-900' : 'bg-white'}`}>
                                    {chatMessages.length === 0 && (
                                        <div className={`text-center mt-12 ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                            <i className="fas fa-robot text-4xl mb-4"></i>
                                            <p className="text-lg">Start a conversation with your Splunk environment</p>
                                            <p className="text-sm mt-2">Ask questions about your data, indexes, searches, or get help with SPL queries</p>
                                        </div>
                                    )}
                                    
                                    {chatMessages.map((msg) => (
                                        <div key={msg.id} className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}>
                                            <div className={`max-w-3xl p-4 rounded-lg ${
                                                msg.type === 'user' 
                                                    ? 'bg-indigo-600 text-white' 
                                                    : msg.type === 'error'
                                                    ? (isDarkTheme ? 'bg-red-900 text-red-100 border border-red-700' : 'bg-red-50 text-red-800 border border-red-200')
                                                    : msg.type === 'warning'
                                                    ? (isDarkTheme ? 'bg-amber-900 text-amber-100 border border-amber-700' : 'bg-amber-50 text-amber-900 border border-amber-200')
                                                    : (isDarkTheme ? 'bg-gray-700 text-gray-100 border border-gray-600' : 'bg-gray-100 text-gray-800')
                                            }`}>
                                                {msg.type === 'user' && (
                                                    <div className="flex items-start">
                                                        <div className="flex-1">
                                                            <p className="whitespace-pre-wrap">{msg.content}</p>
                                                        </div>
                                                        <i className="fas fa-user ml-3 mt-1"></i>
                                                    </div>
                                                )}
                                                
                                                {msg.type === 'assistant' && (
                                                    <div className="flex items-start">
                                                        <i className="fas fa-robot mr-3 mt-1 text-green-600"></i>
                                                        <div className="flex-1">
                                                            <p className="whitespace-pre-wrap">{msg.content}</p>
                                                            
                                                            {/* Show SPL Query from tool execution */}
                                                            {msg.spl_query && (
                                                                <details className="mt-3" open>
                                                                    <summary className="cursor-pointer text-sm font-medium text-indigo-600 hover:text-indigo-800 flex items-center">
                                                                        <i className="fas fa-code mr-2"></i>
                                                                        SPL Query Executed
                                                                    </summary>
                                                                    <div className="mt-2 p-4 bg-gray-900 text-green-300 rounded-lg font-mono text-sm">
                                                                        <div className="flex justify-between items-start mb-2">
                                                                            <span className="text-xs text-gray-300 uppercase tracking-wide">Splunk Query</span>
                                                                            <button 
                                                                                onClick={() => {
                                                                                    navigator.clipboard.writeText(msg.spl_query);
                                                                                    // Show feedback
                                                                                    const btn = event.currentTarget;
                                                                                    const originalHTML = btn.innerHTML;
                                                                                    btn.innerHTML = '<i className="fas fa-check"></i> Copied!';
                                                                                    setTimeout(() => btn.innerHTML = originalHTML, 2000);
                                                                                }}
                                                                                className="px-2 py-1 text-xs text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded transition-colors"
                                                                                title="Copy to clipboard"
                                                                            >
                                                                                <i className="fas fa-copy mr-1"></i>
                                                                                Copy
                                                                            </button>
                                                                        </div>
                                                                        <pre className="whitespace-pre-wrap break-all">{msg.spl_query}</pre>
                                                                    </div>
                                                                </details>
                                                            )}
                                                            
                                                            {/* Show SPL mentioned in text (even if not executed) */}
                                                            {!msg.spl_query && msg.spl_in_text && (
                                                                <details className="mt-3">
                                                                    <summary className={`cursor-pointer text-sm font-medium flex items-center ${isDarkTheme ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}>
                                                                        <i className="fas fa-code mr-2"></i>
                                                                        SPL Query (Not Executed)
                                                                    </summary>
                                                                    <div className="mt-2 p-4 bg-gray-900 text-amber-300 rounded-lg font-mono text-sm">
                                                                        <div className="flex justify-between items-start mb-2">
                                                                            <span className="text-xs text-gray-300 uppercase tracking-wide">Suggested Query</span>
                                                                            <button 
                                                                                onClick={() => {
                                                                                    navigator.clipboard.writeText(msg.spl_in_text);
                                                                                    const btn = event.currentTarget;
                                                                                    const originalHTML = btn.innerHTML;
                                                                                    btn.innerHTML = '<i className="fas fa-check"></i> Copied!';
                                                                                    setTimeout(() => btn.innerHTML = originalHTML, 2000);
                                                                                }}
                                                                                className="px-2 py-1 text-xs text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded transition-colors"
                                                                                title="Copy to clipboard"
                                                                            >
                                                                                <i className="fas fa-copy mr-1"></i>
                                                                                Copy
                                                                            </button>
                                                                        </div>
                                                                        <pre className="whitespace-pre-wrap break-all">{msg.spl_in_text}</pre>
                                                                    </div>
                                                                </details>
                                                            )}
                                                            
                                                            {/* Show investigation timeline if multi-turn */}
                                                            {msg.status_timeline && msg.status_timeline.length > 0 && (
                                                                <details className="mt-3">
                                                                    <summary className="cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-800 flex items-center">
                                                                        <i className="fas fa-tasks mr-2"></i>
                                                                        Investigation Timeline ({msg.iterations} iterations, {msg.execution_time})
                                                                    </summary>
                                                                    <div className="mt-2 space-y-2">
                                                                        {msg.status_timeline.map((status, idx) => (
                                                                            <div key={idx} className={`flex items-center justify-between px-3 py-2 rounded border-l-4 border-blue-400 ${isDarkTheme ? 'bg-gray-800' : 'bg-gradient-to-r from-blue-50 to-purple-50'}`}>
                                                                                <span className={`text-sm ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>{status.action}</span>
                                                                                <span className={`text-xs ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>{status.time.toFixed(1)}s</span>
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                </details>
                                                            )}
                                                            
                                                            {/* Show raw MCP data if available */}
                                                            {msg.mcp_data && (
                                                                <details className="mt-3">
                                                                    <summary className={`cursor-pointer text-sm ${isDarkTheme ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}>
                                                                        <i className="fas fa-database mr-1"></i>
                                                                        View Raw Data
                                                                    </summary>
                                                                    <pre className={`mt-2 p-3 rounded text-xs overflow-x-auto ${isDarkTheme ? 'bg-gray-800 text-gray-200' : 'bg-gray-200 text-gray-800'}`}>
                                                                        {JSON.stringify(msg.mcp_data, null, 2)}
                                                                    </pre>
                                                                </details>
                                                            )}
                                                            
                                                            {/* Indicate if follow-on is expected */}
                                                            {msg.has_follow_on && (
                                                                <div className={`mt-3 p-3 border rounded ${isDarkTheme ? 'bg-indigo-900 border-indigo-700' : 'bg-indigo-50 border-indigo-200'}`}>
                                                                    <div className={`text-xs font-semibold flex items-center mb-2 ${isDarkTheme ? 'text-indigo-200' : 'text-indigo-700'}`}>
                                                                        <i className="fas fa-arrow-right mr-1"></i>
                                                                        <span>Suggested next actions</span>
                                                                    </div>
                                                                    {Array.isArray(msg.follow_on_actions) && msg.follow_on_actions.length > 0 ? (
                                                                        <ul className={`text-xs space-y-1 list-disc pl-4 ${isDarkTheme ? 'text-indigo-100' : 'text-indigo-900'}`}>
                                                                            {msg.follow_on_actions.map((action, idx) => (
                                                                                <li key={idx}>{action}</li>
                                                                            ))}
                                                                        </ul>
                                                                    ) : (
                                                                        <div className={`text-xs ${isDarkTheme ? 'text-indigo-200' : 'text-indigo-800'}`}>Follow-up action available.</div>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {msg.type === 'error' && (
                                                    <div className="flex items-start">
                                                        <i className="fas fa-exclamation-triangle mr-3 mt-1 text-red-600"></i>
                                                        <p className="flex-1">{msg.content}</p>
                                                    </div>
                                                )}
                                                
                                                {msg.type === 'warning' && (
                                                    <div className={`flex items-start border-l-4 border-amber-400 p-4 rounded ${isDarkTheme ? 'bg-amber-900' : 'bg-amber-50'}`}>
                                                        <i className="fas fa-exclamation-circle mr-3 mt-1 text-amber-600"></i>
                                                        <p className={`flex-1 ${isDarkTheme ? 'text-amber-100' : 'text-amber-800'}`}>{msg.content}</p>
                                                    </div>
                                                )}
                                                
                                                <div className="text-xs opacity-70 mt-2">
                                                    {new Date(msg.timestamp).toLocaleTimeString()}
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                    
                                    {isTyping && (
                                        <div className="flex justify-start">
                                            <div className={`p-4 rounded-lg shadow-sm border ${isDarkTheme ? 'bg-gray-800 text-gray-200 border-gray-700' : 'bg-gradient-to-r from-blue-50 to-green-50 text-gray-800 border-blue-100'}`}>
                                                <div className="flex items-center space-x-3">
                                                    <i className="fas fa-robot text-green-600"></i>
                                                    <div className="flex space-x-1">
                                                        <div className="w-2 h-2 bg-green-500 rounded-full animate-bounce"></div>
                                                        <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                                                        <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                                                    </div>
                                                    {chatStatus && (
                                                        <span className={`text-sm ml-2 animate-pulse ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            {chatStatus}
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    <div ref={chatEndRef} />
                                </div>
                                
                                {/* Chat Input */}
                                <div className={`p-6 border-t ${isDarkTheme ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                    <div className="mb-4">
                                        <div className="flex items-center justify-between mb-2">
                                            <p className={`text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>Suggested Queries (Demo)</p>
                                            <div className="flex items-center gap-3">
                                                <span className={`text-xs ${isDarkTheme ? 'text-gray-500' : 'text-gray-400'}`}>Deterministic-friendly prompts</span>
                                                <button
                                                    onClick={() => setShowSuggestedQueries(prev => !prev)}
                                                    className="text-xs text-indigo-600 hover:text-indigo-800 flex items-center"
                                                    title={showSuggestedQueries ? 'Collapse suggested queries' : 'Expand suggested queries'}
                                                >
                                                    <i className={`fas ${showSuggestedQueries ? 'fa-chevron-up' : 'fa-chevron-down'}`}></i>
                                                </button>
                                            </div>
                                        </div>
                                        {showSuggestedQueries && (
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                                {suggestedChatQueries.map((query, idx) => (
                                                    <div key={idx} className={`flex items-center border rounded-lg px-2 py-1.5 ${isDarkTheme ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                        <button
                                                            onClick={() => useSuggestedQuery(query)}
                                                            className={`flex-1 text-left text-xs truncate ${isDarkTheme ? 'text-gray-200 hover:text-indigo-300' : 'text-gray-700 hover:text-indigo-700'}`}
                                                            title={query}
                                                        >
                                                            {query}
                                                        </button>
                                                        <button
                                                            onClick={() => sendSuggestedQuery(query)}
                                                            disabled={isTyping}
                                                            className={`ml-2 px-2 py-1 text-xs rounded ${isTyping ? (isDarkTheme ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-gray-200 text-gray-500 cursor-not-allowed') : 'bg-indigo-600 hover:bg-indigo-700 text-white'}`}
                                                            title="Run this query now"
                                                        >
                                                            <i className="fas fa-play"></i>
                                                        </button>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>

                                    <div className="flex space-x-4">
                                        <textarea
                                            ref={chatInputRef}
                                            value={chatInput}
                                            onChange={(e) => setChatInput(e.target.value)}
                                            onKeyPress={(e) => {
                                                if (e.key === 'Enter' && !e.shiftKey) {
                                                    e.preventDefault();
                                                    sendChatMessage();
                                                }
                                            }}
                                            placeholder="Ask me about your Splunk environment..."
                                            className={`flex-1 p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent resize-none ${isDarkTheme ? 'bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'}`}
                                            rows="3"
                                            disabled={isTyping}
                                        />
                                        <button
                                            onClick={sendChatMessage}
                                            disabled={!chatInput.trim() || isTyping}
                                            className={`px-6 py-3 rounded-lg font-medium ${
                                                chatInput.trim() && !isTyping
                                                    ? 'bg-indigo-600 hover:bg-indigo-700 text-white'
                                                    : (isDarkTheme ? 'bg-gray-700 text-gray-400 cursor-not-allowed' : 'bg-gray-300 text-gray-500 cursor-not-allowed')
                                            }`}
                                        >
                                            <i className="fas fa-paper-plane"></i>
                                        </button>
                                    </div>
                                    <p className={`text-xs mt-2 ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                        Press Enter to send, Shift+Enter for new line • Ask about indexes, searches, data sources, or get help with SPL queries
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Chat Settings Modal */}
                    {isChatSettingsOpen && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                            <div className={`chat-settings-modal-shell rounded-xl shadow-2xl w-full max-w-3xl h-5/6 flex flex-col ${isDarkTheme ? 'bg-gray-800 border border-gray-700' : 'bg-white'}`}>
                                {/* Header */}
                                <div className="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-t-xl">
                                    <div className="flex items-center">
                                        <i className="fas fa-cog text-2xl mr-3"></i>
                                        <h2 className="text-2xl font-bold">Chat Settings</h2>
                                    </div>
                                    <div className="flex items-center space-x-3">
                                        <button
                                            onClick={resetChatSettings}
                                            className="px-4 py-2 bg-white bg-opacity-20 hover:bg-opacity-30 rounded-lg text-sm font-medium transition-all"
                                            title="Reset to defaults"
                                        >
                                            <i className="fas fa-undo mr-2"></i>
                                            Reset
                                        </button>
                                        <button
                                            onClick={() => setIsChatSettingsOpen(false)}
                                            className="text-white hover:text-gray-200"
                                        >
                                            <i className="fas fa-times text-2xl"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Settings Content - Scrollable */}
                                <div className="flex-1 overflow-y-auto p-6 space-y-6">
                                    {chatSettings && (
                                        <>
                                            {/* Discovery Settings */}
                                            <div className="bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg p-5 border-2 border-green-200">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                                                    <i className="fas fa-search text-green-600 mr-2"></i>
                                                    Discovery Settings
                                                </h3>
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Max Execution Time: {chatSettings.max_execution_time}s
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="30"
                                                            max="300"
                                                            value={chatSettings.max_execution_time}
                                                            onChange={(e) => updateSetting('max_execution_time', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>30s</span>
                                                            <span>300s</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Max Iterations: {chatSettings.max_iterations}
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="1"
                                                            max="10"
                                                            value={chatSettings.max_iterations}
                                                            onChange={(e) => updateSetting('max_iterations', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>1</span>
                                                            <span>10</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Discovery Freshness: {chatSettings.discovery_freshness_days} days
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="1"
                                                            max="30"
                                                            value={chatSettings.discovery_freshness_days}
                                                            onChange={(e) => updateSetting('discovery_freshness_days', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>1 day</span>
                                                            <span>30 days</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            {/* LLM Behavior */}
                                            <div className="bg-gradient-to-r from-purple-50 to-indigo-50 rounded-lg p-5 border-2 border-purple-200">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                                                    <i className="fas fa-brain text-purple-600 mr-2"></i>
                                                    LLM Behavior
                                                </h3>
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Max Tokens: {chatSettings.max_tokens}
                                                            {config?.llm?.max_tokens && (
                                                                <span className="ml-2 text-xs text-purple-600">
                                                                    (Profile: {config.llm.max_tokens})
                                                                </span>
                                                            )}
                                                        </label>
                                                        <input
                                                            type="number"
                                                            min="1000"
                                                            max="128000"
                                                            value={chatSettings.max_tokens}
                                                            onChange={(e) => updateSetting('max_tokens', parseInt(e.target.value))}
                                                            className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Temperature: {chatSettings.temperature.toFixed(1)}
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="0"
                                                            max="2"
                                                            step="0.1"
                                                            value={chatSettings.temperature}
                                                            onChange={(e) => updateSetting('temperature', parseFloat(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>0.0 (Focused)</span>
                                                            <span>2.0 (Creative)</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Context History: {chatSettings.context_history} messages
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="0"
                                                            max="20"
                                                            value={chatSettings.context_history}
                                                            onChange={(e) => updateSetting('context_history', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>0</span>
                                                            <span>20</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            {/* Performance Tuning */}
                                            <div className="bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg p-5 border-2 border-amber-200">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                                                    <i className="fas fa-tachometer-alt text-amber-600 mr-2"></i>
                                                    Performance Tuning
                                                </h3>
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Max Retry Delay: {chatSettings.max_retry_delay}s
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="10"
                                                            max="600"
                                                            value={chatSettings.max_retry_delay}
                                                            onChange={(e) => updateSetting('max_retry_delay', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>10s</span>
                                                            <span>600s</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Max Retries: {chatSettings.max_retries}
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="1"
                                                            max="10"
                                                            value={chatSettings.max_retries}
                                                            onChange={(e) => updateSetting('max_retries', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>1</span>
                                                            <span>10</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Query Sample Size: {chatSettings.query_sample_size} rows
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="1"
                                                            max="10"
                                                            value={chatSettings.query_sample_size}
                                                            onChange={(e) => updateSetting('query_sample_size', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>1</span>
                                                            <span>10</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            {/* Quality Control */}
                                            <div className="bg-gradient-to-r from-blue-50 to-cyan-50 rounded-lg p-5 border-2 border-blue-200">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                                                    <i className="fas fa-check-circle text-blue-600 mr-2"></i>
                                                    Quality Control
                                                </h3>
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Quality Threshold: {chatSettings.quality_threshold}
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="0"
                                                            max="100"
                                                            value={chatSettings.quality_threshold}
                                                            onChange={(e) => updateSetting('quality_threshold', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>0 (Permissive)</span>
                                                            <span>100 (Strict)</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            Convergence Detection: {chatSettings.convergence_detection} iterations
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="3"
                                                            max="10"
                                                            value={chatSettings.convergence_detection}
                                                            onChange={(e) => updateSetting('convergence_detection', parseInt(e.target.value))}
                                                            className="w-full"
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>3</span>
                                                            <span>10</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="bg-gradient-to-r from-indigo-50 to-violet-50 rounded-lg p-5 border-2 border-indigo-200">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                                                    <i className="fas fa-magic text-indigo-600 mr-2"></i>
                                                    Splunk IQ (Demo)
                                                </h3>
                                                <div className="space-y-4">
                                                    <label className="flex items-center justify-between bg-white rounded p-3 border border-indigo-100">
                                                        <div>
                                                            <div className="text-sm font-medium text-gray-800">Enable Splunk Augmentation</div>
                                                            <div className="text-xs text-gray-500">Use intent-specific deterministic skills for common Splunk questions</div>
                                                        </div>
                                                        <input
                                                            type="checkbox"
                                                            checked={!!chatSettings.enable_splunk_augmentation}
                                                            onChange={(e) => updateSetting('enable_splunk_augmentation', e.target.checked)}
                                                            className="h-4 w-4"
                                                        />
                                                    </label>

                                                    <label className="flex items-center justify-between bg-white rounded p-3 border border-indigo-100">
                                                        <div>
                                                            <div className="text-sm font-medium text-gray-800">Enable Optional Local RAG</div>
                                                            <div className="text-xs text-gray-500">Retrieve matching snippets from recent discovery output files</div>
                                                        </div>
                                                        <input
                                                            type="checkbox"
                                                            checked={!!chatSettings.enable_rag_context}
                                                            onChange={(e) => updateSetting('enable_rag_context', e.target.checked)}
                                                            className="h-4 w-4"
                                                        />
                                                    </label>

                                                    <div>
                                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                                            RAG Snippet Chunks: {chatSettings.rag_max_chunks}
                                                        </label>
                                                        <input
                                                            type="range"
                                                            min="1"
                                                            max="6"
                                                            value={chatSettings.rag_max_chunks || 3}
                                                            onChange={(e) => updateSetting('rag_max_chunks', parseInt(e.target.value))}
                                                            className="w-full"
                                                            disabled={!chatSettings.enable_rag_context}
                                                        />
                                                        <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                            <span>1</span>
                                                            <span>6</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </>
                                    )}
                                </div>
                                
                                {/* Footer */}
                                <div className={`p-6 border-t rounded-b-xl ${isDarkTheme ? 'border-gray-700 bg-gray-900' : 'border-gray-200 bg-gray-50'}`}>
                                    <p className="text-sm text-gray-600 text-center">
                                        <i className="fas fa-info-circle mr-2"></i>
                                        Settings apply immediately and reset to defaults on server restart
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Summary Modal */}
                    {isSummaryModalOpen && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                            <div className={`${isDarkTheme ? 'bg-gray-900 text-gray-100' : 'bg-white text-gray-900'} rounded-xl shadow-2xl w-full max-w-7xl h-5/6 flex flex-col`}>
                                {/* Header */}
                                <div className="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-t-xl">
                                    <div className="flex items-center">
                                        <i className={`fas ${summaryData?.from_cache ? 'fa-eye' : 'fa-magic'} text-2xl mr-3`}></i>
                                        <div>
                                            <h2 className="text-2xl font-bold">
                                                V2 Intelligence Report
                                                {summaryData?.from_cache && (
                                                    <span className="ml-3 text-sm font-normal bg-green-500 bg-opacity-30 px-3 py-1 rounded-full">
                                                        <i className="fas fa-check-circle mr-1"></i>
                                                        Cached
                                                    </span>
                                                )}
                                            </h2>
                                            <p className="text-sm text-indigo-100 mt-1">Session: {currentSessionId}</p>
                                        </div>
                                    </div>
                                    <button
                                        onClick={closeSummaryModal}
                                        className="text-white hover:text-gray-200"
                                    >
                                        <i className="fas fa-times text-2xl"></i>
                                    </button>
                                </div>
                                
                                {/* Tab Navigation */}
                                {!isLoadingSummary && summaryData && (
                                    <div className={`border-b ${isDarkTheme ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                        <div className="flex space-x-1 px-6">
                                            <button
                                                onClick={() => setActiveTab('summary')}
                                                className={`px-6 py-3 font-medium text-sm transition-all ${
                                                    activeTab === 'summary'
                                                        ? (isDarkTheme ? 'border-b-2 border-indigo-400 text-indigo-300 bg-gray-900' : 'border-b-2 border-indigo-600 text-indigo-600 bg-white')
                                                        : (isDarkTheme ? 'text-gray-300 hover:text-white hover:bg-gray-700' : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100')
                                                }`}
                                            >
                                                <i className="fas fa-brain mr-2"></i>
                                                Executive Summary
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('queries')}
                                                className={`px-6 py-3 font-medium text-sm transition-all ${
                                                    activeTab === 'queries'
                                                        ? (isDarkTheme ? 'border-b-2 border-indigo-400 text-indigo-300 bg-gray-900' : 'border-b-2 border-indigo-600 text-indigo-600 bg-white')
                                                        : (isDarkTheme ? 'text-gray-300 hover:text-white hover:bg-gray-700' : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100')
                                                }`}
                                            >
                                                <i className="fas fa-code mr-2"></i>
                                                SPL Queries ({summaryData.spl_queries?.length || 0})
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('tasks')}
                                                className={`px-6 py-3 font-medium text-sm transition-all ${
                                                    activeTab === 'tasks'
                                                        ? (isDarkTheme ? 'border-b-2 border-indigo-400 text-indigo-300 bg-gray-900' : 'border-b-2 border-indigo-600 text-indigo-600 bg-white')
                                                        : (isDarkTheme ? 'text-gray-300 hover:text-white hover:bg-gray-700' : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100')
                                                }`}
                                            >
                                                <i className="fas fa-tasks mr-2"></i>
                                                Admin Tasks ({summaryData.admin_tasks?.length || 0})
                                                {summaryData.admin_tasks?.length > 0 && (
                                                    <span className="ml-2 px-2 py-0.5 text-xs bg-green-500 text-white rounded-full">New</span>
                                                )}
                                            </button>
                                        </div>
                                    </div>
                                )}
                                
                                {/* Content */}
                                <div className="flex-1 overflow-y-auto p-6">
                                    {isLoadingSummary ? (
                                        <div className="flex items-center justify-center h-full">
                                            <div className="text-center max-w-md">
                                                {/* Animated Icon */}
                                                <div className="relative mb-8">
                                                    <div className={`inline-block animate-spin rounded-full h-20 w-20 border-4 ${isDarkTheme ? 'border-indigo-900 border-t-indigo-400' : 'border-indigo-200 border-t-indigo-600'}`}></div>
                                                    <i className={`fas fa-brain absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-3xl animate-pulse ${isDarkTheme ? 'text-indigo-300' : 'text-indigo-600'}`}></i>
                                                </div>
                                                
                                                {/* Main Message */}
                                                <h3 className={`text-2xl font-bold mb-4 ${isDarkTheme ? 'text-gray-100' : 'text-gray-800'}`}>
                                                    Analyzing Your Splunk Environment
                                                </h3>
                                                
                                                {/* Progress Steps */}
                                                <div className={`space-y-3 text-left rounded-lg shadow-sm border p-4 mb-4 ${isDarkTheme ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                    {/* Stage 1: Loading Reports */}
                                                    <div className={`flex items-center text-sm ${isSummaryStepActive(1) ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            isSummaryStepDone(1)
                                                                ? 'bg-green-500'
                                                                : isSummaryStepActive(1)
                                                                    ? 'bg-indigo-500'
                                                                    : (isDarkTheme ? 'border-2 border-gray-600' : 'border-2 border-gray-300')
                                                        }`}>
                                                            {isSummaryStepDone(1) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : isSummaryStepActive(1) ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={isSummaryStepActive(1) ? (isDarkTheme ? 'text-gray-100 font-medium' : 'text-gray-700 font-medium') : (isDarkTheme ? 'text-gray-300' : 'text-gray-700')}>
                                                            Loading discovery reports...
                                                        </span>
                                                    </div>
                                                    
                                                    {/* Stage 2: Generating Queries */}
                                                    <div className={`flex items-center text-sm ${isSummaryStepActive(2) ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            isSummaryStepDone(2)
                                                                ? 'bg-green-500'
                                                                : isSummaryStepActive(2)
                                                                    ? 'bg-indigo-500'
                                                                    : (isDarkTheme ? 'border-2 border-gray-600' : 'border-2 border-gray-300')
                                                        }`}>
                                                            {isSummaryStepDone(2) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : isSummaryStepActive(2) ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={isSummaryStepActive(2) ? (isDarkTheme ? 'text-gray-100 font-medium' : 'text-gray-700 font-medium') : (isDarkTheme ? 'text-gray-400' : 'text-gray-500')}>
                                                            Generating SPL queries...
                                                        </span>
                                                    </div>
                                                    
                                                    {/* Stage 3: Building Summary */}
                                                    <div className={`flex items-center text-sm ${isSummaryStepActive(3) ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            isSummaryStepDone(3)
                                                                ? 'bg-green-500'
                                                                : isSummaryStepActive(3)
                                                                    ? 'bg-indigo-500'
                                                                    : (isDarkTheme ? 'border-2 border-gray-600' : 'border-2 border-gray-300')
                                                        }`}>
                                                            {isSummaryStepDone(3) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : isSummaryStepActive(3) ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={isSummaryStepActive(3) ? (isDarkTheme ? 'text-gray-100 font-medium' : 'text-gray-700 font-medium') : (isDarkTheme ? 'text-gray-400' : 'text-gray-500')}>
                                                            Building executive summary...
                                                        </span>
                                                    </div>
                                                    
                                                    {/* Stage 4: Creating Tasks */}
                                                    <div className={`flex items-center text-sm ${isSummaryStepActive(4) ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            isSummaryStepDone(4)
                                                                ? 'bg-green-500'
                                                                : isSummaryStepActive(4)
                                                                    ? 'bg-indigo-500'
                                                                    : (isDarkTheme ? 'border-2 border-gray-600' : 'border-2 border-gray-300')
                                                        }`}>
                                                            {isSummaryStepDone(4) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : isSummaryStepActive(4) ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={isSummaryStepActive(4) ? (isDarkTheme ? 'text-gray-100 font-medium' : 'text-gray-700 font-medium') : (isDarkTheme ? 'text-gray-400' : 'text-gray-500')}>
                                                            Creating admin tasks...
                                                        </span>
                                                    </div>
                                                </div>
                                                
                                                {/* Progress Bar */}
                                                <div className="mb-4">
                                                    <div className="flex justify-between items-center mb-1">
                                                        <span className={`text-xs font-medium ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>{summaryProgress.message}</span>
                                                        <span className="text-xs font-semibold text-indigo-600">{summaryProgress.progress}%</span>
                                                    </div>
                                                    <div className={`w-full rounded-full h-2 ${isDarkTheme ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                                        <div 
                                                            className="bg-gradient-to-r from-indigo-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
                                                            style={{width: `${summaryProgress.progress}%`}}
                                                        ></div>
                                                    </div>
                                                </div>
                                                
                                                {/* Fun Facts */}
                                                <div className={`text-xs italic ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                                    <i className="fas fa-lightbulb mr-1 text-yellow-500"></i>
                                                    This analysis uses AI to understand your data patterns and recommend optimizations
                                                </div>
                                            </div>
                                        </div>
                                    ) : summaryData ? (
                                        <div>
                                            {/* Executive Summary Tab */}
                                            {activeTab === 'summary' && (
                                                <div className="space-y-6">
                                                    {/* AI Summary Section */}
                                                    <div className={`border-l-4 p-6 rounded-r-lg ${isDarkTheme ? 'bg-gradient-to-r from-slate-800 to-indigo-950 border-indigo-400' : 'bg-gradient-to-r from-blue-50 to-indigo-50 border-indigo-600'}`}>
                                                        <h3 className={`text-xl font-semibold mb-4 flex items-center ${isDarkTheme ? 'text-indigo-100' : 'text-gray-900'}`}>
                                                            <i className="fas fa-brain text-indigo-600 mr-2"></i>
                                                            Executive Summary
                                                        </h3>
                                                        <div className="prose max-w-none">
                                                            <pre className={`whitespace-pre-wrap font-sans ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>{summaryData.ai_summary}</pre>
                                                        </div>
                                                    </div>

                                                    {/* V2 Intelligence KPIs */}
                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                                        <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-indigo-950 border-indigo-700' : 'bg-indigo-100 border-indigo-300'}`}>
                                                            <div className={`text-3xl font-bold ${isDarkTheme ? 'text-indigo-200' : 'text-indigo-900'}`}>{summaryData.readiness_score ?? summaryData.v2_context?.readiness_score ?? 'N/A'}</div>
                                                            <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-indigo-300' : 'text-indigo-800'}`}>Readiness Score</div>
                                                        </div>
                                                        <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-red-950 border-red-700' : 'bg-red-100 border-red-300'}`}>
                                                            <div className={`text-3xl font-bold ${isDarkTheme ? 'text-red-200' : 'text-red-900'}`}>{summaryData.risk_register?.length ?? summaryData.v2_context?.risk_register ?? 0}</div>
                                                            <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-red-300' : 'text-red-800'}`}>Risk Register Items</div>
                                                        </div>
                                                        <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-amber-950 border-amber-700' : 'bg-amber-100 border-amber-300'}`}>
                                                            <div className={`text-3xl font-bold ${isDarkTheme ? 'text-amber-200' : 'text-amber-900'}`}>{summaryData.coverage_gaps?.length ?? summaryData.v2_context?.coverage_gaps ?? 0}</div>
                                                            <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-amber-300' : 'text-amber-800'}`}>Coverage Gaps</div>
                                                        </div>
                                                        <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-purple-950 border-purple-700' : 'bg-purple-100 border-purple-300'}`}>
                                                            <div className={`text-3xl font-bold ${isDarkTheme ? 'text-purple-200' : 'text-purple-900'}`}>{summaryData.recursive_investigations?.length ?? summaryData.v2_context?.recursive_investigations ?? 0}</div>
                                                            <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-purple-300' : 'text-purple-800'}`}>Recursive Loops</div>
                                                        </div>
                                                    </div>
                                                    
                                                    {/* Stats Section */}
                                                    {summaryData.stats && (
                                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                            <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-green-950 border-green-700' : 'bg-green-100 border-green-300'}`}>
                                                                <div className={`text-3xl font-bold ${isDarkTheme ? 'text-green-200' : 'text-green-900'}`}>{summaryData.stats.total_queries}</div>
                                                                <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-green-300' : 'text-green-800'}`}>SPL Queries Generated</div>
                                                            </div>
                                                            <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-blue-950 border-blue-700' : 'bg-blue-100 border-blue-300'}`}>
                                                                <div className={`text-3xl font-bold ${isDarkTheme ? 'text-blue-200' : 'text-blue-900'}`}>{summaryData.stats.categories?.length || 0}</div>
                                                                <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-blue-300' : 'text-blue-800'}`}>Use Case Categories</div>
                                                            </div>
                                                            <div className={`border rounded-lg p-4 text-center ${isDarkTheme ? 'bg-orange-950 border-orange-700' : 'bg-orange-100 border-orange-300'}`}>
                                                                <div className={`text-3xl font-bold ${isDarkTheme ? 'text-orange-200' : 'text-orange-900'}`}>{summaryData.stats.unknown_items}</div>
                                                                <div className={`text-sm mt-1 font-medium ${isDarkTheme ? 'text-orange-300' : 'text-orange-800'}`}>Data Sources Needing Review</div>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Trend Signals Panel */}
                                                    {summaryData.trend_signals && (
                                                        <div className={`${isDarkTheme ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-5`}>
                                                            <h3 className={`text-lg font-semibold mb-3 flex items-center ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                                <i className="fas fa-chart-line text-blue-600 mr-2"></i>
                                                                Trend & Usage Signals
                                                            </h3>
                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                                <div className={`${isDarkTheme ? 'bg-blue-950 border-blue-700' : 'bg-blue-100 border-blue-300'} border rounded p-3`}>
                                                                    <div className={`text-xs uppercase tracking-wide ${isDarkTheme ? 'text-blue-300' : 'text-blue-800'}`}>Evidence Steps</div>
                                                                    <div className={`text-2xl font-bold ${isDarkTheme ? 'text-blue-100' : 'text-blue-900'}`}>{summaryData.trend_signals.evidence_steps ?? 0}</div>
                                                                </div>
                                                                <div className={`${isDarkTheme ? 'bg-green-950 border-green-700' : 'bg-green-100 border-green-300'} border rounded p-3`}>
                                                                    <div className={`text-xs uppercase tracking-wide ${isDarkTheme ? 'text-green-300' : 'text-green-800'}`}>High Priority Recommendations</div>
                                                                    <div className={`text-2xl font-bold ${isDarkTheme ? 'text-green-100' : 'text-green-900'}`}>{summaryData.trend_signals.high_priority_recommendations ?? 0}</div>
                                                                </div>
                                                            </div>
                                                            {summaryData.trend_signals.recommendation_by_domain && (
                                                                <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
                                                                    {Object.entries(summaryData.trend_signals.recommendation_by_domain).map(([domain, count]) => (
                                                                        <div key={domain} className={`${isDarkTheme ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'} border rounded p-2 text-center`}>
                                                                            <div className={`text-xs uppercase ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>{domain.replace('_', ' ')}</div>
                                                                            <div className={`text-lg font-bold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>{count}</div>
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}

                                                    {/* Risk Register Panel */}
                                                    {summaryData.risk_register && summaryData.risk_register.length > 0 && (
                                                        <div className={`${isDarkTheme ? 'bg-red-950 border-red-700' : 'bg-red-50 border-red-200'} border rounded-lg p-5`}>
                                                            <h3 className={`text-lg font-semibold mb-3 flex items-center ${isDarkTheme ? 'text-red-200' : 'text-red-900'}`}>
                                                                <i className="fas fa-shield-alt text-red-600 mr-2"></i>
                                                                Risk Register (Top {Math.min(summaryData.risk_register.length, 6)})
                                                            </h3>
                                                            <div className="space-y-3">
                                                                {summaryData.risk_register.slice(0, 6).map((risk, idx) => (
                                                                    <div key={idx} className={`${isDarkTheme ? 'bg-gray-900 border-red-700' : 'bg-white border-red-200'} border rounded p-3`}>
                                                                        <div className="flex items-start justify-between gap-3">
                                                                            <div className="flex-1">
                                                                                <div className="flex items-center gap-2 mb-1">
                                                                                    <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${
                                                                                        String(risk.severity || '').toLowerCase() === 'high' ? 'bg-red-600 text-white' :
                                                                                        String(risk.severity || '').toLowerCase() === 'critical' ? 'bg-red-700 text-white' :
                                                                                        String(risk.severity || '').toLowerCase() === 'medium' ? 'bg-orange-500 text-white' :
                                                                                        'bg-gray-500 text-white'
                                                                                    }`}>
                                                                                        {(risk.severity || 'medium').toString().toUpperCase()}
                                                                                    </span>
                                                                                    <span className={`text-xs ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>{risk.domain || 'general'}</span>
                                                                                </div>
                                                                                <p className={`font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>{risk.risk || 'Operational risk'}</p>
                                                                                {risk.impact && <p className={`text-sm mt-1 ${isDarkTheme ? 'text-gray-300' : 'text-gray-700'}`}>{risk.impact}</p>}
                                                                            </div>
                                                                            <button
                                                                                onClick={() => {
                                                                                    setChatInput(`Help me investigate and mitigate this risk in Splunk:\n\n${risk.risk || ''}\nImpact: ${risk.impact || ''}\nMitigation: ${risk.mitigation || ''}`);
                                                                                    setIsChatOpen(true);
                                                                                    closeSummaryModal();
                                                                                }}
                                                                                className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs rounded"
                                                                            >
                                                                                Investigate
                                                                            </button>
                                                                        </div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Recursive Loop Panel */}
                                                    {summaryData.recursive_investigations && summaryData.recursive_investigations.length > 0 && (
                                                        <div className={`${isDarkTheme ? 'bg-purple-950 border-purple-700' : 'bg-purple-50 border-purple-200'} border rounded-lg p-5`}>
                                                            <h3 className={`text-lg font-semibold mb-3 flex items-center ${isDarkTheme ? 'text-purple-200' : 'text-purple-900'}`}>
                                                                <i className="fas fa-sync-alt text-purple-600 mr-2"></i>
                                                                Recursive Discovery & Analysis Loops
                                                            </h3>
                                                            <div className="space-y-3">
                                                                {summaryData.recursive_investigations.map((loop, idx) => (
                                                                    <details key={idx} className={`${isDarkTheme ? 'bg-gray-900 border-purple-700' : 'bg-white border-purple-200'} border rounded p-3`} open={idx === 0}>
                                                                        <summary className={`cursor-pointer font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>{loop.loop || `Loop ${idx + 1}`}</summary>
                                                                        <div className={`mt-2 text-sm space-y-1 ${isDarkTheme ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                            <p><strong>Objective:</strong> {loop.objective || 'N/A'}</p>
                                                                            <p><strong>Trigger:</strong> {loop.next_iteration_trigger || 'N/A'}</p>
                                                                            <p><strong>Deliverable:</strong> {loop.output || 'N/A'}</p>
                                                                        </div>
                                                                    </details>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                    
                                                    {/* Unknown Data Section */}
                                                    {summaryData.unknown_data && summaryData.unknown_data.length > 0 && (
                                                        <div className={`${isDarkTheme ? 'bg-gray-800 border-gray-700' : 'bg-orange-50 border-orange-200'} border rounded-lg p-4`}>
                                                            <h3 className={`text-xl font-semibold mb-2 flex items-center ${isDarkTheme ? 'text-orange-200' : 'text-gray-900'}`}>
                                                                <i className="fas fa-question-circle text-orange-600 mr-2"></i>
                                                                Help Us Understand Your Data ({summaryData.unknown_data.length})
                                                            </h3>
                                                            <p className={`text-sm mb-4 ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                                                We found some data sources we're not familiar with. Your answers will help us provide better recommendations.
                                                            </p>
                                                            <div className="space-y-4">
                                                                {summaryData.unknown_data.slice(0, 3).map((item, idx) => (
                                                                    <div key={idx} className={`${isDarkTheme ? 'border-orange-700 bg-gray-900' : 'border-orange-200 bg-orange-50'} border rounded-lg p-4`}>
                                                                        <div className="flex items-center justify-between">
                                                                            <h4 className={`text-base font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                                                {item.type === 'index' ? '📦' : '📄'} 
                                                                                <code className={`ml-2 px-2 py-1 rounded text-sm ${isDarkTheme ? 'bg-gray-800 text-orange-200' : 'bg-white text-gray-900'}`}>{item.name}</code>
                                                                            </h4>
                                                                            <span className={`text-xs ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>{item.type}</span>
                                                                        </div>
                                                                        {item.reason && (
                                                                            <p className={`text-sm mt-2 ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>{item.reason}</p>
                                                                        )}
                                                                        <div className="mt-3 flex flex-wrap gap-2">
                                                                            <button
                                                                                onClick={() => {
                                                                                    setChatInput(`Investigate this unknown Splunk ${item.type || 'entity'} and explain what it is, whether it is expected, and how to validate it:\n\nName: ${item.name || 'unknown'}\nReason: ${item.reason || 'not classified in current model'}`);
                                                                                    setIsChatOpen(true);
                                                                                    closeSummaryModal();
                                                                                }}
                                                                                className="px-3 py-1.5 bg-orange-600 hover:bg-orange-700 text-white text-xs rounded"
                                                                            >
                                                                                Investigate in Chat
                                                                            </button>
                                                                            <button
                                                                                onClick={() => {
                                                                                    const entityType = (item.type || '').toLowerCase();
                                                                                    const entityName = item.name || '';
                                                                                    const suggestedSPL = entityType === 'index'
                                                                                        ? `index=${entityName} | stats count by sourcetype host | sort - count`
                                                                                        : `index=* sourcetype=${entityName} | stats count by index host | sort - count`;
                                                                                    setChatInput(`Create and explain a validation workflow for this unknown entity. Start with this SPL and improve it if needed:\n\n${suggestedSPL}`);
                                                                                    setIsChatOpen(true);
                                                                                    closeSummaryModal();
                                                                                }}
                                                                                className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs rounded"
                                                                            >
                                                                                Build Validation Query
                                                                            </button>
                                                                        </div>
                                                                    </div>
                                                                ))}
                                                                {summaryData.unknown_data.length > 3 && (
                                                                    <p className={`text-sm text-center ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                                                        And {summaryData.unknown_data.length - 3} more...
                                                                    </p>
                                                                )}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                            
                                            {/* SPL Queries Tab */}
                                            {activeTab === 'queries' && (
                                                <div className={isDarkTheme ? 'text-gray-100' : 'text-gray-900'}>
                                                    {summaryData.risk_register && summaryData.risk_register.length > 0 && (
                                                        <div className={`mb-4 rounded-lg p-4 border ${isDarkTheme ? 'bg-red-950 border-red-700' : 'bg-red-50 border-red-200'}`}>
                                                            <h4 className={`text-sm font-semibold mb-2 flex items-center ${isDarkTheme ? 'text-red-200' : 'text-red-900'}`}>
                                                                <i className="fas fa-shield-alt mr-2"></i>
                                                                Risk-Linked Query Focus
                                                            </h4>
                                                            <p className={`text-sm mb-3 ${isDarkTheme ? 'text-red-300' : 'text-red-800'}`}>
                                                                Prioritize queries that validate or reduce the highest-severity risks discovered in this session.
                                                            </p>
                                                            <div className="space-y-1">
                                                                {summaryData.risk_register.slice(0, 3).map((risk, idx) => (
                                                                    <div key={idx} className={`text-xs rounded px-3 py-2 border ${isDarkTheme ? 'text-red-200 bg-gray-900 border-red-800' : 'text-red-900 bg-white border-red-200'}`}>
                                                                        <span className="font-semibold">{(risk.severity || 'medium').toString().toUpperCase()}:</span> {risk.risk || 'Operational risk'}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}

                                                    <div className="flex items-center justify-between mb-4">
                                                        <h3 className={`text-xl font-semibold flex items-center ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                            <i className="fas fa-code text-purple-600 mr-2"></i>
                                                            Ready-to-Use SPL Queries ({summaryData.spl_queries.filter(q => 
                                                                queryFilter === 'all' || q.query_source === queryFilter
                                                            ).length})
                                                        </h3>
                                                        
                                                        {/* Filter Toggle */}
                                                        <div className="flex items-center space-x-2">
                                                            <button
                                                                onClick={() => setQueryFilter('all')}
                                                                className={`px-3 py-1 text-sm font-medium rounded-lg transition-colors ${
                                                                    queryFilter === 'all' 
                                                                        ? 'bg-indigo-600 text-white' 
                                                                        : (isDarkTheme ? 'bg-gray-700 text-gray-200 hover:bg-gray-600' : 'bg-gray-100 text-gray-700 hover:bg-gray-200')
                                                                }`}
                                                            >
                                                                All ({summaryData.spl_queries.length})
                                                            </button>
                                                            <button
                                                                onClick={() => setQueryFilter('ai_finding')}
                                                                className={`px-3 py-1 text-sm font-medium rounded-lg transition-colors flex items-center space-x-1 ${
                                                                    queryFilter === 'ai_finding' 
                                                                        ? 'bg-purple-600 text-white' 
                                                                        : (isDarkTheme ? 'bg-gray-700 text-gray-200 hover:bg-gray-600' : 'bg-gray-100 text-gray-700 hover:bg-gray-200')
                                                                }`}
                                                            >
                                                                <span>⚡</span>
                                                                <span>AI-Generated ({summaryData.spl_queries.filter(q => q.query_source === 'ai_finding').length})</span>
                                                            </button>
                                                            <button
                                                                onClick={() => setQueryFilter('template')}
                                                                className={`px-3 py-1 text-sm font-medium rounded-lg transition-colors flex items-center space-x-1 ${
                                                                    queryFilter === 'template' 
                                                                        ? 'bg-blue-600 text-white' 
                                                                        : (isDarkTheme ? 'bg-gray-700 text-gray-200 hover:bg-gray-600' : 'bg-gray-100 text-gray-700 hover:bg-gray-200')
                                                                }`}
                                                            >
                                                                <span>📋</span>
                                                                <span>Template-Based ({summaryData.spl_queries.filter(q => q.query_source === 'template').length})</span>
                                                            </button>
                                                        </div>
                                                    </div>
                                                    
                                                    <div className="space-y-4">
                                                        {summaryData.spl_queries
                                                            .filter(query => queryFilter === 'all' || query.query_source === queryFilter)
                                                            .map((query, idx) => (
                                                            <div key={idx} className={`border rounded-lg p-5 hover:shadow-md transition-shadow ${
                                                                query.priority?.startsWith('🔴') ? (isDarkTheme ? 'border-red-700 bg-red-950' : 'border-red-300 bg-red-50') :
                                                                query.priority?.startsWith('🟠') ? (isDarkTheme ? 'border-orange-700 bg-orange-950' : 'border-orange-300 bg-orange-50') :
                                                                query.priority?.startsWith('🟡') ? (isDarkTheme ? 'border-yellow-700 bg-yellow-950' : 'border-yellow-300 bg-yellow-50') :
                                                                (isDarkTheme ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white')
                                                            }`}>
                                                                {/* Priority Badge */}
                                                                {query.priority && (
                                                                    <div className="mb-2">
                                                                        <span className={`px-3 py-1 text-xs font-bold rounded-full ${
                                                                            query.priority.startsWith('🔴') ? 'bg-red-600 text-white' :
                                                                            query.priority.startsWith('🟠') ? 'bg-orange-600 text-white' :
                                                                            query.priority.startsWith('🟡') ? 'bg-yellow-500 text-gray-900' :
                                                                            'bg-gray-600 text-white'
                                                                        }`}>
                                                                            {query.priority}
                                                                        </span>
                                                                        {query.query_source === 'ai_finding' && (
                                                                            <span className="ml-2 px-2 py-1 text-xs bg-purple-600 text-white rounded-full">
                                                                                ⚡ AI-Generated
                                                                            </span>
                                                                        )}
                                                                        {query.query_source === 'template' && (
                                                                            <span className="ml-2 px-2 py-1 text-xs bg-blue-600 text-white rounded-full">
                                                                                📋 Template
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                )}
                                                                
                                                                <div className="flex justify-between items-start mb-3">
                                                                    <div className="flex-1">
                                                                        <div className="flex items-center space-x-2 mb-2">
                                                                            <h4 className={`text-lg font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>{query.title}</h4>
                                                                            <span className={`px-2 py-1 text-xs rounded-full ${
                                                                                query.category === 'Security & Compliance' ? (isDarkTheme ? 'bg-red-900 text-red-200' : 'bg-red-100 text-red-700') :
                                                                                query.category === 'Infrastructure & Performance' ? (isDarkTheme ? 'bg-blue-900 text-blue-200' : 'bg-blue-100 text-blue-700') :
                                                                                query.category === 'Capacity Planning' ? (isDarkTheme ? 'bg-green-900 text-green-200' : 'bg-green-100 text-green-700') :
                                                                                (isDarkTheme ? 'bg-gray-700 text-gray-200' : 'bg-gray-100 text-gray-700')
                                                                            }`}>
                                                                                {query.category}
                                                                            </span>
                                                                            <span className={`px-2 py-1 text-xs rounded-full ${isDarkTheme ? 'bg-purple-900 text-purple-200' : 'bg-purple-100 text-purple-700'}`}>
                                                                                {query.difficulty}
                                                                            </span>
                                                                        </div>
                                                                        <p className={`text-sm mb-2 ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>{query.description}</p>
                                                                        
                                                                        {/* Finding Reference */}
                                                                        {query.finding_reference && (
                                                                            <div className={`mt-2 p-2 border-l-2 rounded-r text-xs ${isDarkTheme ? 'bg-indigo-950 border-indigo-500 text-indigo-200' : 'bg-indigo-50 border-indigo-600 text-indigo-900'}`}>
                                                                                <strong>📋 Discovery Finding:</strong> {query.finding_reference}
                                                                            </div>
                                                                        )}
                                                                        {query.environment_evidence && query.environment_evidence.length > 0 && (
                                                                            <div className="mt-2 flex flex-wrap gap-2">
                                                                                {query.environment_evidence.map((evidence, evidenceIdx) => (
                                                                                    <span key={evidenceIdx} className={`px-2 py-1 text-xs rounded-full border ${isDarkTheme ? 'bg-emerald-900 text-emerald-200 border-emerald-700' : 'bg-emerald-100 text-emerald-800 border-emerald-300'}`}>
                                                                                        {evidence}
                                                                                    </span>
                                                                                ))}
                                                                            </div>
                                                                        )}
                                                                        
                                                                        <div className={`flex items-center space-x-4 text-xs mt-2 ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                                                            <span><i className="fas fa-clock mr-1"></i>{query.execution_time}</span>
                                                                            <span><i className="fas fa-chart-line mr-1"></i>{query.use_case}</span>
                                                                        </div>
                                                                    </div>
                                                                    <div className="ml-4 flex space-x-2">
                                                                        <button
                                                                            onClick={() => {
                                                                                setChatInput(`Can you help me understand this query and run it?\\n\\n${query.spl}`);
                                                                                setIsChatOpen(true);
                                                                                closeSummaryModal();
                                                                                setTimeout(() => chatInputRef.current?.focus(), 300);
                                                                            }}
                                                                            className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1"
                                                                            title="Ask AI about this query"
                                                                        >
                                                                            <i className="fas fa-comments"></i>
                                                                            <span>Ask AI</span>
                                                                        </button>
                                                                        <button
                                                                            onClick={() => copyToClipboard(query.spl)}
                                                                            className="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white text-sm rounded flex items-center space-x-1"
                                                                            title="Copy to clipboard"
                                                                        >
                                                                            <i className="fas fa-copy"></i>
                                                                            <span>Copy</span>
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                                
                                                                <details className="mt-3">
                                                                    <summary className={`cursor-pointer text-sm font-medium ${isDarkTheme ? 'text-indigo-300 hover:text-indigo-200' : 'text-indigo-600 hover:text-indigo-800'}`}>
                                                                        <i className="fas fa-code mr-1"></i>
                                                                        View SPL Code
                                                                    </summary>
                                                                    <pre className="mt-2 p-4 bg-gray-900 text-green-400 rounded text-sm overflow-x-auto">
{query.spl}
                                                                    </pre>
                                                                </details>
                                                                
                                                                {query.business_value && (
                                                                    <div className={`mt-3 p-3 border-l-4 rounded-r ${isDarkTheme ? 'bg-yellow-950 border-yellow-600' : 'bg-yellow-50 border-yellow-400'}`}>
                                                                        <p className={`text-sm ${isDarkTheme ? 'text-yellow-200' : 'text-yellow-900'}`}>
                                                                            <i className="fas fa-lightbulb mr-1"></i>
                                                                            <strong>Business Value:</strong> {query.business_value}
                                                                        </p>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {/* Admin Tasks Tab */}
                                            {activeTab === 'tasks' && (
                                                <div className={isDarkTheme ? 'text-gray-100' : 'text-gray-900'}>
                                                    {summaryData.recursive_investigations && summaryData.recursive_investigations.length > 0 && (
                                                        <div className={`mb-5 rounded-lg p-4 border ${isDarkTheme ? 'bg-purple-950 border-purple-700' : 'bg-purple-50 border-purple-200'}`}>
                                                            <h4 className={`text-sm font-semibold mb-2 flex items-center ${isDarkTheme ? 'text-purple-200' : 'text-purple-900'}`}>
                                                                <i className="fas fa-sync-alt mr-2"></i>
                                                                Recursive Execution Guidance
                                                            </h4>
                                                            <div className="space-y-2">
                                                                {summaryData.recursive_investigations.slice(0, 2).map((loop, idx) => (
                                                                    <div key={idx} className={`rounded p-3 text-xs border ${isDarkTheme ? 'bg-gray-900 border-purple-800 text-purple-200' : 'bg-white border-purple-200 text-purple-900'}`}>
                                                                        <div className="font-semibold">{loop.loop || `Loop ${idx + 1}`}</div>
                                                                        <div className="mt-1"><strong>Trigger:</strong> {loop.next_iteration_trigger || 'N/A'}</div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {summaryData.admin_tasks && summaryData.admin_tasks.length > 0 ? (
                                                        <div>
                                                            <div className="mb-6">
                                                                <h3 className={`text-2xl font-bold mb-2 flex items-center ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                                    <i className="fas fa-tasks text-indigo-600 mr-3"></i>
                                                                    Recommended Implementation Tasks
                                                                </h3>
                                                                <p className={isDarkTheme ? 'text-gray-300' : 'text-gray-600'}>
                                                                    Prioritized tasks based on your environment analysis. Each includes step-by-step guidance and verification queries.
                                                                </p>
                                                            </div>
                                                            
                                                            <div className="space-y-4">
                                                                {summaryData.admin_tasks.map((task, idx) => {
                                                                    const progress = getTaskProgress(currentSessionId, idx);
                                                                    const completionPct = getTaskCompletionPercentage(currentSessionId, idx, task.steps?.length || 0);
                                                                    
                                                                    return (
                                                                    <div key={idx} className={`border-2 rounded-lg overflow-hidden transition-all ${
                                                                        progress.status === 'completed' ? (isDarkTheme ? 'border-green-600 bg-green-950 opacity-95' : 'border-green-400 bg-green-50 opacity-90') :
                                                                        progress.status === 'in-progress' ? (isDarkTheme ? 'border-indigo-600 bg-indigo-950' : 'border-indigo-400 bg-indigo-50') :
                                                                        task.priority === 'HIGH' ? (isDarkTheme ? 'border-red-700 bg-red-950' : 'border-red-300 bg-red-50') :
                                                                        task.priority === 'MEDIUM' ? (isDarkTheme ? 'border-orange-700 bg-orange-950' : 'border-orange-300 bg-orange-50') :
                                                                        (isDarkTheme ? 'border-yellow-700 bg-yellow-950' : 'border-yellow-300 bg-yellow-50')
                                                                    }`}>
                                                                        {/* Task Header */}
                                                                        <div className={`p-5 border-b ${isDarkTheme ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                                            <div className="flex items-start justify-between mb-3">
                                                                                <div className="flex-1">
                                                                                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                                                                                        {/* Status Badge */}
                                                                                        {progress.status === 'completed' && (
                                                                                            <span className="px-3 py-1 text-xs font-bold rounded-full bg-green-600 text-white">
                                                                                                ✓ COMPLETED
                                                                                            </span>
                                                                                        )}
                                                                                        {progress.status === 'in-progress' && (
                                                                                            <span className="px-3 py-1 text-xs font-bold rounded-full bg-indigo-600 text-white animate-pulse">
                                                                                                ⟳ IN PROGRESS
                                                                                            </span>
                                                                                        )}
                                                                                        
                                                                                        {/* Priority Badge */}
                                                                                        <span className={`px-3 py-1 text-xs font-bold rounded-full ${
                                                                                            task.priority === 'HIGH' ? 'bg-red-600 text-white' :
                                                                                            task.priority === 'MEDIUM' ? 'bg-orange-600 text-white' :
                                                                                            'bg-yellow-500 text-gray-900'
                                                                                        }`}>
                                                                                            {task.priority === 'HIGH' ? '🔴 HIGH' : 
                                                                                             task.priority === 'MEDIUM' ? '🟠 MEDIUM' : '🟡 LOW'} PRIORITY
                                                                                        </span>
                                                                                        
                                                                                        {/* Category Badge */}
                                                                                        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                                                                                            task.category === 'Security' ? (isDarkTheme ? 'bg-red-900 text-red-200' : 'bg-red-100 text-red-700') :
                                                                                            task.category === 'Performance' ? (isDarkTheme ? 'bg-blue-900 text-blue-200' : 'bg-blue-100 text-blue-700') :
                                                                                            task.category === 'Compliance' ? (isDarkTheme ? 'bg-purple-900 text-purple-200' : 'bg-purple-100 text-purple-700') :
                                                                                            task.category === 'Data Quality' ? (isDarkTheme ? 'bg-green-900 text-green-200' : 'bg-green-100 text-green-700') :
                                                                                            (isDarkTheme ? 'bg-gray-700 text-gray-200' : 'bg-gray-100 text-gray-700')
                                                                                        }`}>
                                                                                            {task.category}
                                                                                        </span>
                                                                                        
                                                                                        {/* Time Estimate */}
                                                                                        {task.estimated_time && (
                                                                                            <span className={`px-2 py-1 text-xs rounded-full ${isDarkTheme ? 'bg-indigo-900 text-indigo-200' : 'bg-indigo-100 text-indigo-700'}`}>
                                                                                                <i className="fas fa-clock mr-1"></i>
                                                                                                {task.estimated_time}
                                                                                            </span>
                                                                                        )}
                                                                                    </div>
                                                                                    
                                                                                    <h4 className={`text-xl font-bold mb-2 ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>{task.title}</h4>
                                                                                    <p className={`text-sm ${isDarkTheme ? 'text-gray-300' : 'text-gray-700'}`}>{task.description}</p>
                                                                                    
                                                                                    {/* Progress Bar */}
                                                                                    <div className="mt-3">
                                                                                        <div className={`flex items-center justify-between text-xs mb-1 ${isDarkTheme ? 'text-gray-400' : 'text-gray-600'}`}>
                                                                                            <span className="font-medium">Progress: {completionPct}%</span>
                                                                                            <span>{progress.completedSteps.length} / {task.steps?.length || 0} steps</span>
                                                                                        </div>
                                                                                        <div className={`w-full rounded-full h-2 overflow-hidden ${isDarkTheme ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                                                                            <div 
                                                                                                className={`h-full rounded-full transition-all duration-500 ${
                                                                                                    completionPct === 100 ? 'bg-green-500' :
                                                                                                    completionPct > 0 ? 'bg-indigo-500' : 'bg-gray-300'
                                                                                                }`}
                                                                                                style={{width: `${completionPct}%`}}
                                                                                            ></div>
                                                                                        </div>
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                            
                                                                            {/* Impact */}
                                                                            {task.impact && (
                                                                                <div className={`mt-3 p-3 border-l-4 rounded-r ${isDarkTheme ? 'bg-green-950 border-green-600' : 'bg-green-50 border-green-500'}`}>
                                                                                    <p className={`text-sm ${isDarkTheme ? 'text-green-200' : 'text-green-900'}`}>
                                                                                        <i className="fas fa-chart-line mr-2"></i>
                                                                                        <strong>Impact:</strong> {task.impact}
                                                                                    </p>
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Task Details - Expandable */}
                                                                        <details className="group" open={progress.status === 'in-progress'}>
                                                                            <summary className={`cursor-pointer px-5 py-3 transition-colors list-none flex items-center justify-between ${isDarkTheme ? 'bg-gradient-to-r from-indigo-950 to-purple-950 hover:from-indigo-900 hover:to-purple-900' : 'bg-gradient-to-r from-indigo-50 to-purple-50 hover:from-indigo-100 hover:to-purple-100'}`}>
                                                                                <span className={`font-semibold flex items-center ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                                                    <i className="fas fa-chevron-right mr-2 group-open:rotate-90 transition-transform"></i>
                                                                                    Implementation Steps
                                                                                </span>
                                                                                <span className={`text-sm ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                                                                    {task.steps?.length || 0} steps
                                                                                </span>
                                                                            </summary>
                                                                            
                                                                            <div className={`p-5 space-y-4 ${isDarkTheme ? 'bg-gray-900' : 'bg-white'}`}>
                                                                                {/* Prerequisites */}
                                                                                {task.prerequisites && task.prerequisites.length > 0 && (
                                                                                    <div className="mb-4">
                                                                                        <h5 className={`font-semibold mb-2 flex items-center ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                                                            <i className="fas fa-list-check mr-2 text-blue-600"></i>
                                                                                            Prerequisites
                                                                                        </h5>
                                                                                        <ul className="space-y-1">
                                                                                            {task.prerequisites.map((prereq, pIdx) => (
                                                                                                <li key={pIdx} className={`text-sm flex items-start ${isDarkTheme ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                                                    <i className="fas fa-angle-right mr-2 mt-1 text-blue-500"></i>
                                                                                                    <span>{prereq}</span>
                                                                                                </li>
                                                                                            ))}
                                                                                        </ul>
                                                                                    </div>
                                                                                )}
                                                                                
                                                                                {/* Implementation Steps with Checkboxes */}
                                                                                <div>
                                                                                    <h5 className={`font-semibold mb-3 flex items-center ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                                                                        <i className="fas fa-clipboard-list mr-2 text-indigo-600"></i>
                                                                                        Implementation Steps
                                                                                    </h5>
                                                                                    <div className="space-y-3">
                                                                                        {task.steps?.map((step, sIdx) => {
                                                                                            const isCompleted = progress.completedSteps.includes(step.number);
                                                                                            
                                                                                            return (
                                                                                            <div key={sIdx} className={`border-2 rounded-lg p-4 transition-all ${
                                                                                                isCompleted ? (isDarkTheme ? 'border-green-700 bg-green-950' : 'border-green-300 bg-green-50') : (isDarkTheme ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-gray-50')
                                                                                            }`}>
                                                                                                <div className="flex items-start gap-3">
                                                                                                    {/* Checkbox */}
                                                                                                    <input 
                                                                                                        type="checkbox"
                                                                                                        checked={isCompleted}
                                                                                                        onChange={() => toggleStepCompletion(currentSessionId, idx, step.number)}
                                                                                                        className="mt-1 w-5 h-5 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500 cursor-pointer"
                                                                                                    />
                                                                                                    
                                                                                                    <div className="flex-shrink-0 w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-sm">
                                                                                                        {isCompleted ? '✓' : step.number}
                                                                                                    </div>
                                                                                                    <div className="flex-1">
                                                                                                        <p className={`text-sm font-medium ${
                                                                                                            isCompleted ? (isDarkTheme ? 'text-gray-500 line-through' : 'text-gray-500 line-through') : (isDarkTheme ? 'text-gray-100' : 'text-gray-900')
                                                                                                        }`}>{step.action}</p>
                                                                                                    </div>
                                                                                                </div>
                                                                                                
                                                                                                {/* SPL Query for this step */}
                                                                                                {step.spl && (
                                                                                                    <div className="mt-3 ml-16">
                                                                                                        <div className="flex items-center justify-between mb-1">
                                                                                                            <span className={`text-xs font-semibold ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>SPL Query:</span>
                                                                                                            <button
                                                                                                                onClick={() => copyToClipboard(step.spl, 'Step SPL')}
                                                                                                                className="px-2 py-1 bg-gray-700 hover:bg-gray-800 text-white rounded text-xs"
                                                                                                            >
                                                                                                                <i className="fas fa-copy mr-1"></i>
                                                                                                                Copy
                                                                                                            </button>
                                                                                                        </div>
                                                                                                        <pre className="p-3 bg-gray-900 text-green-400 rounded text-xs overflow-x-auto">
{step.spl}
                                                                                                        </pre>
                                                                                                    </div>
                                                                                                )}
                                                                                            </div>
                                                                                        )})}
                                                                                    </div>
                                                                                </div>
                                                                                
                                                                                {/* Verification */}
                                                                                {task.verification_spl && (
                                                                                    <div className="mt-4">
                                                                                        <div className={`p-4 border-l-4 rounded-r ${isDarkTheme ? 'bg-blue-950 border-blue-600' : 'bg-blue-50 border-blue-500'}`}>
                                                                                            <div className="flex items-center justify-between mb-2">
                                                                                                <h5 className={`font-semibold flex items-center ${isDarkTheme ? 'text-blue-200' : 'text-blue-900'}`}>
                                                                                                    <i className="fas fa-check-circle mr-2"></i>
                                                                                                    Verification
                                                                                                </h5>
                                                                                                <button
                                                                                                    onClick={() => runVerification(currentSessionId, idx, task)}
                                                                                                    disabled={verifyingTask === idx}
                                                                                                    className={`px-4 py-2 rounded-lg font-medium text-sm transition-all ${
                                                                                                        verifyingTask === idx
                                                                                                            ? 'bg-gray-400 text-white cursor-not-allowed'
                                                                                                            : 'bg-blue-600 hover:bg-blue-700 text-white shadow-sm hover:shadow'
                                                                                                    }`}
                                                                                                >
                                                                                                    {verifyingTask === idx ? (
                                                                                                        <>
                                                                                                            <i className="fas fa-spinner fa-spin mr-2"></i>
                                                                                                            Verifying...
                                                                                                        </>
                                                                                                    ) : (
                                                                                                        <>
                                                                                                            <i className="fas fa-play-circle mr-2"></i>
                                                                                                            Run Verification
                                                                                                        </>
                                                                                                    )}
                                                                                                </button>
                                                                                            </div>
                                                                                            
                                                                                            <p className={`text-sm mb-2 ${isDarkTheme ? 'text-blue-300' : 'text-blue-800'}`}>
                                                                                                <strong>Expected Outcome:</strong> {task.expected_outcome}
                                                                                            </p>
                                                                                            
                                                                                            <details className="mt-2">
                                                                                                <summary className={`cursor-pointer text-xs font-semibold ${isDarkTheme ? 'text-blue-300 hover:text-blue-200' : 'text-blue-700 hover:text-blue-900'}`}>
                                                                                                    <i className="fas fa-code mr-1"></i>
                                                                                                    View Verification SPL
                                                                                                </summary>
                                                                                                <div className="mt-2 flex items-center justify-between mb-1">
                                                                                                    <span className={`text-xs ${isDarkTheme ? 'text-blue-300' : 'text-blue-700'}`}></span>
                                                                                                    <button
                                                                                                        onClick={() => copyToClipboard(task.verification_spl, 'Verification SPL')}
                                                                                                        className="px-2 py-1 bg-blue-700 hover:bg-blue-800 text-white rounded text-xs"
                                                                                                    >
                                                                                                        <i className="fas fa-copy mr-1"></i>
                                                                                                        Copy
                                                                                                    </button>
                                                                                                </div>
                                                                                                <pre className="p-3 bg-gray-900 text-green-400 rounded text-xs overflow-x-auto">
{task.verification_spl}
                                                                                                </pre>
                                                                                            </details>
                                                                                        </div>
                                                                                        
                                                                                        {/* Verification Results */}
                                                                                        {(() => {
                                                                                            const verResult = getVerificationResult(currentSessionId, idx);
                                                                                            if (!verResult) return null;
                                                                                            
                                                                                            return (
                                                                                                <div className={`mt-3 p-4 border-l-4 rounded-r fade-in ${
                                                                                                    verResult.status === 'success' ? 'bg-green-50 border-green-500' :
                                                                                                    verResult.status === 'partial' ? 'bg-yellow-50 border-yellow-500' :
                                                                                                    verResult.status === 'failed' ? 'bg-red-50 border-red-500' :
                                                                                                    'bg-gray-50 border-gray-500'
                                                                                                }`}>
                                                                                                    {/* Status Header */}
                                                                                                    <div className="flex items-center justify-between mb-3">
                                                                                                        <div className="flex items-center gap-2">
                                                                                                            {verResult.status === 'success' && (
                                                                                                                <span className="px-3 py-1 bg-green-600 text-white text-xs font-bold rounded-full">
                                                                                                                    ✓ SUCCESS
                                                                                                                </span>
                                                                                                            )}
                                                                                                            {verResult.status === 'partial' && (
                                                                                                                <span className="px-3 py-1 bg-yellow-500 text-gray-900 text-xs font-bold rounded-full">
                                                                                                                    ⚠ PARTIAL SUCCESS
                                                                                                                </span>
                                                                                                            )}
                                                                                                            {verResult.status === 'failed' && (
                                                                                                                <span className="px-3 py-1 bg-red-600 text-white text-xs font-bold rounded-full">
                                                                                                                    ✗ FAILED
                                                                                                                </span>
                                                                                                            )}
                                                                                                            {verResult.status === 'error' && (
                                                                                                                <span className="px-3 py-1 bg-gray-600 text-white text-xs font-bold rounded-full">
                                                                                                                    ⚠ ERROR
                                                                                                                </span>
                                                                                                            )}
                                                                                                        </div>
                                                                                                        <span className="text-xs text-gray-500">
                                                                                                            {new Date(verResult.timestamp).toLocaleString()}
                                                                                                        </span>
                                                                                                    </div>
                                                                                                    
                                                                                                    {/* Message */}
                                                                                                    <p className={`text-sm mb-3 ${
                                                                                                            verResult.status === 'success' ? (isDarkTheme ? 'text-green-200' : 'text-green-900') :
                                                                                                            verResult.status === 'partial' ? (isDarkTheme ? 'text-yellow-200' : 'text-yellow-900') :
                                                                                                            verResult.status === 'failed' ? (isDarkTheme ? 'text-red-200' : 'text-red-900') :
                                                                                                            (isDarkTheme ? 'text-gray-100' : 'text-gray-900')
                                                                                                    }`}>
                                                                                                        {verResult.message}
                                                                                                    </p>
                                                                                                    
                                                                                                    {/* Metrics */}
                                                                                                    {verResult.metrics && (
                                                                                                        <div className="bg-white rounded-lg p-3 mb-3">
                                                                                                            <h6 className="text-xs font-semibold text-gray-700 mb-2">Metrics:</h6>
                                                                                                            <div className="grid grid-cols-2 gap-2 text-xs">
                                                                                                                {verResult.metrics.current_value && (
                                                                                                                    <div>
                                                                                                                        <span className="text-gray-600">Current:</span>
                                                                                                                        <span className="ml-2 font-medium">{verResult.metrics.current_value}</span>
                                                                                                                    </div>
                                                                                                                )}
                                                                                                                {verResult.metrics.expected_value && (
                                                                                                                    <div>
                                                                                                                        <span className="text-gray-600">Expected:</span>
                                                                                                                        <span className="ml-2 font-medium">{verResult.metrics.expected_value}</span>
                                                                                                                    </div>
                                                                                                                )}
                                                                                                                {verResult.metrics.gap && (
                                                                                                                    <div className="col-span-2">
                                                                                                                        <span className="text-gray-600">Gap:</span>
                                                                                                                        <span className="ml-2 font-medium text-orange-700">{verResult.metrics.gap}</span>
                                                                                                                    </div>
                                                                                                                )}
                                                                                                            </div>
                                                                                                        </div>
                                                                                                    )}
                                                                                                    
                                                                                                    {/* Recommendations */}
                                                                                                    {verResult.recommendations && verResult.recommendations.length > 0 && (
                                                                                                        <div className="bg-white rounded-lg p-3 mb-3">
                                                                                                            <h6 className="text-xs font-semibold text-gray-700 mb-2 flex items-center">
                                                                                                                <i className="fas fa-lightbulb mr-1 text-yellow-600"></i>
                                                                                                                Recommendations:
                                                                                                            </h6>
                                                                                                            <ul className="space-y-1">
                                                                                                                {verResult.recommendations.map((rec, rIdx) => (
                                                                                                                    <li key={rIdx} className="text-xs text-gray-700 flex items-start">
                                                                                                                        <i className="fas fa-arrow-right mr-2 mt-0.5 text-blue-500"></i>
                                                                                                                        <span>{rec}</span>
                                                                                                                    </li>
                                                                                                                ))}
                                                                                                            </ul>
                                                                                                        </div>
                                                                                                    )}
                                                                                                    
                                                                                                    {/* Action Buttons for Failed/Partial */}
                                                                                                    {(verResult.status === 'failed' || verResult.status === 'partial') && (
                                                                                                        <div className="flex gap-2 mt-3">
                                                                                                            <button
                                                                                                                onClick={() => getRemediation(currentSessionId, idx, task, verResult)}
                                                                                                                disabled={loadingRemediation === idx}
                                                                                                                className="flex-1 px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-medium rounded disabled:opacity-50 disabled:cursor-not-allowed"
                                                                                                            >
                                                                                                                {loadingRemediation === idx ? (
                                                                                                                    <>
                                                                                                                        <i className="fas fa-spinner fa-spin mr-1"></i>
                                                                                                                        Analyzing...
                                                                                                                    </>
                                                                                                                ) : (
                                                                                                                    <>
                                                                                                                        <i className="fas fa-wrench mr-1"></i>
                                                                                                                        Get Remediation Help
                                                                                                                    </>
                                                                                                                )}
                                                                                                            </button>
                                                                                                            <button
                                                                                                                onClick={() => runVerification(currentSessionId, idx, task)}
                                                                                                                disabled={verifyingTask === idx}
                                                                                                                className="px-3 py-2 bg-green-600 hover:bg-green-700 text-white text-xs font-medium rounded disabled:opacity-50 disabled:cursor-not-allowed"
                                                                                                            >
                                                                                                                <i className="fas fa-redo mr-1"></i>
                                                                                                                Re-verify
                                                                                                            </button>
                                                                                                            <button
                                                                                                                onClick={() => {
                                                                                                                    loadVerificationHistory(currentSessionId, idx);
                                                                                                                    setShowHistory(showHistory === idx ? null : idx);
                                                                                                                }}
                                                                                                                className="px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-xs font-medium rounded"
                                                                                                            >
                                                                                                                <i className="fas fa-history mr-1"></i>
                                                                                                                History
                                                                                                            </button>
                                                                                                        </div>
                                                                                                    )}
                                                                                                    
                                                                                                    {/* Success - Show Re-verify and History */}
                                                                                                    {verResult.status === 'success' && (
                                                                                                        <div className="flex gap-2 mt-3">
                                                                                                            <button
                                                                                                                onClick={() => {
                                                                                                                    loadVerificationHistory(currentSessionId, idx);
                                                                                                                    setShowHistory(showHistory === idx ? null : idx);
                                                                                                                }}
                                                                                                                className="px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-xs font-medium rounded"
                                                                                                            >
                                                                                                                <i className="fas fa-history mr-1"></i>
                                                                                                                View History
                                                                                                            </button>
                                                                                                        </div>
                                                                                                    )}
                                                                                                    
                                                                                                    {/* Remediation Details */}
                                                                                                    {(() => {
                                                                                                        const remediation = remediationData[`${currentSessionId}_task${idx}`];
                                                                                                        if (!remediation) return null;
                                                                                                        
                                                                                                        return (
                                                                                                            <div className="mt-3 p-4 bg-gradient-to-r from-purple-50 to-indigo-50 border border-indigo-200 rounded-lg fade-in">
                                                                                                                <h6 className="text-sm font-bold text-indigo-900 mb-3 flex items-center">
                                                                                                                    <i className="fas fa-magic mr-2"></i>
                                                                                                                    AI-Powered Remediation Guide
                                                                                                                </h6>
                                                                                                                
                                                                                                                {/* Root Cause */}
                                                                                                                <div className="bg-white rounded-lg p-3 mb-3">
                                                                                                                    <h7 className="text-xs font-semibold text-gray-700 mb-1 flex items-center">
                                                                                                                        <i className="fas fa-search mr-1 text-red-600"></i>
                                                                                                                        Root Cause:
                                                                                                                    </h7>
                                                                                                                    <p className="text-xs text-gray-800">{remediation.root_cause}</p>
                                                                                                                </div>
                                                                                                                
                                                                                                                {/* Remediation Steps */}
                                                                                                                <div className="bg-white rounded-lg p-3 mb-3">
                                                                                                                    <h7 className="text-xs font-semibold text-gray-700 mb-2 flex items-center">
                                                                                                                        <i className="fas fa-list-ol mr-1 text-green-600"></i>
                                                                                                                        Remediation Steps:
                                                                                                                    </h7>
                                                                                                                    <div className="space-y-3">
                                                                                                                        {remediation.remediation_steps?.map((step, sIdx) => (
                                                                                                                            <div key={sIdx} className="border-l-2 border-indigo-300 pl-3">
                                                                                                                                <div className="flex items-start justify-between mb-1">
                                                                                                                                    <span className="text-xs font-medium text-gray-900">
                                                                                                                                        {step.number}. {step.action}
                                                                                                                                    </span>
                                                                                                                                    <span className={`px-2 py-0.5 text-xs rounded ${
                                                                                                                                        step.risk === 'low' ? 'bg-green-100 text-green-800' :
                                                                                                                                        step.risk === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                                                                                                                        'bg-red-100 text-red-800'
                                                                                                                                    }`}>
                                                                                                                                        {step.risk?.toUpperCase()} RISK
                                                                                                                                    </span>
                                                                                                                                </div>
                                                                                                                                {step.explanation && (
                                                                                                                                    <p className="text-xs text-gray-600 mb-2">{step.explanation}</p>
                                                                                                                                )}
                                                                                                                                {step.spl && (
                                                                                                                                    <pre className="bg-gray-900 text-green-400 p-2 rounded text-xs overflow-x-auto font-mono">
{step.spl}
                                                                                                                                    </pre>
                                                                                                                                )}
                                                                                                                            </div>
                                                                                                                        ))}
                                                                                                                    </div>
                                                                                                                </div>
                                                                                                                
                                                                                                                {/* Metadata */}
                                                                                                                <div className="grid grid-cols-2 gap-2 text-xs">
                                                                                                                    <div className="bg-white rounded p-2">
                                                                                                                        <span className="text-gray-600">Estimated Time:</span>
                                                                                                                        <span className="ml-1 font-medium">{remediation.estimated_time}</span>
                                                                                                                    </div>
                                                                                                                    <div className="bg-white rounded p-2">
                                                                                                                        <span className="text-gray-600">Success Probability:</span>
                                                                                                                        <span className={`ml-1 font-medium ${
                                                                                                                            remediation.success_probability === 'high' ? 'text-green-600' :
                                                                                                                            remediation.success_probability === 'medium' ? 'text-yellow-600' :
                                                                                                                            'text-red-600'
                                                                                                                        }`}>
                                                                                                                            {remediation.success_probability?.toUpperCase()}
                                                                                                                        </span>
                                                                                                                    </div>
                                                                                                                </div>
                                                                                                                
                                                                                                                {/* Preventive Measures */}
                                                                                                                {remediation.preventive_measures && remediation.preventive_measures.length > 0 && (
                                                                                                                    <details className="mt-3 bg-white rounded-lg p-3">
                                                                                                                        <summary className="text-xs font-semibold text-gray-700 cursor-pointer">
                                                                                                                            <i className="fas fa-shield-alt mr-1 text-blue-600"></i>
                                                                                                                            Preventive Measures
                                                                                                                        </summary>
                                                                                                                        <ul className="mt-2 space-y-1">
                                                                                                                            {remediation.preventive_measures.map((measure, mIdx) => (
                                                                                                                                <li key={mIdx} className="text-xs text-gray-700 flex items-start">
                                                                                                                                    <i className="fas fa-check-circle mr-2 mt-0.5 text-green-500"></i>
                                                                                                                                    <span>{measure}</span>
                                                                                                                                </li>
                                                                                                                            ))}
                                                                                                                        </ul>
                                                                                                                    </details>
                                                                                                                )}
                                                                                                            </div>
                                                                                                        );
                                                                                                    })()}
                                                                                                    
                                                                                                    {/* Verification History */}
                                                                                                    {showHistory === idx && (() => {
                                                                                                        const history = verificationHistory[`${currentSessionId}_task${idx}`];
                                                                                                        if (!history) return <div className="mt-3 text-xs text-gray-500">Loading history...</div>;
                                                                                                        
                                                                                                        return (
                                                                                                            <div className="mt-3 p-4 bg-gray-50 border border-gray-200 rounded-lg fade-in">
                                                                                                                <h6 className="text-sm font-bold text-gray-900 mb-3 flex items-center justify-between">
                                                                                                                    <span>
                                                                                                                        <i className="fas fa-history mr-2"></i>
                                                                                                                        Verification History
                                                                                                                    </span>
                                                                                                                    <button
                                                                                                                        onClick={() => setShowHistory(null)}
                                                                                                                        className="text-gray-500 hover:text-gray-700"
                                                                                                                    >
                                                                                                                        <i className="fas fa-times"></i>
                                                                                                                    </button>
                                                                                                                </h6>
                                                                                                                
                                                                                                                {/* Stats */}
                                                                                                                <div className="grid grid-cols-4 gap-2 mb-3">
                                                                                                                    <div className="bg-white rounded-lg p-2 text-center">
                                                                                                                        <div className="text-lg font-bold text-blue-600">{history.total_attempts}</div>
                                                                                                                        <div className="text-xs text-gray-600">Attempts</div>
                                                                                                                    </div>
                                                                                                                    <div className="bg-white rounded-lg p-2 text-center">
                                                                                                                        <div className="text-lg font-bold text-green-600">{history.successful_attempts}</div>
                                                                                                                        <div className="text-xs text-gray-600">Successful</div>
                                                                                                                    </div>
                                                                                                                    <div className="bg-white rounded-lg p-2 text-center">
                                                                                                                        <div className="text-lg font-bold text-purple-600">{Math.round(history.success_rate * 100)}%</div>
                                                                                                                        <div className="text-xs text-gray-600">Success Rate</div>
                                                                                                                    </div>
                                                                                                                    <div className="bg-white rounded-lg p-2 text-center">
                                                                                                                        <div className={`text-lg font-bold ${
                                                                                                                            history.improvement_trend === 'improving' ? 'text-green-600' :
                                                                                                                            history.improvement_trend === 'stable' ? 'text-blue-600' :
                                                                                                                            'text-red-600'
                                                                                                                        }`}>
                                                                                                                            {history.improvement_trend === 'improving' ? '↑' :
                                                                                                                             history.improvement_trend === 'stable' ? '→' : '↓'}
                                                                                                                        </div>
                                                                                                                        <div className="text-xs text-gray-600">Trend</div>
                                                                                                                    </div>
                                                                                                                </div>
                                                                                                                
                                                                                                                {history.time_to_success && (
                                                                                                                    <div className="bg-green-100 border border-green-300 rounded-lg p-2 mb-3 text-xs text-green-800">
                                                                                                                        <i className="fas fa-clock mr-1"></i>
                                                                                                                        Time to success: <span className="font-semibold">{history.time_to_success}</span>
                                                                                                                    </div>
                                                                                                                )}
                                                                                                                
                                                                                                                {/* Timeline */}
                                                                                                                <div className="space-y-2 max-h-60 overflow-y-auto">
                                                                                                                    {history.verifications?.map((ver, vIdx) => (
                                                                                                                        <div key={vIdx} className="bg-white rounded-lg p-2 border-l-4 ${
                                                                                                                            ver.status === 'success' ? 'border-green-500' :
                                                                                                                            ver.status === 'partial' ? 'border-yellow-500' :
                                                                                                                            'border-red-500'
                                                                                                                        }">
                                                                                                                            <div className="flex items-center justify-between mb-1">
                                                                                                                                <span className={`text-xs font-semibold ${
                                                                                                                                    ver.status === 'success' ? 'text-green-700' :
                                                                                                                                    ver.status === 'partial' ? 'text-yellow-700' :
                                                                                                                                    'text-red-700'
                                                                                                                                }`}>
                                                                                                                                    Attempt #{vIdx + 1} - {ver.status?.toUpperCase()}
                                                                                                                                </span>
                                                                                                                                <span className="text-xs text-gray-500">
                                                                                                                                    {new Date(ver.timestamp).toLocaleString()}
                                                                                                                                </span>
                                                                                                                            </div>
                                                                                                                            <p className="text-xs text-gray-700">{ver.message}</p>
                                                                                                                        </div>
                                                                                                                    ))}
                                                                                                                </div>
                                                                                                            </div>
                                                                                                        );
                                                                                                    })()}
                                                                                                </div>
                                                                                            );
                                                                                        })()}
                                                                                    </div>
                                                                                )}
                                                                                
                                                                                {/* Rollback */}
                                                                                {task.rollback && (
                                                                                    <div className="mt-4 p-3 bg-yellow-50 border-l-4 border-yellow-500 rounded-r">
                                                                                        <h5 className="font-semibold text-yellow-900 mb-1 flex items-center text-sm">
                                                                                            <i className="fas fa-undo mr-2"></i>
                                                                                            Rollback Instructions
                                                                                        </h5>
                                                                                        <p className="text-sm text-yellow-800">{task.rollback}</p>
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        </details>
                                                                    </div>
                                                                )})}
                                                            </div>
                                                        </div>
                                                    ) : (
                                                        <div className="text-center py-20">
                                                            <div className="inline-block p-6 bg-gradient-to-br from-indigo-50 to-purple-50 rounded-2xl mb-6">
                                                                <i className="fas fa-tools text-7xl text-indigo-400 mb-4"></i>
                                                            </div>
                                                            <h3 className="text-3xl font-bold text-gray-800 mb-3">
                                                                Generating Tasks...
                                                            </h3>
                                                            <p className="text-lg text-gray-600 mb-6 max-w-2xl mx-auto">
                                                                Admin tasks are being generated based on your environment analysis
                                                            </p>
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    ) : (
                                        <div className="text-center text-gray-500 py-12">
                                            <i className="fas fa-exclamation-circle text-4xl mb-4"></i>
                                            <p>No summary data available</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Settings Modal */}
                    {isSettingsOpen && config && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={closeSettings}>
                            <div className={`settings-modal-shell rounded-xl shadow-2xl w-full max-w-2xl h-5/6 flex flex-col ${isDarkTheme ? 'bg-gray-800' : 'bg-white'}`} onClick={(e) => e.stopPropagation()}>
                                {/* Header */}
                                <div className={`p-6 border-b flex justify-between items-center ${isDarkTheme ? 'border-gray-700' : 'border-gray-200'}`}>
                                    <div className="flex items-center">
                                        <i className="fas fa-cog text-2xl text-indigo-600 mr-3"></i>
                                        <h2 className={`text-xl font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>Settings</h2>
                                    </div>
                                    <button onClick={closeSettings} className={`${isDarkTheme ? 'text-gray-400 hover:text-gray-200' : 'text-gray-500 hover:text-gray-700'}`}>
                                        <i className="fas fa-times text-xl"></i>
                                    </button>
                                </div>

                                <div className={`px-6 py-4 border-b ${isDarkTheme ? 'border-gray-700 bg-gray-900' : 'border-gray-200 bg-gray-50'}`}>
                                    <div className="flex items-center justify-between mb-3">
                                        <h3 className={`text-sm font-semibold ${isDarkTheme ? 'text-gray-100' : 'text-gray-900'}`}>
                                            <i className="fas fa-adjust mr-2 text-indigo-600"></i>
                                            Appearance Theme
                                        </h3>
                                        <span className={`text-xs ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                            Active: {resolvedTheme}
                                        </span>
                                    </div>
                                    <div className={`inline-flex rounded-lg border overflow-hidden ${isDarkTheme ? 'border-gray-600' : 'border-gray-300'}`} role="group" aria-label="Theme preference">
                                        <button
                                            onClick={() => setThemePreference('light')}
                                            className={`px-3 py-2 text-xs font-medium ${themePreference === 'light' ? 'bg-indigo-600 text-white' : (isDarkTheme ? 'bg-gray-800 text-gray-200 hover:bg-gray-700' : 'bg-white text-gray-700 hover:bg-gray-100')}`}
                                        >
                                            Light
                                        </button>
                                        <button
                                            onClick={() => setThemePreference('dark')}
                                            className={`px-3 py-2 text-xs font-medium border-l ${themePreference === 'dark' ? 'bg-indigo-600 text-white border-indigo-500' : (isDarkTheme ? 'bg-gray-800 text-gray-200 hover:bg-gray-700 border-gray-600' : 'bg-white text-gray-700 hover:bg-gray-100 border-gray-300')}`}
                                        >
                                            Dark
                                        </button>
                                        <button
                                            onClick={() => setThemePreference('system')}
                                            className={`px-3 py-2 text-xs font-medium border-l ${themePreference === 'system' ? 'bg-indigo-600 text-white border-indigo-500' : (isDarkTheme ? 'bg-gray-800 text-gray-200 hover:bg-gray-700 border-gray-600' : 'bg-white text-gray-700 hover:bg-gray-100 border-gray-300')}`}
                                        >
                                            System
                                        </button>
                                    </div>
                                    <p className={`text-xs mt-2 ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>
                                        System mode follows your OS appearance preference automatically.
                                    </p>
                                </div>
                                
                                {/* Scrollable Content */}
                                <div className="flex-1 overflow-y-auto p-6 space-y-6">
                                    {/* MCP Configuration Vault */}
                                    <div>
                                        <div className={`rounded-lg p-6 border-2 ${isDarkTheme ? 'bg-gray-800 border-green-700' : 'bg-gradient-to-r from-green-50 to-emerald-50 border-green-200'}`}>
                                            {/* Header */}
                                            <div className="mb-4">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                                                    <i className="fas fa-server mr-2 text-green-600"></i>
                                                    MCP Server Configurations
                                                </h3>
                                                <p className="text-sm text-gray-600">Manage your Splunk MCP server connections</p>
                                            </div>
                                            
                                            {/* Currently Loaded Indicator */}
                                            {(loadedMCPConfigName || config?.active_mcp_config_name) && (
                                                <div className="mb-4 bg-emerald-50 border-l-4 border-emerald-500 rounded-r-lg p-3">
                                                    <div className="flex items-center justify-between">
                                                        <div className="flex items-center gap-2">
                                                            <i className="fas fa-check-circle text-emerald-600"></i>
                                                            <div>
                                                                <p className="text-sm font-semibold text-gray-900">Active Configuration:</p>
                                                                <p className="text-base font-bold text-gray-800">{loadedMCPConfigName || config?.active_mcp_config_name}</p>
                                                            </div>
                                                        </div>
                                                        <button
                                                            onClick={() => {
                                                                setLoadedMCPConfigName(null);
                                                                setShowMCPConfigForm(false);
                                                            }}
                                                            className="text-emerald-600 hover:text-emerald-800 text-sm font-medium"
                                                            title="Clear and close editor"
                                                        >
                                                            <i className="fas fa-times-circle mr-1"></i>Close
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {/* Action Button - Create New Configuration */}
                                            {!showMCPConfigForm && (
                                                <div className="mb-4">
                                                    <button
                                                        onClick={() => {
                                                            setShowMCPConfigForm(true);
                                                            setLoadedMCPConfigName(null);
                                                            setMCPTokenPlaceholder('Enter token');
                                                        }}
                                                        className="w-full px-4 py-3 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white rounded-lg font-bold shadow-md hover:shadow-lg transition-all transform hover:scale-[1.02]"
                                                    >
                                                        <i className="fas fa-plus-circle mr-2"></i>Create New Configuration
                                                    </button>
                                                </div>
                                            )}
                                            
                                            {/* Saved Configurations List */}
                                            <div id="mcp-configs-list" className="space-y-2 max-h-96 overflow-y-auto">
                                                <div className="text-sm text-gray-500 text-center py-4 italic">Loading configurations...</div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* MCP Configuration Form - Conditional */}
                                    {showMCPConfigForm && (
                                        <div>
                                            <div className="flex items-center justify-between mb-3">
                                                <h3 className="text-lg font-semibold text-gray-900">
                                                    <i className="fas fa-server mr-2 text-green-600"></i>
                                                    {loadedMCPConfigName ? 'Edit Configuration' : 'New Configuration'}
                                                </h3>
                                                <button
                                                    onClick={() => {
                                                        setShowMCPConfigForm(false);
                                                        setLoadedMCPConfigName(null);
                                                    }}
                                                    className="px-3 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded transition-colors"
                                                >
                                                    <i className="fas fa-times mr-1"></i>Cancel
                                                </button>
                                            </div>
                                            <div className="space-y-3">
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">MCP URL</label>
                                                    <input 
                                                        type="text" 
                                                        defaultValue={config.mcp.url}
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="mcp-url"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">Token</label>
                                                    <input 
                                                        type="password" 
                                                        placeholder={mcpTokenPlaceholder}
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="mcp-token"
                                                        onChange={() => setMCPTokenPlaceholder('Enter token')}
                                                    />
                                                </div>
                                                <div className="flex items-center">
                                                    <input 
                                                        type="checkbox" 
                                                        checked={config.mcp.verify_ssl}
                                                        onChange={(e) => setConfig({...config, mcp: {...config.mcp, verify_ssl: e.target.checked}})}
                                                        className="mr-2"
                                                        id="mcp-verify-ssl"
                                                    />
                                                    <label htmlFor="mcp-verify-ssl" className="text-sm text-gray-700">Verify SSL Certificate</label>
                                                </div>
                                                
                                                {/* Test & Save Buttons */}
                                                <div className="pt-3 border-t border-gray-200 space-y-2">
                                                    <button
                                                        onClick={async () => {
                                                            const urlEl = document.getElementById('mcp-url');
                                                            const tokenEl = document.getElementById('mcp-token');
                                                            const verifySslEl = document.getElementById('mcp-verify-ssl');
                                                            
                                                            const testUrl = urlEl?.value || config.mcp.url;
                                                            const testToken = tokenEl?.value || config.mcp.token;
                                                            const testVerifySsl = verifySslEl?.checked ?? config.mcp.verify_ssl;
                                                            
                                                            if (!testUrl) {
                                                                alert('Please enter an MCP URL');
                                                                return;
                                                            }
                                                            
                                                            const button = event.target.closest('button');
                                                            const originalHTML = button.innerHTML;
                                                            button.disabled = true;
                                                            button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Testing...';
                                                            
                                                            try {
                                                                const response = await fetch('/api/mcp-configs/test', {
                                                                    method: 'POST',
                                                                    headers: {'Content-Type': 'application/json'},
                                                                    body: JSON.stringify({
                                                                        url: testUrl,
                                                                        token: testToken,
                                                                        verify_ssl: testVerifySsl
                                                                    })
                                                                });
                                                                
                                                                const result = await response.json();
                                                                
                                                                if (result.status === 'success') {
                                                                    alert('✅ ' + result.message);
                                                                } else {
                                                                    alert('⚠️ ' + result.message);
                                                                }
                                                            } catch (error) {
                                                                alert('❌ Test failed: ' + error.message);
                                                            } finally {
                                                                button.disabled = false;
                                                                button.innerHTML = originalHTML;
                                                            }
                                                        }}
                                                        className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
                                                    >
                                                        <i className="fas fa-network-wired mr-2"></i>Test Connection
                                                    </button>
                                                    
                                                    {/* Save Buttons */}
                                                    {loadedMCPConfigName ? (
                                                        <>
                                                            <button
                                                                onClick={() => {
                                                                    setMCPConfigName('');
                                                                    setIsMCPSaveModalOpen(true);
                                                                }}
                                                                className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
                                                            >
                                                                <i className="fas fa-plus-circle mr-2"></i>Save as New
                                                            </button>
                                                            <button
                                                                onClick={() => {
                                                                    setMCPConfigName(loadedMCPConfigName);
                                                                    setIsMCPSaveModalOpen(true);
                                                                }}
                                                                className="w-full px-4 py-2 bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 rounded-lg font-bold border-2 border-amber-600 shadow-md hover:shadow-lg transition-all"
                                                            >
                                                                <i className="fas fa-sync-alt mr-2"></i>Update Active Configuration
                                                            </button>
                                                        </>
                                                    ) : (
                                                        <button
                                                            onClick={() => {
                                                                setMCPConfigName('');
                                                                setIsMCPSaveModalOpen(true);
                                                            }}
                                                            className="w-full px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white rounded-lg font-bold shadow-md hover:shadow-lg transition-all"
                                                        >
                                                            <i className="fas fa-save mr-2"></i>Save as New Configuration
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* LLM Credential Vault - Show First */}
                                    <div>
                                        <div className={`rounded-lg p-6 border-2 ${isDarkTheme ? 'bg-gray-800 border-purple-700' : 'bg-gradient-to-r from-purple-50 to-indigo-50 border-purple-200'}`}>
                                            {/* Header */}
                                            <div className="mb-4">
                                                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                                                    <i className="fas fa-key mr-2 text-purple-600"></i>
                                                    LLM Credentials
                                                </h3>
                                                <p className="text-sm text-gray-600">Manage your AI model connections</p>
                                            </div>
                                            
                                            {/* Currently Loaded Indicator */}
                                            {(loadedCredentialName || config?.active_credential_name) && (
                                                <div className="mb-4 bg-amber-50 border-l-4 border-amber-500 rounded-r-lg p-3">
                                                    <div className="flex items-center justify-between">
                                                        <div className="flex items-center gap-2">
                                                            <i className="fas fa-check-circle text-amber-600"></i>
                                                            <div>
                                                                <p className="text-sm font-semibold text-gray-900">Active Connection:</p>
                                                                <p className="text-base font-bold text-gray-800">{loadedCredentialName || config?.active_credential_name}</p>
                                                            </div>
                                                        </div>
                                                        <button
                                                            onClick={() => {
                                                                setLoadedCredentialName(null);
                                                                setShowConfigForm(false);
                                                            }}
                                                            className="text-amber-600 hover:text-amber-800 text-sm font-medium"
                                                            title="Clear and close editor"
                                                        >
                                                            <i className="fas fa-times-circle mr-1"></i>Close
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {/* Action Button - Create New Connection */}
                                            {!showConfigForm && (
                                                <div className="mb-4">
                                                    <button
                                                        onClick={() => {
                                                            setShowConfigForm(true);
                                                            setLoadedCredentialName(null);
                                                            setApiKeyPlaceholder('Enter API key');
                                                        }}
                                                        className="w-full px-4 py-3 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white rounded-lg font-bold shadow-md hover:shadow-lg transition-all transform hover:scale-[1.02]"
                                                    >
                                                        <i className="fas fa-plus-circle mr-2"></i>Create New Connection
                                                    </button>
                                                </div>
                                            )}
                                            
                                            {/* Saved Credentials List */}
                                            <div id="credentials-list" className="space-y-2 max-h-96 overflow-y-auto">
                                                <div className="text-sm text-gray-500 text-center py-4 italic">Loading credentials...</div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* LLM Configuration Form - Conditional */}
                                    {showConfigForm && (
                                        <div>
                                            <div className="flex items-center justify-between mb-3">
                                                <h3 className="text-lg font-semibold text-gray-900">
                                                    <i className="fas fa-brain mr-2 text-purple-600"></i>
                                                    {loadedCredentialName ? 'Edit Connection' : 'New Connection'}
                                                </h3>
                                                <button
                                                    onClick={() => {
                                                        setShowConfigForm(false);
                                                        setLoadedCredentialName(null);
                                                    }}
                                                    className="px-3 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded transition-colors"
                                                >
                                                    <i className="fas fa-times mr-1"></i>Cancel
                                                </button>
                                            </div>
                                            <div className="space-y-3">
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">Provider</label>
                                                    <select 
                                                        value={selectedProvider}
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="llm-provider"
                                                        onChange={(e) => {
                                                            setSelectedProvider(e.target.value);
                                                            handleSettingsChange();
                                                        }}
                                                    >
                                                        <option value="openai">OpenAI</option>
                                                        <option value="azure">Azure OpenAI</option>
                                                        <option value="anthropic">Anthropic (Claude)</option>
                                                        <option value="gemini">Google Gemini</option>
                                                        <option value="custom">Custom Endpoint</option>
                                                    </select>
                                                </div>
                                            {selectedProvider !== 'openai' && (
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                                        Endpoint URL
                                                        <span className="ml-2 text-xs text-gray-500">
                                                            ({selectedProvider === 'custom' ? 'used exactly as configured' : 'base URL or full API path'})
                                                        </span>
                                                    </label>
                                                    <input 
                                                        type="text" 
                                                        defaultValue={config.llm.endpoint_url || ''}
                                                        placeholder={
                                                            selectedProvider === 'azure' ? 'https://YOUR-RESOURCE.openai.azure.com' :
                                                            selectedProvider === 'anthropic' ? 'https://api.anthropic.com (optional)' :
                                                            selectedProvider === 'gemini' ? 'https://generativelanguage.googleapis.com (optional)' :
                                                            'http://localhost:8000/v1/chat/completions'
                                                        }
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="llm-endpoint-url"
                                                        onChange={handleSettingsChange}
                                                    />
                                                    {selectedProvider === 'custom' && (
                                                        <p className="mt-1 text-xs text-gray-500">
                                                            ✅ <strong>Full API Path (Recommended):</strong> <span className="font-mono">http://localhost:8000/v1/chat/completions</span><br/>
                                                            ⚠️ <strong>Base URL (Slower):</strong> <span className="font-mono">http://localhost:8000</span> - requires auto-detection<br/>
                                                            <span className="italic">URL is used exactly as entered. No automatic path manipulation.</span>
                                                        </p>
                                                    )}
                                                </div>
                                            )}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-1">
                                                    API Key
                                                    {selectedProvider === 'custom' && (
                                                        <span className="ml-2 text-xs text-gray-500">(Optional for local LLMs)</span>
                                                    )}
                                                </label>
                                                <input 
                                                    type="password" 
                                                    placeholder={apiKeyPlaceholder}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="llm-api-key"
                                                    onChange={handleApiKeyChange}
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-1">
                                                    Model
                                                    <button
                                                        onClick={async () => {
                                                            setIsLoadingModels(true);
                                                            try {
                                                                const provider = document.getElementById('llm-provider').value;
                                                                const apiKey = document.getElementById('llm-api-key').value;
                                                                const endpointUrl = document.getElementById('llm-endpoint-url')?.value;
                                                                
                                                                const response = await fetch('/api/llm/list-models', {
                                                                    method: 'POST',
                                                                    headers: { 'Content-Type': 'application/json' },
                                                                    body: JSON.stringify({
                                                                        provider: provider,
                                                                        api_key: apiKey,
                                                                        endpoint_url: endpointUrl
                                                                    })
                                                                });
                                                                
                                                                if (response.ok) {
                                                                    const data = await response.json();
                                                                    setAvailableModels(data.models);
                                                                    if (data.models.length > 0) {
                                                                        setSelectedModel(data.models[0]);
                                                                    }
                                                                } else {
                                                                    const error = await response.json();
                                                                    alert('Failed to fetch models: ' + error.detail);
                                                                }
                                                            } catch (error) {
                                                                alert('Error fetching models: ' + error.message);
                                                            } finally {
                                                                setIsLoadingModels(false);
                                                            }
                                                        }}
                                                        className="ml-2 px-2 py-1 text-xs bg-purple-100 hover:bg-purple-200 text-purple-700 rounded disabled:opacity-50"
                                                        disabled={isLoadingModels}
                                                        type="button"
                                                    >
                                                        <i className={`fas ${isLoadingModels ? 'fa-spinner fa-spin' : 'fa-download'}`}></i> {isLoadingModels ? 'Fetching...' : 'Fetch Models'}
                                                    </button>
                                                </label>
                                                {availableModels.length > 0 ? (
                                                    <select
                                                        value={selectedModel}
                                                        onChange={(e) => {
                                                            setSelectedModel(e.target.value);
                                                            handleSettingsChange();
                                                        }}
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="llm-model"
                                                    >
                                                        {availableModels.map(model => (
                                                            <option key={model} value={model}>{model}</option>
                                                        ))}
                                                    </select>
                                                ) : (
                                                    <input 
                                                        type="text" 
                                                        defaultValue={config.llm.model}
                                                        placeholder={
                                                            selectedProvider === 'openai' ? 'gpt-4o' :
                                                            selectedProvider === 'azure' ? 'your-azure-deployment-name' :
                                                            selectedProvider === 'anthropic' ? 'claude-3-5-sonnet-latest' :
                                                            selectedProvider === 'gemini' ? 'gemini-1.5-pro' :
                                                            'e.g., llama3.2:3b'
                                                        }
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="llm-model"
                                                        onChange={handleSettingsChange}
                                                    />
                                                )}
                                                {selectedProvider !== 'openai' && (
                                                    <p className="mt-1 text-xs text-gray-500 italic">
                                                        Tip: Click "Fetch Models" to query provider model/deployment inventory where supported
                                                    </p>
                                                )}
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-1">
                                                    Max Tokens
                                                    <button 
                                                        onClick={async () => {
                                                            const btn = event.target;
                                                            btn.disabled = true;
                                                            btn.innerHTML = '<i className="fas fa-spinner fa-spin"></i> Testing...';
                                                            try {
                                                                const response = await fetch('/api/llm/assess-max-tokens', { method: 'POST' });
                                                                const result = await response.json();
                                                                document.getElementById('llm-max-tokens').value = result.recommended_max_tokens;
                                                                btn.innerHTML = '<i className="fas fa-check"></i> Done';
                                                                setTimeout(() => {
                                                                    btn.disabled = false;
                                                                    btn.innerHTML = '<i className="fas fa-magic"></i> Auto-Assess';
                                                                }, 2000);
                                                            } catch (error) {
                                                                btn.innerHTML = '<i className="fas fa-times"></i> Failed';
                                                                setTimeout(() => {
                                                                    btn.disabled = false;
                                                                    btn.innerHTML = '<i className="fas fa-magic"></i> Auto-Assess';
                                                                }, 2000);
                                                            }
                                                        }}
                                                        className="ml-2 px-2 py-1 text-xs bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded"
                                                    >
                                                        <i className="fas fa-magic"></i> Auto-Assess
                                                    </button>
                                                </label>
                                                <input 
                                                    type="number" 
                                                    defaultValue={config.llm.max_tokens}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="llm-max-tokens"
                                                    onChange={handleSettingsChange}
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-1">Temperature</label>
                                                <input 
                                                    type="number" 
                                                    step="0.1"
                                                    defaultValue={config.llm.temperature}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="llm-temperature"
                                                    onChange={handleSettingsChange}
                                                />
                                            </div>
                                            
                                            {/* Test Connection Button */}
                                            <div className="pt-3 border-t border-gray-200">
                                                <button
                                                    onClick={async () => {
                                                        const btn = event.target;
                                                        const resultsDiv = document.getElementById('llm-test-results');
                                                        
                                                        btn.disabled = true;
                                                        btn.innerHTML = '<i className="fas fa-spinner fa-spin mr-2"></i> Testing Connection...';
                                                        resultsDiv.innerHTML = '<div className="text-blue-600"><i className="fas fa-spinner fa-spin mr-2"></i> Running tests...</div>';
                                                        resultsDiv.style.display = 'block';
                                                        
                                                        try {
                                                            // First save current settings
                                                            const provider = document.getElementById('llm-provider').value;
                                                            const endpointUrlInput = document.getElementById('llm-endpoint-url');
                                                            
                                                            await fetch('/api/config', {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify({
                                                                    llm: {
                                                                        provider: provider,
                                                                        api_key: document.getElementById('llm-api-key').value || undefined,
                                                                        model: document.getElementById('llm-model').value,
                                                                        endpoint_url: (provider !== 'openai' && endpointUrlInput) ? endpointUrlInput.value : undefined,
                                                                        max_tokens: parseInt(document.getElementById('llm-max-tokens').value),
                                                                        temperature: parseFloat(document.getElementById('llm-temperature').value)
                                                                    }
                                                                })
                                                            });
                                                            
                                                            // Then test the connection
                                                            const response = await fetch('/api/llm/test-connection', {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify({
                                                                    llm: {
                                                                        provider: provider,
                                                                        api_key: document.getElementById('llm-api-key').value || undefined,
                                                                        model: document.getElementById('llm-model').value,
                                                                        endpoint_url: (provider !== 'openai' && endpointUrlInput) ? endpointUrlInput.value : undefined,
                                                                        max_tokens: parseInt(document.getElementById('llm-max-tokens').value),
                                                                        temperature: parseFloat(document.getElementById('llm-temperature').value)
                                                                    }
                                                                })
                                                            });
                                                            const result = await response.json();
                                                            
                                                            let html = '<div className="space-y-2">';
                                                            
                                                            // Show URL cleaning notification if applicable
                                                            if (result.url_cleaned && result.original_endpoint) {
                                                                html += '<div className="bg-blue-100 border border-blue-300 rounded-lg p-3 mb-2">';
                                                                html += '<div className="font-semibold text-blue-800"><i className="fas fa-info-circle mr-2"></i>Endpoint URL Cleaned</div>';
                                                                html += '<div className="text-xs text-blue-700 mt-1">';
                                                                html += 'Removed API path from endpoint URL for proper testing.<br>';
                                                                html += '<span className="font-mono">From: ' + result.original_endpoint + '</span><br>';
                                                                html += '<span className="font-mono">To: ' + result.endpoint + '</span><br>';
                                                                html += '<span className="italic mt-1">Tip: Enter only the base URL (e.g., http://localhost:8000)</span>';
                                                                html += '</div>';
                                                                html += '</div>';
                                                            }
                                                            
                                                            // Overall status
                                                            if (result.status === 'success') {
                                                                html += '<div className="bg-green-100 border border-green-300 rounded-lg p-3 mb-2">';
                                                                html += '<div className="font-semibold text-green-800"><i className="fas fa-check-circle mr-2"></i>All Tests Passed!</div>';
                                                                html += '<div className="text-sm text-green-700 mt-1">' + result.message + '</div>';
                                                                html += '</div>';
                                                                
                                                                // Auto-apply recommended config
                                                                if (result.recommended_config) {
                                                                    document.getElementById('llm-max-tokens').value = result.recommended_config.max_tokens;
                                                                }
                                                            } else if (result.status === 'error') {
                                                                html += '<div className="bg-red-100 border border-red-300 rounded-lg p-3 mb-2">';
                                                                html += '<div className="font-semibold text-red-800"><i className="fas fa-times-circle mr-2"></i>Test Failed</div>';
                                                                html += '<div className="text-sm text-red-700 mt-1">' + (result.message || result.error) + '</div>';
                                                                html += '</div>';
                                                            }
                                                            
                                                            // Individual test results
                                                            html += '<div className="text-xs font-semibold text-gray-700 mb-1">Test Details:</div>';
                                                            
                                                            for (const [testName, testResult] of Object.entries(result.tests || {})) {
                                                                const statusIcon = testResult.status === 'success' ? 'check' : 
                                                                                 testResult.status === 'error' ? 'times' : 
                                                                                 testResult.status === 'warning' ? 'exclamation-triangle' : 'info-circle';
                                                                const statusColor = testResult.status === 'success' ? 'green' : 
                                                                                  testResult.status === 'error' ? 'red' : 
                                                                                  testResult.status === 'warning' ? 'yellow' : 'blue';
                                                                
                                                                html += `<div className="bg-${statusColor}-50 border border-${statusColor}-200 rounded p-2 mb-1">`;
                                                                html += `<div className="text-xs font-medium text-${statusColor}-800">`;
                                                                html += `<i className="fas fa-${statusIcon} mr-1"></i>${testName.charAt(0).toUpperCase() + testName.slice(1)}: ${testResult.message}`;
                                                                html += '</div>';
                                                                if (testResult.response_preview) {
                                                                    html += `<div className="text-xs text-gray-600 mt-1 italic">"${testResult.response_preview}"</div>`;
                                                                }
                                                                html += '</div>';
                                                            }
                                                            
                                                            html += '</div>';
                                                            resultsDiv.innerHTML = html;
                                                            
                                                            btn.innerHTML = '<i className="fas fa-check mr-2"></i> Test Complete';
                                                            setTimeout(() => {
                                                                btn.disabled = false;
                                                                btn.innerHTML = '<i className="fas fa-plug mr-2"></i> Test Connection & Auto-Configure';
                                                            }, 3000);
                                                            
                                                        } catch (error) {
                                                            resultsDiv.innerHTML = `<div className="bg-red-100 border border-red-300 rounded-lg p-3">
                                                                <div className="font-semibold text-red-800"><i className="fas fa-times-circle mr-2"></i>Error</div>
                                                                <div className="text-sm text-red-700 mt-1">${error.message}</div>
                                                            </div>`;
                                                            btn.innerHTML = '<i className="fas fa-times mr-2"></i> Test Failed';
                                                            setTimeout(() => {
                                                                btn.disabled = false;
                                                                btn.innerHTML = '<i className="fas fa-plug mr-2"></i> Test Connection & Auto-Configure';
                                                            }, 3000);
                                                        }
                                                    }}
                                                    className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium"
                                                >
                                                    <i className="fas fa-plug mr-2"></i> Test Connection & Auto-Configure
                                                </button>
                                                <div id="llm-test-results" className="mt-3" style={{display: 'none'}}></div>
                                                
                                                {/* Save Buttons */}
                                                <div className="mt-3 pt-3 border-t border-gray-200 space-y-2">
                                                    {loadedCredentialName ? (
                                                        <>
                                                            <button
                                                                onClick={() => {
                                                                    setIsUpdateMode(false);
                                                                    setCredentialName('');
                                                                    setIsCredentialModalOpen(true);
                                                                }}
                                                                className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
                                                            >
                                                                <i className="fas fa-plus-circle mr-2"></i>Save as New
                                                            </button>
                                                            <button
                                                                onClick={() => {
                                                                    setIsUpdateMode(true);
                                                                    setCredentialName(loadedCredentialName);
                                                                    setIsCredentialModalOpen(true);
                                                                }}
                                                                className="w-full px-4 py-2 bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 rounded-lg font-bold border-2 border-amber-600 shadow-md hover:shadow-lg transition-all"
                                                            >
                                                                <i className="fas fa-sync-alt mr-2"></i>Update Active Connection
                                                            </button>
                                                        </>
                                                    ) : (
                                                        <button
                                                            onClick={() => {
                                                                setIsUpdateMode(false);
                                                                setCredentialName('');
                                                                setIsCredentialModalOpen(true);
                                                            }}
                                                            className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
                                                        >
                                                            <i className="fas fa-save mr-2"></i>Save Connection
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                                
                                {/* Footer */}
                                <div className={`p-6 border-t ${isDarkTheme ? 'border-gray-700 bg-gray-900' : 'border-gray-200 bg-gray-50'}`}>
                                    <div className="flex justify-between items-center">
                                        <button
                                            onClick={async () => {
                                                try {
                                                    const response = await fetch('/api/dependencies');
                                                    const data = await response.json();
                                                    
                                                    const depsWindow = window.open('', 'dependencies', 'width=800,height=600,scrollbars=yes');
                                                    if (depsWindow) {
                                                        const doc = depsWindow.document;
                                                        doc.open();
                                                        doc.write('<html><head><title>Installed Dependencies</title>');
                                                        doc.write('<style>body{font-family:system-ui;padding:20px;background:#f5f5f5}');
                                                        doc.write('h1{color:#333;margin-bottom:20px}table{width:100%;border-collapse:collapse;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1)}');
                                                        doc.write('th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd}');
                                                        doc.write('th{background:#4f46e5;color:white;font-weight:600}');
                                                        doc.write('tr:hover{background:#f9fafb}.count{color:#666;margin-top:10px}</style></head>');
                                                        doc.write('<body><h1>📦 Installed Python Packages</h1>');
                                                        doc.write(`<p class="count"><strong>${data.total}</strong> packages installed</p>`);
                                                        doc.write('<table><thead><tr><th>Package Name</th><th>Version</th></tr></thead><tbody>');
                                                        data.packages.forEach(pkg => {
                                                            doc.write(`<tr><td>${pkg.name}</td><td>${pkg.version}</td></tr>`);
                                                        });
                                                        doc.write('</tbody></table></body></html>');
                                                        doc.close();
                                                    } else {
                                                        alert('Please allow popups to view dependencies');
                                                    }
                                                } catch (err) {
                                                    alert('Failed to load dependencies: ' + err.message);
                                                }
                                            }}
                                            className={`px-4 py-2 text-sm rounded-lg font-medium ${isDarkTheme ? 'bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-600' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
                                        >
                                            <i className="fas fa-list mr-2"></i>
                                            View Dependencies
                                        </button>
                                        
                                        {/* Always show Save Settings button */}
                                        <button
                                            onClick={async () => {
                                                const providerEl = document.getElementById('llm-provider');
                                                const endpointUrlInput = document.getElementById('llm-endpoint-url');
                                                const modelInput = document.getElementById('llm-model');
                                                const apiKeyEl = document.getElementById('llm-api-key');
                                                const maxTokensEl = document.getElementById('llm-max-tokens');
                                                const tempEl = document.getElementById('llm-temperature');
                                                const mcpUrlEl = document.getElementById('mcp-url');
                                                const mcpTokenEl = document.getElementById('mcp-token');
                                                const mcpVerifyEl = document.getElementById('mcp-verify-ssl');
                                                
                                                const provider = providerEl ? providerEl.value : selectedProvider;
                                                
                                                // Only include token if it's actually changed (not empty)
                                                const mcpToken = mcpTokenEl ? mcpTokenEl.value : '';
                                                const mcpSettings = {
                                                    url: mcpUrlEl ? mcpUrlEl.value : config.mcp.url,
                                                    verify_ssl: mcpVerifyEl ? mcpVerifyEl.checked : config.mcp.verify_ssl
                                                };
                                                // Only include token if user entered a new one
                                                if (mcpToken && mcpToken.trim()) {
                                                    mcpSettings.token = mcpToken;
                                                }
                                                
                                                const settings = {
                                                    mcp: mcpSettings,
                                                    llm: {
                                                        provider: provider,
                                                        api_key: (apiKeyEl ? apiKeyEl.value : config.llm.api_key) || undefined,
                                                        model: (modelInput ? modelInput.value : selectedModel) || config.llm.model,
                                                        endpoint_url: (provider !== 'openai' && endpointUrlInput) ? endpointUrlInput.value : undefined,
                                                        max_tokens: maxTokensEl ? parseInt(maxTokensEl.value) : config.llm.max_tokens,
                                                        temperature: tempEl ? parseFloat(tempEl.value) : config.llm.temperature
                                                    },
                                                    server: {
                                                        ...config.server
                                                    }
                                                };
                                                await saveSettings(settings);
                                            }}
                                            className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium"
                                        >
                                            <i className="fas fa-save mr-2"></i>
                                            Save Settings
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Credential Save Modal */}
                    {isCredentialModalOpen && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                            <div className={`rounded-xl shadow-2xl w-full max-w-md ${isDarkTheme ? 'bg-gray-800 border border-gray-700' : 'bg-white'}`}>
                                {/* Header */}
                                <div className={`px-6 py-4 rounded-t-xl ${isUpdateMode ? 'bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-b-4 border-amber-600' : 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white'}`}>
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <i className={`text-2xl ${isUpdateMode ? 'fas fa-sync-alt' : 'fas fa-save'}`}></i>
                                            <h2 className="text-xl font-bold">{isUpdateMode ? 'Update' : 'Save'} LLM Credential</h2>
                                        </div>
                                        <button
                                            onClick={() => {
                                                setIsCredentialModalOpen(false);
                                                setCredentialName('');
                                                setIsUpdateMode(false);
                                            }}
                                            className={`transition-colors ${isUpdateMode ? 'text-gray-900 hover:text-gray-600' : 'text-white hover:text-gray-200'}`}
                                        >
                                            <i className="fas fa-times text-xl"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Content */}
                                <div className="p-6">
                                    {isUpdateMode ? (
                                        <div className="bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-4">
                                            <div className="flex items-start">
                                                <i className="fas fa-exclamation-triangle text-yellow-600 text-xl mr-3 mt-0.5"></i>
                                                <div>
                                                    <p className="text-sm font-bold text-gray-900 mb-1">⚠️ Update Warning</p>
                                                    <p className="text-sm text-gray-800">
                                                        You are about to overwrite the existing credential "<strong className="text-gray-900">{credentialName}</strong>". 
                                                        This will replace all settings with your current configuration. This action cannot be undone.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className={`text-sm mb-4 ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                            Save your current LLM settings as a named credential for quick access later.
                                        </p>
                                    )}
                                    
                                    <div className="mb-6">
                                        <label className={`block text-sm font-medium mb-2 ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>
                                            Credential Name <span className="text-red-500">*</span>
                                        </label>
                                        <input
                                            type="text"
                                            value={credentialName}
                                            onChange={(e) => setCredentialName(e.target.value)}
                                            placeholder="e.g., My OpenAI GPT-4, Local Llama Server"
                                            className={`w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent ${isDarkTheme ? 'bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'}`}
                                            disabled={isUpdateMode}
                                            autoFocus={!isUpdateMode}
                                        />
                                        {isUpdateMode && (
                                            <p className={`text-xs mt-1 italic ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>Credential name cannot be changed when updating</p>
                                        )}
                                    </div>
                                    
                                    {/* Preview */}
                                    <div className={`rounded-lg p-4 mb-6 border ${isDarkTheme ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                        <h4 className={`text-xs font-semibold mb-2 uppercase tracking-wide ${isDarkTheme ? 'text-gray-300' : 'text-gray-700'}`}>Current Settings Preview</h4>
                                        <div className={`space-y-1 text-sm ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                            <div><span className="font-medium">Provider:</span> {selectedProvider}</div>
                                            <div><span className="font-medium">Model:</span> {document.getElementById('llm-model')?.value || 'N/A'}</div>
                                            <div><span className="font-medium">Max Tokens:</span> {document.getElementById('llm-max-tokens')?.value || 'N/A'}</div>
                                            <div><span className="font-medium">Temperature:</span> {document.getElementById('llm-temperature')?.value || 'N/A'}</div>
                                        </div>
                                    </div>
                                    
                                    {/* Actions */}
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => {
                                                setIsCredentialModalOpen(false);
                                                setCredentialName('');
                                                setIsUpdateMode(false);
                                            }}
                                            className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${isDarkTheme ? 'bg-gray-700 hover:bg-gray-600 text-gray-100' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            onClick={async () => {
                                                if (!credentialName.trim()) {
                                                    alert('Please enter a credential name');
                                                    return;
                                                }
                                                
                                                // Additional confirmation for updates
                                                if (isUpdateMode) {
                                                    const confirmed = confirm(`⚠️ Confirm Update\n\nAre you sure you want to overwrite "${credentialName}"?\n\nThis will replace:\n• Provider & Model\n• API Key\n• Endpoint URL\n• Max Tokens & Temperature\n\nThis action cannot be undone.`);
                                                    if (!confirmed) return;
                                                }
                                                
                                                try {
                                                    const provider = document.getElementById('llm-provider').value;
                                                    const endpointUrlInput = document.getElementById('llm-endpoint-url');
                                                    
                                                    const response = await fetch('/api/credentials', {
                                                        method: 'POST',
                                                        headers: { 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({
                                                            name: credentialName.trim(),
                                                            provider: provider,
                                                            api_key: document.getElementById('llm-api-key').value,
                                                            model: document.getElementById('llm-model').value,
                                                            endpoint_url: (provider === 'custom' && endpointUrlInput) ? endpointUrlInput.value : null,
                                                            max_tokens: parseInt(document.getElementById('llm-max-tokens').value),
                                                            temperature: parseFloat(document.getElementById('llm-temperature').value)
                                                        })
                                                    });
                                                    
                                                    if (response.ok) {
                                                        // Close modal
                                                        setIsCredentialModalOpen(false);
                                                        setCredentialName('');
                                                        const wasUpdate = isUpdateMode;
                                                        setIsUpdateMode(false);
                                                        
                                                        // Refresh credential list
                                                        await loadCredentials();
                                                        
                                                        // Show success message
                                                        const successDiv = document.createElement('div');
                                                        successDiv.className = `fixed top-6 right-6 ${wasUpdate ? 'bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-2 border-amber-600' : 'bg-green-600 text-white'} px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce`;
                                                        successDiv.innerHTML = `
                                                            <div class="flex items-center gap-3">
                                                                <i class="fas ${wasUpdate ? 'fa-sync-alt' : 'fa-check-circle'} text-2xl"></i>
                                                                <div>
                                                                    <p class="font-bold text-base">Credential ${wasUpdate ? 'Updated' : 'Saved'}!</p>
                                                                    <p class="text-sm ${wasUpdate ? 'opacity-80' : 'opacity-90'}">${credentialName}</p>
                                                                </div>
                                                            </div>
                                                        `;
                                                        document.body.appendChild(successDiv);
                                                        setTimeout(() => {
                                                            successDiv.style.animation = 'none';
                                                            successDiv.style.opacity = '0';
                                                            successDiv.style.transition = 'opacity 0.3s';
                                                            setTimeout(() => successDiv.remove(), 300);
                                                        }, 2500);
                                                    } else {
                                                        const error = await response.json();
                                                        alert('Failed to save credential: ' + (error.detail || 'Unknown error'));
                                                    }
                                                } catch (error) {
                                                    alert('Error saving credential: ' + error.message);
                                                }
                                            }}
                                            disabled={!credentialName.trim()}
                                            className={`flex-1 px-4 py-2 ${isUpdateMode ? 'bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 border-2 border-amber-600' : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white'} disabled:from-gray-400 disabled:to-gray-400 disabled:text-gray-300 rounded-lg font-bold transition-all shadow-md hover:shadow-lg disabled:cursor-not-allowed disabled:border-0`}
                                        >
                                            <i className={`mr-2 ${isUpdateMode ? 'fas fa-sync-alt' : 'fas fa-save'}`}></i>
                                            {isUpdateMode ? 'Update Credential' : 'Save Credential'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* MCP Configuration Save Modal */}
                    {isMCPSaveModalOpen && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                            <div className={`rounded-xl shadow-2xl w-full max-w-md ${isDarkTheme ? 'bg-gray-800 border border-gray-700' : 'bg-white'}`}>
                                {/* Header */}
                                <div className={`px-6 py-4 rounded-t-xl ${loadedMCPConfigName ? 'bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-b-4 border-amber-600' : 'bg-gradient-to-r from-green-600 to-emerald-600 text-white'}`}>
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <i className={`text-2xl ${loadedMCPConfigName ? 'fas fa-sync-alt' : 'fas fa-save'}`}></i>
                                            <h2 className="text-xl font-bold">{loadedMCPConfigName ? 'Update' : 'Save'} MCP Configuration</h2>
                                        </div>
                                        <button
                                            onClick={() => {
                                                setIsMCPSaveModalOpen(false);
                                                setMCPConfigName('');
                                                setMCPConfigDescription('');
                                            }}
                                            className={`transition-colors ${loadedMCPConfigName ? 'text-gray-900 hover:text-gray-600' : 'text-white hover:text-gray-200'}`}
                                        >
                                            <i className="fas fa-times text-xl"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Content */}
                                <div className="p-6">
                                    {loadedMCPConfigName ? (
                                        <div className="bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-4">
                                            <div className="flex items-start">
                                                <i className="fas fa-exclamation-triangle text-yellow-600 text-xl mr-3 mt-0.5"></i>
                                                <div>
                                                    <p className="text-sm font-bold text-gray-900 mb-1">⚠️ Update Warning</p>
                                                    <p className="text-sm text-gray-800">
                                                        You are about to overwrite the existing configuration "<strong className="text-gray-900">{mcpConfigName}</strong>". 
                                                        This will replace all settings with your current configuration. This action cannot be undone.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className={`text-sm mb-4 ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                            Save your current MCP server settings as a named configuration for quick access later.
                                        </p>
                                    )}
                                    
                                    <div className="mb-4">
                                        <label className={`block text-sm font-medium mb-2 ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>
                                            Configuration Name <span className="text-red-500">*</span>
                                        </label>
                                        <input
                                            type="text"
                                            value={mcpConfigName}
                                            onChange={(e) => setMCPConfigName(e.target.value)}
                                            placeholder="e.g., Production Splunk, Dev Environment"
                                            className={`w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent ${isDarkTheme ? 'bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'}`}
                                            disabled={loadedMCPConfigName}
                                            autoFocus={!loadedMCPConfigName}
                                        />
                                        {loadedMCPConfigName && (
                                            <p className={`text-xs mt-1 italic ${isDarkTheme ? 'text-gray-400' : 'text-gray-500'}`}>Configuration name cannot be changed when updating</p>
                                        )}
                                    </div>
                                    
                                    <div className="mb-6">
                                        <label className={`block text-sm font-medium mb-2 ${isDarkTheme ? 'text-gray-200' : 'text-gray-700'}`}>
                                            Description (Optional)
                                        </label>
                                        <input
                                            type="text"
                                            value={mcpConfigDescription}
                                            onChange={(e) => setMCPConfigDescription(e.target.value)}
                                            placeholder="e.g., Main production Splunk server"
                                            className={`w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent ${isDarkTheme ? 'bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'}`}
                                        />
                                    </div>
                                    
                                    {/* Preview */}
                                    <div className={`rounded-lg p-4 mb-6 border ${isDarkTheme ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                        <h4 className={`text-xs font-semibold mb-2 uppercase tracking-wide ${isDarkTheme ? 'text-gray-300' : 'text-gray-700'}`}>Current Settings Preview</h4>
                                        <div className={`space-y-1 text-sm ${isDarkTheme ? 'text-gray-300' : 'text-gray-600'}`}>
                                            <div><span className="font-medium">URL:</span> {config?.mcp?.url || 'N/A'}</div>
                                            <div><span className="font-medium">Token:</span> {config?.mcp?.token ? '***' : 'Not set'}</div>
                                            <div><span className="font-medium">Verify SSL:</span> {config?.mcp?.verify_ssl ? 'Yes' : 'No'}</div>
                                        </div>
                                    </div>
                                    
                                    {/* Actions */}
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => {
                                                setIsMCPSaveModalOpen(false);
                                                setMCPConfigName('');
                                                setMCPConfigDescription('');
                                            }}
                                            className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${isDarkTheme ? 'bg-gray-700 hover:bg-gray-600 text-gray-100' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            onClick={async () => {
                                                if (!mcpConfigName.trim()) {
                                                    alert('Please enter a configuration name');
                                                    return;
                                                }
                                                
                                                // Additional confirmation for updates
                                                if (loadedMCPConfigName) {
                                                    const confirmed = confirm(`⚠️ Confirm Update\n\nAre you sure you want to overwrite "${mcpConfigName}"?\n\nThis will replace:\n• MCP URL\n• Token\n• SSL Settings\n• Description\n\nThis action cannot be undone.`);
                                                    if (!confirmed) return;
                                                }
                                                
                                                try {
                                                    const response = await fetch('/api/mcp-configs', {
                                                        method: 'POST',
                                                        headers: { 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({
                                                            name: mcpConfigName.trim(),
                                                            url: document.getElementById('mcp-url').value,
                                                            token: document.getElementById('mcp-token').value || config.mcp.token,
                                                            verify_ssl: document.getElementById('mcp-verify-ssl').checked,
                                                            description: mcpConfigDescription.trim() || null
                                                        })
                                                    });
                                                    
                                                    if (response.ok) {
                                                        // Close modal
                                                        setIsMCPSaveModalOpen(false);
                                                        const savedName = mcpConfigName.trim();
                                                        const wasUpdate = loadedMCPConfigName;
                                                        setMCPConfigName('');
                                                        setMCPConfigDescription('');
                                                        
                                                        // Refresh MCP configs list
                                                        await loadMCPConfigs();
                                                        
                                                        // Show success message
                                                        const successDiv = document.createElement('div');
                                                        successDiv.className = `fixed top-6 right-6 ${wasUpdate ? 'bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-2 border-amber-600' : 'bg-green-600 text-white'} px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce`;
                                                        successDiv.innerHTML = `
                                                            <div class="flex items-center gap-3">
                                                                <i class="fas ${wasUpdate ? 'fa-sync-alt' : 'fa-check-circle'} text-2xl"></i>
                                                                <div>
                                                                    <p class="font-bold text-base">Configuration ${wasUpdate ? 'Updated' : 'Saved'}!</p>
                                                                    <p class="text-sm ${wasUpdate ? 'opacity-80' : 'opacity-90'}">${savedName}</p>
                                                                </div>
                                                            </div>
                                                        `;
                                                        document.body.appendChild(successDiv);
                                                        setTimeout(() => {
                                                            successDiv.style.animation = 'none';
                                                            successDiv.style.opacity = '0';
                                                            successDiv.style.transition = 'opacity 0.3s';
                                                            setTimeout(() => successDiv.remove(), 300);
                                                        }, 2500);
                                                    } else {
                                                        const error = await response.json();
                                                        alert('Failed to save configuration: ' + (error.detail || 'Unknown error'));
                                                    }
                                                } catch (error) {
                                                    alert('Error saving configuration: ' + error.message);
                                                }
                                            }}
                                            disabled={!mcpConfigName.trim()}
                                            className={`flex-1 px-4 py-2 ${loadedMCPConfigName ? 'bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 border-2 border-amber-600' : 'bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white'} disabled:from-gray-400 disabled:to-gray-400 disabled:text-gray-300 rounded-lg font-bold transition-all shadow-md hover:shadow-lg disabled:cursor-not-allowed disabled:border-0`}
                                        >
                                            <i className={`mr-2 ${loadedMCPConfigName ? 'fas fa-sync-alt' : 'fas fa-save'}`}></i>
                                            {loadedMCPConfigName ? 'Update Configuration' : 'Save Configuration'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }
        
        // Global error handler to catch unhandled errors
        window.addEventListener('error', (event) => {
            console.error('Global error caught:', event.error);
            // Prevent white screen by not letting the error propagate
            event.preventDefault();
        });
        
        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled promise rejection:', event.reason);
            // Prevent white screen
            event.preventDefault();
        });
        
        ReactDOM.render(
            <ErrorBoundary>
                <App />
            </ErrorBoundary>,
            document.getElementById('root')
        );
    </script>
</body>
</html>
    """


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

