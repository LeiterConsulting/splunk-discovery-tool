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
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import uvicorn
import httpx
from pydantic import BaseModel

# DT4SMS: Use encrypted config manager instead of YAML
from config_manager import ConfigManager
from discovery.engine import DiscoveryEngine
from llm.factory import LLMClientFactory

# Initialize encrypted config manager
config_manager = ConfigManager("config.encrypted")


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
        
        # Initialize LLM client with display callback
        llm_client = LLMClientFactory.create_client(
            provider=config.llm.provider,
            custom_endpoint=config.llm.endpoint_url if config.llm.endpoint_url else None,
            api_key=config.llm.api_key,
            model=config.llm.model,
            rate_limit_display_callback=display.handle_rate_limit_callback
        )
        display.success("✅ LLM client initialized")
        
        # Initialize discovery engine
        discovery_engine = DiscoveryEngine(
            mcp_url=config.mcp.url,
            mcp_token=config.mcp.token,
            llm_client=llm_client
        )
        display.success("✅ Discovery engine initialized")
        
        # Initialize progress tracker
        progress = ProgressTracker()
        
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
                    "discovery_results": discovery_results_dict,
                    "timestamp": timestamp
                }, f, indent=2, default=str)
            report_paths.append(str(json_export_path.name))
            display.info(f"   ✓ {json_export_path.name} (includes {len(discovery_results_dict)} discovery items)")
        except Exception as e:
            display.error(f"   ✗ Failed to export JSON: {str(e)}")
        
        # Export Executive Summary
        try:
            exec_summary_path = output_dir / f"executive_summary_{timestamp}.md"
            with open(exec_summary_path, 'w', encoding='utf-8') as f:
                f.write(f"# Splunk Environment Discovery - Executive Summary\n\n")
                f.write(f"**Discovery Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"## Environment Overview\n\n")
                if hasattr(overview, 'total_indexes'):
                    f.write(f"- **Total Indexes:** {overview.total_indexes}\n")
                    f.write(f"- **Total Source Types:** {overview.total_sourcetypes}\n")
                    f.write(f"- **Active Data Sources:** {overview.total_sourcetypes}\n\n")
                f.write(f"## Key Findings\n\n")
                f.write(f"Discovery completed successfully across {overview.estimated_discovery_steps if hasattr(overview, 'estimated_discovery_steps') else 'multiple'} analysis steps.\n\n")
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
                f.write(f"## Discovery Results\n\n")
                f.write(json.dumps(discovery_engine.discovery_results, indent=2, default=str))
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
                f.write(json.dumps(classifications, indent=2, default=str))
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
            "report_paths": report_paths,
            "timestamp": timestamp
        }
        
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
    """Get list of available reports."""
    output_dir = Path("output")
    if not output_dir.exists():
        return {"reports": []}
    
    reports = []
    for file_path in output_dir.glob("*"):
        if file_path.is_file():
            reports.append({
                "name": file_path.name,
                "path": str(file_path),
                "size": file_path.stat().st_size,
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                "type": file_path.suffix[1:] if file_path.suffix else "unknown"
            })
    
    return {"reports": sorted(reports, key=lambda x: x["modified"], reverse=True)}


@app.get("/api/discovery/results")
async def get_discovery_results():
    """
    Legacy endpoint stub - prevents 404 errors from cached frontend code.
    Modern discovery results are now delivered via WebSocket real-time updates
    and stored in discovery report files.
    """
    return {
        "message": "Discovery results are now delivered via WebSocket. Check /reports for saved discovery sessions.",
        "reports_endpoint": "/reports"
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
        llm_provider = config.llm.provider
        
        # Determine endpoint display based on provider
        if llm_provider == "custom" and config.llm.endpoint_url:
            llm_endpoint = config.llm.endpoint_url
        elif llm_provider == "openai":
            llm_endpoint = "OpenAI API (api.openai.com)"
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
        
        if not config.llm.api_key:
            raise HTTPException(status_code=400, detail="LLM API key not configured")
        
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
async def test_llm_connection():
    """Test LLM connection and auto-detect capabilities"""
    try:
        config = config_manager.get()
        
        # Validate configuration
        if config.llm.provider == "custom" and not config.llm.endpoint_url:
            return {
                "status": "error",
                "error": "Custom endpoint URL is required",
                "suggestion": "Enter the endpoint URL (e.g., http://localhost:11434 for Ollama)"
            }
        
        # Test results
        results = {
            "status": "testing",
            "endpoint": config.llm.endpoint_url if config.llm.provider == "custom" else "OpenAI API",
            "provider": config.llm.provider,
            "model": config.llm.model,
            "tests": {}
        }
        
        # Test 1: Connection test with intelligent path detection
        try:
            if config.llm.provider == "custom":
                # Test custom endpoint with multiple common paths
                import httpx
                endpoint_base = config.llm.endpoint_url.rstrip('/')
                detected_format = None
                available_models = []
                
                # Try various info/health endpoints to detect format
                test_paths = [
                    ("/v1/models", "OpenAI-compatible (v1)"),
                    ("/models", "OpenAI-compatible"),
                    ("/api/tags", "Ollama"),
                    ("/api/version", "Ollama Version"),
                    ("/v1/engines", "OpenAI Engines"),
                    ("/health", "Generic Health"),
                    ("/", "Root"),
                ]
                
                async with httpx.AsyncClient(timeout=10.0) as client:
                    # First try a simple connectivity test
                    try:
                        base_response = await client.get(endpoint_base, follow_redirects=True)
                        if base_response.status_code == 404:
                            # 404 is ok, just means root doesn't have info
                            pass
                    except Exception as e:
                        results["tests"]["connection"] = {
                            "status": "error",
                            "error": str(e),
                            "message": f"Cannot reach endpoint: {str(e)}"
                        }
                        results["status"] = "error"
                        return results
                    
                    # Now try to detect the API format
                    for path, format_name in test_paths:
                        try:
                            response = await client.get(f"{endpoint_base}{path}")
                            if response.status_code == 200:
                                detected_format = format_name
                                try:
                                    data = response.json()
                                    # Extract available models if present
                                    if "models" in data:
                                        available_models = [m.get("id") or m.get("name") for m in data.get("models", [])]
                                    elif "data" in data:
                                        available_models = [m.get("id") for m in data.get("data", [])]
                                except:
                                    pass
                                break
                        except:
                            continue
                    
                    if detected_format:
                        results["tests"]["connection"] = {
                            "status": "success",
                            "format": detected_format,
                            "message": f"Endpoint is reachable ({detected_format})",
                            "available_models": available_models[:5] if available_models else None
                        }
                    else:
                        # Endpoint is up but we couldn't detect format
                        # This is OK - we'll try multiple formats when making requests
                        results["tests"]["connection"] = {
                            "status": "info",
                            "message": "Endpoint reachable, will auto-detect API format on first request"
                        }
            else:
                results["tests"]["connection"] = {
                    "status": "success",
                    "format": "OpenAI",
                    "message": "Using OpenAI API"
                }
        except Exception as e:
            results["tests"]["connection"] = {
                "status": "error",
                "error": str(e),
                "message": f"Cannot reach endpoint: {str(e)}"
            }
            results["status"] = "error"
            return results
        
        # Test 2: Model test with simple query
        try:
            llm_client = LLMClientFactory.create_client(
                provider=config.llm.provider,
                custom_endpoint=config.llm.endpoint_url if config.llm.provider == "custom" else None,
                api_key=config.llm.api_key,
                model=config.llm.model
            )
            
            response = await llm_client.generate_response(
                messages=[{"role": "user", "content": "Say 'test successful' and nothing else."}],
                max_tokens=50,
                temperature=0.0
            )
            
            results["tests"]["model"] = {
                "status": "success",
                "message": "Model responded successfully",
                "response_preview": response[:100]
            }
        except Exception as e:
            results["tests"]["model"] = {
                "status": "error",
                "error": str(e),
                "message": f"Model test failed: {str(e)}"
            }
            results["status"] = "error"
            return results
        
        # Test 3: Auto-detect max_tokens
        try:
            if config.llm.provider == "openai":
                # Use OpenAI client for accurate detection
                from openai import OpenAI
                client = OpenAI(api_key=config.llm.api_key)
                
                test_values = [128000, 64000, 32000, 16000, 8000, 4000]
                detected_max = None
                
                for test_max in test_values:
                    try:
                        client.chat.completions.create(
                            model=config.llm.model,
                            messages=[{"role": "user", "content": "Hi"}],
                            max_tokens=test_max,
                            temperature=0.0
                        )
                        detected_max = test_max
                        break
                    except Exception as e:
                        error_str = str(e)
                        import re
                        match = re.search(r'supports at most (\d+)', error_str)
                        if match:
                            actual_limit = int(match.group(1))
                            detected_max = int(actual_limit * 0.9)
                            break
                        continue
                
                if detected_max:
                    results["tests"]["max_tokens"] = {
                        "status": "success",
                        "detected_max": detected_max,
                        "message": f"Detected max_tokens: {detected_max}"
                    }
                else:
                    results["tests"]["max_tokens"] = {
                        "status": "warning",
                        "detected_max": 4000,
                        "message": "Could not detect max_tokens, using 4000 as fallback"
                    }
            else:
                # For custom endpoints, use conservative default
                results["tests"]["max_tokens"] = {
                    "status": "info",
                    "detected_max": 4000,
                    "message": "Using default 4000 tokens for custom endpoint (adjust manually if needed)"
                }
        except Exception as e:
            results["tests"]["max_tokens"] = {
                "status": "warning",
                "detected_max": 4000,
                "error": str(e),
                "message": f"Max tokens detection failed, using 4000 as fallback"
            }
        
        # Overall status
        if all(test.get("status") in ["success", "info", "warning"] for test in results["tests"].values()):
            results["status"] = "success"
            results["message"] = "All tests passed! Configuration is working."
            results["recommended_config"] = {
                "max_tokens": results["tests"]["max_tokens"]["detected_max"],
                "temperature": 0.7
            }
        else:
            results["status"] = "partial"
            results["message"] = "Some tests passed, check details"
        
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
    
    # Check if summary already exists
    output_dir = Path("output")
    summary_file = output_dir / f"ai_summary_{safe_timestamp}.json"
    
    if summary_file.exists():
        # Load and return existing summary
        try:
            with open(summary_file, 'r', encoding='utf-8') as f:
                existing_summary = json.load(f)
            existing_summary['from_cache'] = True
            return existing_summary
        except Exception as e:
            print(f"Error loading cached summary: {e}")
            # Continue to regenerate
    
    # Load session reports
    json_file = output_dir / f"discovery_export_{timestamp}.json"
    detailed_file = output_dir / f"detailed_discovery_{timestamp}.md"
    classification_file = output_dir / f"data_classification_{timestamp}.md"
    executive_file = output_dir / f"executive_summary_{timestamp}.md"
    
    if not json_file.exists():
        return {"error": "Session data not found"}
    
    # Initialize progress tracking
    summarization_progress[timestamp] = {
        "stage": "loading",
        "progress": 10,
        "message": "Loading discovery reports..."
    }
    
    # Load discovery data
    with open(json_file, 'r', encoding='utf-8') as f:
        discovery_data = json.load(f)
    
    # Extract discovery results
    discovery_results = discovery_data.get('discovery_results', [])
    
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
    unknown_id = UnknownDataIdentifier(discovery_results)
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
    llm_client = LLMClientFactory.create_client(
        provider=config.llm.provider,
        custom_endpoint=config.llm.endpoint_url if config.llm.endpoint_url else None,
        api_key=config.llm.api_key,
        model=config.llm.model
    )
    
    # Extract indexes and sourcetypes from discovery results
    discovered_indexes = set()
    discovered_sourcetypes = set()
    for result in discovery_results:
        data = result.get('data', {})
        if 'title' in data and 'totalEventCount' in data:
            discovered_indexes.add(data['title'])
        elif 'sourcetype' in data:
            discovered_sourcetypes.add(data['sourcetype'])
    
    findings_prompt = f"""Analyze these Splunk discovery reports and extract specific, actionable findings.

**Executive Summary:**
{executive_summary[:3000]}

**Detailed Findings:**
{detailed_findings[:3000]}

**Classification Report:**
{classification_report[:2000]}

**Discovered Indexes:** {', '.join(list(discovered_indexes)[:20])}
**Discovered Sourcetypes:** {', '.join(list(discovered_sourcetypes)[:30])}

Extract specific findings in these categories:
1. **Security Issues** (failed logins, suspicious activity, missing security monitoring)
2. **Performance Issues** (high CPU/memory/disk, slow queries, bottlenecks)
3. **Data Quality Issues** (missing data, parsing errors, empty indexes, data gaps)
4. **Optimization Opportunities** (retention policies, acceleration, index consolidation)
5. **Compliance Gaps** (missing audit logs, retention violations, access control issues)

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
  "compliance_findings": [...]
}}

Focus on ACTUAL findings from the reports with SPECIFIC details. If no findings in a category, return empty array.
Return ONLY the JSON object."""

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
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', findings_response, re.DOTALL)
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
            "compliance_findings": []
        }
    except Exception as e:
        print(f"Error extracting findings with AI: {e}")
        ai_findings = {
            "security_findings": [],
            "performance_findings": [],
            "data_quality_findings": [],
            "optimization_findings": [],
            "compliance_findings": []
        }
    
    # ===== AI-POWERED QUERY GENERATION =====
    # Generate SPL queries based on actual findings
    query_generation_prompt = f"""Generate 4 SPL queries based on these Splunk findings.

Findings: {json.dumps(ai_findings, indent=2)[:2000]}

Available: {len(discovered_indexes)} indexes, {len(discovered_sourcetypes)} sourcetypes

Return JSON array with exactly 4 queries. Each query must have:
- title: Clear, actionable title with emoji
- description: 1 sentence explaining the query
- use_case: Security Investigation, Performance Monitoring, Data Quality, or Capacity Planning
- category: Security & Compliance, Infrastructure & Performance, Data Quality, or Capacity Planning
- spl: Valid SPL query using actual indexes/sourcetypes from findings
- finding_reference: Which finding this addresses
- execution_time: Estimated time
- business_value: Why this matters
- priority: 🔴 HIGH, 🟠 MEDIUM, or 🟡 LOW
- difficulty: Beginner, Intermediate, or Advanced

Example:
[{{"title": "🔍 Investigation Title", "description": "What this does", "use_case": "Security Investigation", "category": "Security & Compliance", "spl": "index=main | stats count", "finding_reference": "Specific finding", "execution_time": "< 30s", "business_value": "Why it matters", "priority": "🔴 HIGH", "difficulty": "Beginner"}}]

Return ONLY the JSON array of 4 queries, nothing else."""

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
                    q['query_source'] = 'ai_finding'
            else:
                raise
        except:
            print("Could not salvage queries, will use templates")
            finding_based_queries = []
    except Exception as e:
        print(f"Error generating finding-based queries with AI: {e}")
        finding_based_queries = []
    
    # Combine AI-generated queries with template queries
    print(f"📊 Query Status: AI generated {len(finding_based_queries)}, Template generated {len(template_queries)}")
    
    if len(finding_based_queries) >= 8:
        # AI generated enough queries - use them, but keep some templates for variety
        queries = finding_based_queries + template_queries[:4]
        print(f"✅ Using {len(finding_based_queries)} AI queries + {len(template_queries[:4])} template queries = {len(queries)} total")
    else:
        # AI didn't generate enough - prioritize what we have, supplement with templates
        queries = finding_based_queries + template_queries
        print(f"⚠️  Using {len(finding_based_queries)} AI queries + all {len(template_queries)} template queries = {len(queries)} total")
    
    # Ensure we have at least some queries
    if len(queries) == 0:
        print("❌ WARNING: No queries generated at all! This shouldn't happen.")
        # This should never happen since template_queries should always have content
        queries = []
    
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
    llm_client = LLMClientFactory.create_client(
        provider=config.llm.provider,
        custom_endpoint=config.llm.endpoint_url if config.llm.endpoint_url else None,
        api_key=config.llm.api_key,
        model=config.llm.model
    )
    
    # Get current date for temporal context
    from datetime import datetime
    current_date = datetime.now().strftime("%B %d, %Y")
    
    summary_prompt = f"""You are analyzing a Splunk discovery report. Create a concise executive summary.

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

Keep it concise and actionable. Focus on business value and ROI. Base all statements on actual data from the reports above."""
    
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
        "progress": 85,
        "message": "Creating admin tasks..."
    }
    
    # ===== ADMIN TASK GENERATION =====
    # Generate actionable admin tasks based on findings
    admin_tasks = []
    
    tasks_prompt = f"""Based on the Splunk discovery analysis below, generate a prioritized list of implementation tasks for the Splunk administrator.

**Discovery Reports:**
{executive_summary[:2500]}

**Key Findings:**
{detailed_findings[:2000]}

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

Generate 3-5 prioritized tasks. Keep each task concise but actionable. Return ONLY the JSON array, no other text."""

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
            admin_tasks = [
                {
                    "title": "Verify Data Ingestion Across Indexes",
                    "priority": "HIGH",
                    "category": "Data Quality",
                    "description": "Ensure data is actively flowing into your Splunk indexes and identify any gaps in data collection that could impact monitoring and analysis.",
                    "prerequisites": ["Access to search Splunk indexes"],
                    "steps": [
                        {"number": 1, "action": "Check recent data ingestion across all indexes", "spl": "| tstats count where index=* earliest=-24h by index | sort -count"},
                        {"number": 2, "action": "Identify indexes with no recent data", "spl": "| tstats count where index=* earliest=-24h by index | where count=0"},
                        {"number": 3, "action": "Review sourcetypes for active indexes", "spl": "index=* earliest=-1h | stats count by index, sourcetype | sort -count"}
                    ],
                    "verification_spl": "| tstats count where index=* earliest=-1h | stats count as active_indexes",
                    "expected_outcome": "At least one index showing recent data (count > 0)",
                    "impact": "Ensures continuous monitoring and detection capabilities are functional",
                    "estimated_time": "30 minutes",
                    "rollback": "No changes made - this is a read-only verification task"
                }
            ]
    except Exception as e:
        print(f"Error generating admin tasks: {e}")
        print(f"Raw response: {tasks_response[:500] if 'tasks_response' in locals() else 'No response'}")
        # Create default tasks based on common findings
        admin_tasks = [
            {
                "title": "Verify Data Ingestion Across Indexes",
                "priority": "HIGH",
                "category": "Data Quality",
                "description": "Ensure data is actively flowing into your Splunk indexes and identify any gaps in data collection that could impact monitoring and analysis.",
                "prerequisites": ["Access to search Splunk indexes"],
                "steps": [
                    {"number": 1, "action": "Check recent data ingestion across all indexes", "spl": "| tstats count where index=* earliest=-24h by index | sort -count"},
                    {"number": 2, "action": "Identify indexes with no recent data", "spl": "| tstats count where index=* earliest=-24h by index | where count=0"},
                    {"number": 3, "action": "Review sourcetypes for active indexes", "spl": "index=* earliest=-1h | stats count by index, sourcetype | sort -count"}
                ],
                "verification_spl": "| tstats count where index=* earliest=-1h | stats count as active_indexes",
                "expected_outcome": "At least one index showing recent data (count > 0)",
                "impact": "Ensures continuous monitoring and detection capabilities are functional",
                "estimated_time": "30 minutes",
                "rollback": "No changes made - this is a read-only verification task"
            }
        ]
    
    # Prepare response
    response_data = {
        "success": True,
        "session_id": timestamp,
        "ai_summary": ai_summary,
        "spl_queries": queries,
        "admin_tasks": admin_tasks,
        "unknown_data": unknown_questions,
        "stats": {
            "total_queries": len(queries),
            "total_tasks": len(admin_tasks),
            "unknown_items": len(unknown_questions),
            "categories": list(set(q['category'] for q in queries))
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
                "name": "run_splunk_query",
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
        llm_client = LLMClientFactory.create_client(
            provider=config.llm.provider,
            custom_endpoint=config.llm.endpoint_url if config.llm.endpoint_url else None,
            api_key=config.llm.api_key,
            model=config.llm.model
        )
        
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
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', analysis_response, re.DOTALL)
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
        llm_client = LLMClientFactory.create_client(
            provider=config.llm.provider,
            custom_endpoint=config.llm.endpoint_url if config.llm.endpoint_url else None,
            api_key=config.llm.api_key,
            model=config.llm.model
        )
        
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
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', remediation_response, re.DOTALL)
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
        user_message = request.get('message', '')
        history = request.get('history', [])
        
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
        
        # Get discovery staleness threshold (default 1 week = 604800 seconds)
        staleness_threshold = 604800
        
        # Load latest discovery context if available
        discovery_context = ""
        discovery_age_warning = None
        output_dir = Path("output")
        
        # Find most recent discovery export
        discovery_files = sorted(output_dir.glob("discovery_export_*.json"), reverse=True)
        if discovery_files:
            try:
                discovery_file = discovery_files[0]
                
                # Parse timestamp from filename: discovery_export_YYYYMMDD_HHMMSS.json
                timestamp_str = discovery_file.stem.replace('discovery_export_', '')
                discovery_datetime = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                discovery_age_seconds = (datetime.now() - discovery_datetime).total_seconds()
                
                # Check if discovery is too old
                if discovery_age_seconds > staleness_threshold:
                    days_old = int(discovery_age_seconds / 86400)
                    discovery_age_warning = f"⚠️ Discovery data is {days_old} days old. Consider running a new discovery for up-to-date information."
                
                with open(discovery_file, 'r', encoding='utf-8') as f:
                    latest_discovery = json.load(f)
                    
                # Build comprehensive context summary
                context_parts = [f"\n🔍 DISCOVERY CONTEXT (from {timestamp_str}):"]
                
                # Extract overview data
                if 'overview' in latest_discovery:
                    overview = latest_discovery['overview']
                    context_parts.append(f"📊 Environment Overview:")
                    
                    # System information
                    splunk_version = overview.get('splunk_version', 'unknown')
                    splunk_build = overview.get('splunk_build', 'unknown')
                    license_state = overview.get('license_state', 'unknown')
                    server_roles = overview.get('server_roles', [])
                    
                    if splunk_version != 'unknown':
                        context_parts.append(f"  - Splunk Version: {splunk_version} (build {splunk_build})")
                    if license_state != 'unknown':
                        context_parts.append(f"  - License State: {license_state}")
                    if server_roles:
                        context_parts.append(f"  - Server Roles: {', '.join(server_roles)}")
                    
                    # Environment metrics
                    context_parts.append(f"  - Total Indexes: {overview.get('total_indexes', 'unknown')}")
                    context_parts.append(f"  - Total Sourcetypes: {overview.get('total_sourcetypes', 'unknown')}")
                    context_parts.append(f"  - Total Hosts: {overview.get('total_hosts', 'unknown')}")
                    context_parts.append(f"  - Total Sources: {overview.get('total_sources', 'unknown')}")
                    context_parts.append(f"  - Knowledge Objects: {overview.get('total_knowledge_objects', 'unknown')}")
                    context_parts.append(f"  - Users: {overview.get('total_users', 'unknown')}")
                    context_parts.append(f"  - KV Collections: {overview.get('total_kv_collections', 'unknown')}")
                    context_parts.append(f"  - Data Volume (24h): {overview.get('data_volume_24h', 'unknown')}")
                
                # Extract index information
                active_indexes = []
                disabled_indexes = []
                index_details = {}
                retention_warnings = []
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'data' in result:
                            data = result['data']
                            if isinstance(data, dict) and 'title' in data:
                                index_name = data['title']
                                is_disabled = data.get('disabled') == '1'
                                event_count = data.get('totalEventCount', '0')
                                size_mb = data.get('currentDBSizeMB', '0')
                                
                                index_details[index_name] = {
                                    'disabled': is_disabled,
                                    'events': event_count,
                                    'size_mb': size_mb
                                }
                                
                                if is_disabled:
                                    disabled_indexes.append(index_name)
                                elif int(event_count) > 0:
                                    active_indexes.append(f"{index_name} ({event_count} events, {size_mb}MB)")
                
                if active_indexes:
                    context_parts.append(f"\n📁 Active Indexes with Data:")
                    for idx in active_indexes[:10]:  # Limit to top 10
                        context_parts.append(f"  - {idx}")
                
                # Extract host information
                active_hosts = []
                high_volume_hosts = []
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'data' in result and 'description' in result:
                            if 'Analyzing host:' in result.get('description', ''):
                                data = result['data']
                                if isinstance(data, dict) and 'host' in data:
                                    host_name = data['host']
                                    event_count = int(data.get('totalCount', '0'))
                                    
                                    if event_count > 10000:
                                        high_volume_hosts.append(f"{host_name} ({event_count:,} events)")
                                    elif event_count > 0:
                                        active_hosts.append(f"{host_name} ({event_count:,} events)")
                
                if high_volume_hosts:
                    context_parts.append(f"\n🖥️ High-Activity Hosts (>10k events):")
                    for host in high_volume_hosts[:10]:  # Top 10
                        context_parts.append(f"  - {host}")
                
                # Extract source information
                active_sources = []
                file_sources = []
                network_sources = []
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'data' in result and 'description' in result:
                            if 'Analyzing source:' in result.get('description', ''):
                                data = result['data']
                                if isinstance(data, dict) and 'source' in data:
                                    source_path = data['source']
                                    event_count = int(data.get('totalCount', '0'))
                                    
                                    if event_count > 1000:
                                        source_lower = source_path.lower()
                                        if '.log' in source_lower or '/var/log' in source_lower:
                                            file_sources.append(f"{source_path} ({event_count:,} events)")
                                        elif 'udp:' in source_lower or 'tcp:' in source_lower or 'syslog' in source_lower:
                                            network_sources.append(f"{source_path} ({event_count:,} events)")
                                        else:
                                            active_sources.append(f"{source_path} ({event_count:,} events)")
                
                if file_sources:
                    context_parts.append(f"\n📄 Top File Sources (>1k events):")
                    for src in file_sources[:5]:  # Top 5
                        context_parts.append(f"  - {src}")
                
                if network_sources:
                    context_parts.append(f"\n📡 Network Sources (>1k events):")
                    for src in network_sources[:5]:  # Top 5
                        context_parts.append(f"  - {src}")
                
                # Extract knowledge object information (alerts, dashboards, etc.)
                alerts = []
                dashboards = []
                macros = []
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'data' in result and 'description' in result:
                            desc = result.get('description', '')
                            data = result['data']
                            
                            if 'Analyzing alerts:' in desc and isinstance(data, dict):
                                alert_name = data.get('name', data.get('title', ''))
                                if alert_name and data.get('disabled', '0') != '1':
                                    severity = data.get('alert.severity', 'medium')
                                    alerts.append(f"{alert_name} (severity: {severity})")
                            
                            elif 'Analyzing dashboards:' in desc and isinstance(data, dict):
                                dash_name = data.get('name', data.get('title', ''))
                                if dash_name:
                                    dashboards.append(dash_name)
                            
                            elif 'Analyzing macros:' in desc and isinstance(data, dict):
                                macro_name = data.get('name', data.get('title', ''))
                                if macro_name:
                                    macros.append(macro_name)
                
                if alerts:
                    context_parts.append(f"\n🚨 Active Alerts ({len(alerts)} total):")
                    for alert in alerts[:5]:  # Top 5
                        context_parts.append(f"  - {alert}")
                    if len(alerts) > 5:
                        context_parts.append(f"  ... and {len(alerts)-5} more")
                
                if dashboards:
                    context_parts.append(f"\n📊 Dashboards ({len(dashboards)} total):")
                    for dash in dashboards[:5]:  # Top 5
                        context_parts.append(f"  - {dash}")
                    if len(dashboards) > 5:
                        context_parts.append(f"  ... and {len(dashboards)-5} more")
                
                # Extract user information
                admin_users = []
                total_users_count = 0
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'data' in result and 'description' in result:
                            if 'Analyzing user:' in result.get('description', ''):
                                total_users_count += 1
                                data = result['data']
                                if isinstance(data, dict):
                                    roles = data.get('roles', [])
                                    if isinstance(roles, str):
                                        roles = [r.strip() for r in roles.split(",")]
                                    if 'admin' in roles:
                                        user_name = data.get('name', data.get('username', 'unknown'))
                                        admin_users.append(user_name)
                
                if total_users_count > 0:
                    context_parts.append(f"\n👥 User Information:")
                    context_parts.append(f"  - Total Users: {total_users_count}")
                    if admin_users:
                        context_parts.append(f"  - Admin Users: {len(admin_users)}")
                        if len(admin_users) <= 5:
                            for admin in admin_users:
                                context_parts.append(f"    • {admin}")
                
                # Extract KV Store collections
                threat_intel_collections = []
                asset_collections = []
                total_kv = 0
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'data' in result and 'description' in result:
                            if 'Analyzing KV collection:' in result.get('description', ''):
                                total_kv += 1
                                data = result['data']
                                if isinstance(data, dict):
                                    kv_name = data.get('name', data.get('title', ''))
                                    if any(term in kv_name.lower() for term in ['threat', 'intel', 'ioc', 'malware']):
                                        threat_intel_collections.append(kv_name)
                                    elif any(term in kv_name.lower() for term in ['asset', 'inventory', 'cmdb']):
                                        asset_collections.append(kv_name)
                
                if total_kv > 0:
                    context_parts.append(f"\n🗄️  KV Store Collections ({total_kv} total):")
                    if threat_intel_collections:
                        context_parts.append(f"  - Threat Intelligence: {', '.join(threat_intel_collections[:3])}")
                    if asset_collections:
                        context_parts.append(f"  - Asset Inventory: {', '.join(asset_collections[:3])}")
                
                # Extract advanced analytics insights
                analytics_insights = []
                
                if 'discovery_results' in latest_discovery:
                    for result in latest_discovery['discovery_results']:
                        if isinstance(result, dict) and 'description' in result:
                            desc = result.get('description', '')
                            if 'Advanced analysis' in desc or 'Data Quality' in desc or 'Temporal Analysis' in desc:
                                findings = result.get('interesting_findings', [])
                                analytics_insights.extend(findings[:2])  # Top 2 findings per analysis
                
                if analytics_insights:
                    context_parts.append(f"\n📈 Analytics Insights:")
                    for insight in analytics_insights[:5]:  # Top 5 insights
                        context_parts.append(f"  - {insight}")
                
                # Extract sourcetype information from notable_patterns
                if 'overview' in latest_discovery and 'notable_patterns' in latest_discovery['overview']:
                    try:
                        patterns_list = latest_discovery['overview']['notable_patterns']
                        if patterns_list and len(patterns_list) > 0:
                            patterns_str = patterns_list[0]
                            # Check if it's already a dict or needs parsing
                            if isinstance(patterns_str, dict):
                                patterns_data = patterns_str
                            elif isinstance(patterns_str, str) and patterns_str.strip():
                                patterns_data = json.loads(patterns_str)
                            else:
                                patterns_data = None
                            
                            if patterns_data and 'patterns' in patterns_data:
                                for pattern in patterns_data['patterns']:
                                    if 'source_types_characteristics' in pattern:
                                        st_char = pattern['source_types_characteristics']
                                        context_parts.append(f"\n📋 Sourcetype Information:")
                                        context_parts.append(f"  - Total: {st_char.get('total_source_types', 'unknown')}")
                                        context_parts.append(f"  - Active: {st_char.get('active_source_types', 'unknown')}")
                                        
                                        if 'most_active_source_type' in st_char:
                                            most_active = st_char['most_active_source_type']
                                            context_parts.append(f"  - Most Active: {most_active.get('sourcetype')} ({most_active.get('total_count')} events)")
                                    
                                    if 'temporal_patterns' in pattern:
                                        temp_pattern = pattern['temporal_patterns']
                                        if 'recent_events' in temp_pattern:
                                            recent = temp_pattern['recent_events']
                                            context_parts.append(f"\n⏰ Temporal Information:")
                                            context_parts.append(f"  - Data Span: {recent.get('event_span_days', 'unknown')} days")
                                            context_parts.append(f"  - Latest Event: {recent.get('last_event_time', 'unknown')}")
                    except (json.JSONDecodeError, IndexError, KeyError) as e:
                        print(f"Could not parse notable_patterns: {e}")
                
                discovery_context = "\n".join(context_parts)
                
            except Exception as e:
                print(f"Could not load discovery context: {e}")
                import traceback
                traceback.print_exc()
        else:
            discovery_age_warning = "⚠️ No discovery data found. Run a discovery first to get environment context."
        
        # Initialize LLM client
        llm_client = LLMClientFactory.create_client(
            provider=config.llm.provider,
            custom_endpoint=config.llm.endpoint_url,
            api_key=config.llm.api_key,
            model=config.llm.model
        )
        
        # Prepare system prompt for Splunk chat - AGENTIC WITH MULTI-TURN REASONING
        system_prompt = f"""You are the world's greatest Splunk administrator - an expert with deep knowledge and autonomous problem-solving abilities.

🌍 ENVIRONMENT CONTEXT:
{discovery_context}

🎯 YOUR SUPERPOWERS:
You are an AUTONOMOUS AGENT with the ability to:
1. Execute multiple queries in sequence to solve complex problems
2. Learn from errors and automatically retry with improved approaches
3. Break down complex questions into smaller investigative steps
4. Cross-reference data across multiple indexes and time ranges
5. Provide deep insights, not just raw data

🔧 AVAILABLE TOOLS:
- run_splunk_query(query, earliest_time, latest_time): Execute any SPL search
- get_indexes(): List all available indexes
- get_index_info(index_name): Get details about a specific index
- get_metadata(type, index): Get hosts, sources, or sourcetypes  
- get_splunk_info(): Get general Splunk system information

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
Always use this exact format for tool calls:

<TOOL_CALL>
{{
  "tool": "run_splunk_query",
  "args": {{
    "query": "index=wineventlog earliest=-24h | stats count by EventCode | sort -count | head 10",
    "earliest_time": "-24h",
    "latest_time": "now"
  }}
}}
</TOOL_CALL>

I'm checking the top 10 event codes in the wineventlog index from the last 24 hours.

💡 EXPERT BEHAVIORS:
1. **Be Proactive**: Don't just answer - provide insights, context, and recommendations
2. **Think Holistically**: Consider security, performance, compliance angles
3. **Explain Clearly**: Translate technical results into business value
4. **Show Your Work**: Let users see your reasoning process
5. **Iterate Intelligently**: Use up to 5 query iterations to thoroughly answer questions
6. **Leverage Context**: Use the discovery data above to inform your queries

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
  "tool": "run_splunk_query",
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
  "tool": "run_splunk_query",
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
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add recent history for context (convert to proper format)
        for msg in history[-6:]:  # Last 6 messages for context
            if msg.get('type') == 'user':
                messages.append({"role": "user", "content": msg['content']})
            elif msg.get('type') == 'assistant':
                messages.append({"role": "assistant", "content": msg['content']})
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})
        
        # Get LLM response - use 15% of configured max_tokens for chat responses
        chat_max_tokens = min(2000, int(config.llm.max_tokens * 0.15))
        response = await llm_client.generate_response(
            messages=messages,
            max_tokens=chat_max_tokens,
            temperature=config.llm.temperature
        )
        
        # Check if response contains tool call or SPL
        tool_call = None
        spl_in_text = None
        clean_response = response
        
        try:
            import re
            
            # Extract tool call using <TOOL_CALL> tags
            tool_match = re.search(r'<TOOL_CALL>\s*(\{.*?\})\s*</TOOL_CALL>', response, re.DOTALL)
            if tool_match:
                try:
                    tool_data = json.loads(tool_match.group(1))
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
                except json.JSONDecodeError as e:
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
                    
        except Exception as e:
            debug_log(f"Error parsing response: {e}", "error")
            import traceback
            traceback.print_exc()
        
        if tool_call and tool_call.get('method') == 'tools/call':
            # ===== INTELLIGENT AGENTIC LOOP WITH QUALITY-DRIVEN STOPPING =====
            import time as time_module
            
            start_time = time_module.time()
            max_execution_time = 90  # 90 seconds timeout as safety valve
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
                
                if isinstance(result_data, dict):
                    if 'error' in result_data:
                        return {"type": "error", "message": result_data.get('error', 'Unknown error')}
                    
                    result = result_data.get('result', {})
                    
                    # MCP wraps responses in content array - extract the actual data
                    actual_results = None
                    if isinstance(result, dict) and 'content' in result:
                        content_items = result.get('content', [])
                        if content_items and len(content_items) > 0:
                            first_item = content_items[0]
                            if isinstance(first_item, dict) and 'text' in first_item:
                                try:
                                    # Parse the JSON string containing actual results
                                    actual_results = json.loads(first_item['text'])
                                    print(f"📦 Extracted {len(actual_results.get('results', []))} results from MCP content wrapper")
                                except json.JSONDecodeError as e:
                                    print(f"⚠️  Failed to parse MCP content text as JSON: {e}")
                    
                    # Summarize based on tool type
                    if tool_name == 'run_splunk_query':
                        # Check parsed results first, then fall back to direct structure
                        results_array = None
                        if actual_results and 'results' in actual_results:
                            results_array = actual_results['results']
                        elif 'results' in result:
                            results_array = result['results']
                        
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
                    
                    elif tool_name in ['get_indexes', 'get_metadata']:
                        if actual_results and 'results' in actual_results:
                            summary['findings'].append(f"Found {len(actual_results['results'])} items")
                        elif 'results' in result:
                            summary['findings'].append(f"Found {len(result['results'])} items")
                
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
                # Need at least 5 iterations before checking convergence (allow more exploration)
                if len(tool_history) < 5:
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
                for call in tool_history[-5:]:
                    params = call.get('params', {})
                    if 'query' in params:
                        # Normalize: remove whitespace differences, lowercase for comparison
                        query = ' '.join(params['query'].lower().split())
                        recent_spl_queries.append(query)
                
                # If all 5 queries are EXACTLY the same, it's true convergence
                if len(recent_spl_queries) == 5 and len(set(recent_spl_queries)) == 1:
                    return True  # Exact same query 5 times in a row
                
                # Check if we're stuck getting zero results consistently
                if len(tool_history) >= 5:
                    last_five_counts = [call.get('summary', {}).get('row_count', 0) for call in tool_history[-5:]]
                    # If all 5 returned zero results, we're stuck
                    if all(count == 0 for count in last_five_counts):
                        return True  # Stuck finding nothing for 5 iterations
                
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
                action = "🔍 Querying Splunk" if tool_name == 'run_splunk_query' else f"⚙️ Executing {tool_name}"
                status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                if status_callback:
                    await status_callback(action, iteration, elapsed)
                
                mcp_result = await execute_mcp_tool_call(tool_call, config)
                
                # Summarize result for efficient context
                result_summary = summarize_result(mcp_result, tool_name)
                action = f"📊 Analyzing {result_summary.get('row_count', 0)} results"
                elapsed = time_module.time() - start_time
                status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                if status_callback:
                    await status_callback(action, iteration, elapsed)
                
                # Track this tool call with summary
                spl_query = None
                if tool_name == 'run_splunk_query' and 'query' in tool_args:
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
                has_data = any('results returned' in f and '0 results' not in f for f in result_summary.get('findings', []))
                
                # Add assistant's reasoning to conversation
                conversation_history.append({"role": "assistant", "content": clean_response})
                
                # Build intelligent feedback with accumulated context
                insights_summary = "\n".join([f"  • {ins}" for ins in accumulated_insights[-5:]])  # Last 5 insights
                
                if has_error:
                    error_msg = result_summary.get('message', 'Unknown error')
                    system_feedback = f"""🔴 ITERATION {iteration} RESULT: ERROR

Error: {error_msg}

ACCUMULATED INSIGHTS SO FAR:
{insights_summary}

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
                    sample_data = result_summary.get('actual_results', [])[:2] if result_summary.get('actual_results') else []
                    result_snippet = {
                        "summary": result_summary,
                        "sample_data": sample_data
                    }
                    
                    system_feedback = f"""✅ ITERATION {iteration} RESULT: SUCCESS - DATA FOUND

{result_summary.get('findings', [])}

ACCUMULATED INSIGHTS:
{insights_summary}

Sample Data (first 2 results):
{json.dumps(result_snippet.get('sample_data'), indent=2)[:800]}

QUALITY CHECK:
- Does this fully answer "{user_intent}"?
- Should you cross-reference with other data sources?
- Is there a deeper insight you can provide?

OPTIONS:
1. ✅ Provide final answer if user's question is fully addressed
2. 🔍 Execute additional query to enrich the answer
3. 📊 Aggregate/analyze these results with another query

Respond with final answer WITHOUT tool calls if complete, OR <TOOL_CALL>...</TOOL_CALL> if more data needed."""
                
                else:  # Success but no data
                    system_feedback = f"""⚠️ ITERATION {iteration} RESULT: NO DATA

The query executed successfully but returned no results.

ACCUMULATED INSIGHTS:
{insights_summary}

STRATEGIC OPTIONS:
1. 🔍 Try different index from discovery context
2. ⏰ Broaden time range (e.g., -7d instead of -24h)
3. 🎯 Simplify search criteria
4. ✅ Accept "no data" as the legitimate answer

Current user intent understanding: "{user_intent}"

If you want to investigate further, use <TOOL_CALL>...</TOOL_CALL> with your strategy.
If "no data" IS the answer, provide final response WITHOUT tool calls."""
                
                conversation_history.append({"role": "system", "content": system_feedback})
                
                # Get LLM's next decision
                print(f"🤔 [Iteration {iteration}] Asking LLM for quality assessment...")
                action = "🧠 AI reasoning & quality assessment"
                elapsed = time_module.time() - start_time
                status_timeline.append({"iteration": iteration, "action": action, "time": elapsed})
                if status_callback:
                    await status_callback(action, iteration, elapsed)
                
                followup_max_tokens = min(2500, int(config.llm.max_tokens * 0.18))
                next_response = await llm_client.generate_response(
                    messages=conversation_history,
                    max_tokens=followup_max_tokens,
                    temperature=config.llm.temperature * 0.9  # Slightly lower temp for more focused decisions
                )
                
                # Parse LLM's response for tool call
                next_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*?\})\s*</TOOL_CALL>', next_response, re.DOTALL)
                
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
                
                # SMART DECISION LOGIC:
                # 1. If high quality answer (>= 70) - we're done regardless
                # 2. If converged (stuck) BUT doing post-processing - allow one more response
                # 3. If converged (stuck) - stop to avoid infinite loops  
                # 4. If low quality (< 50) AND LLM wants to continue - proceed
                # 5. If low quality but LLM says done - try to force one more attempt
                
                if quality_score >= 70:
                    # HIGH QUALITY - Accept answer
                    print(f"✅ [Iteration {iteration}] High quality answer ({quality_score}/100) - investigation complete")
                    final_answer = next_response
                    break
                
                elif is_converged:
                    # STUCK IN LOOP - Stop to avoid wasting resources
                    print(f"🛑 [Iteration {iteration}] Convergence detected - stopping to avoid loops")
                    final_answer = next_response + f"\n\n_Note: Investigation stopped after {iteration} iterations due to pattern convergence._"
                    break
                
                elif quality_score < 50:
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
                        
                        if continuation_intent or quality_score < 40:
                            # Add strict format enforcement message
                            format_enforcement = f"""❗ FORMAT ERROR: Your quality score is {quality_score}/100 (below threshold of 50).

You MUST continue investigating using the exact <TOOL_CALL> format:

<TOOL_CALL>
{{"tool": "run_splunk_query", "args": {{"query": "your SPL query here"}}}}
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
                            
                            retry_max_tokens = min(2000, int(config.llm.max_tokens * 0.15))
                            retry_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=retry_max_tokens,
                                temperature=config.llm.temperature * 0.7  # Lower temp for stricter format
                            )
                            
                            # Check if retry has proper format
                            retry_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*?\})\s*</TOOL_CALL>', retry_response, re.DOTALL)
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
{{"tool": "run_splunk_query", "args": {{"query": "your SPL query here"}}}}
</TOOL_CALL>

Based on your previous response, provide your next query NOW using the proper format above."""
                            
                            conversation_history.append({"role": "system", "content": format_enforcement})
                            
                            retry_max_tokens = min(2000, int(config.llm.max_tokens * 0.15))
                            retry_response = await llm_client.generate_response(
                                messages=conversation_history,
                                max_tokens=retry_max_tokens,
                                temperature=config.llm.temperature * 0.7
                            )
                            
                            retry_tool_match = re.search(r'<TOOL_CALL>\s*(\{.*?\})\s*</TOOL_CALL>', retry_response, re.DOTALL)
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
                            # Moderate quality, no tool call, no continuation intent - good enough
                            print(f"✅ [Iteration {iteration}] Moderate quality ({quality_score}/100) - accepting answer")
                            final_answer = next_response
                            break
            
            # Return comprehensive response with status timeline
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
                "discovery_age_warning": discovery_age_warning
            }
        
        # No tool call, return clean response with any SPL found
        return {
            "response": clean_response,
            "spl_in_text": spl_in_text,
            "discovery_age_warning": discovery_age_warning
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
        import ssl
        
        headers = {}
        if config.mcp.token:
            headers["Authorization"] = f"Bearer {config.mcp.token}"
        
        # Match discovery engine behavior: disable SSL verification by default for self-signed certificates
        # Can be overridden with config.security.verify_ssl = true + optional ca_bundle
        verify_ssl = getattr(config.security, 'verify_ssl', False) if hasattr(config, 'security') else False
        ca_bundle = getattr(config.security, 'ca_bundle_path', None) if hasattr(config, 'security') else None
        
        # Determine SSL verification setting
        if ca_bundle and verify_ssl:
            # Use custom CA bundle
            ssl_verify = ca_bundle
        elif verify_ssl:
            # Use system CA bundle (may fail with self-signed certs)
            print("INFO: SSL verification enabled with system CA bundle")
            ssl_verify = True
        else:
            # Disable SSL verification (for self-signed certs)
            ssl_verify = False
            if not hasattr(config, 'security') or not getattr(config.security, 'verify_ssl', None):
                print("INFO: SSL verification disabled for MCP calls (self-signed certificates)")
        
        async with httpx.AsyncClient(verify=ssl_verify, timeout=30.0) as client:
            response = await client.post(
                config.mcp.url,
                json=tool_call,
                headers=headers
            )
            
            if response.status_code == 200:
                mcp_response = response.json()
                
                # Debug: Log the MCP response structure
                tool_name = tool_call.get('params', {}).get('name', 'unknown')
                debug_log(f"🔍 MCP Response from {tool_name}", "response", {
                    "tool": tool_name,
                    "status": response.status_code,
                    "response_type": str(type(mcp_response)),
                    "response_keys": list(mcp_response.keys()) if isinstance(mcp_response, dict) else None
                })
                
                # Check for 'result' field
                if isinstance(mcp_response, dict) and 'result' in mcp_response:
                    result = mcp_response['result']
                    
                    # Check for results array
                    if isinstance(result, dict) and 'results' in result:
                        results_count = len(result['results']) if isinstance(result['results'], list) else 0
                        debug_log(f"📦 MCP returned {results_count} results", "response", {
                            "count": results_count,
                            "first_result_sample": result['results'][0] if results_count > 0 else None
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
            else:
                error_detail = response.text[:200] if response.text else "No error details"
                print(f"❌ MCP ERROR: Status {response.status_code} - {error_detail}")
                return {"error": f"MCP call failed: {response.status_code}", "detail": error_detail}
                
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
    </style>
</head>
<body class="bg-gray-50">
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect, useRef } = React;
        
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
            const [isConnected, setIsConnected] = useState(false);
            const [discoveryStatus, setDiscoveryStatus] = useState('idle');
            const [messages, setMessages] = useState([]);
            const [progress, setProgress] = useState({ percentage: 0, description: '' });
            const [reports, setReports] = useState([]);
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
            const [isConnectionModalOpen, setIsConnectionModalOpen] = useState(false);
            const [connectionInfo, setConnectionInfo] = useState(null);
            
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
            
            // Poll for summarization progress
            useEffect(() => {
                if (!isLoadingSummary || !currentSessionId) return;
                
                const interval = setInterval(async () => {
                    try {
                        const response = await fetch(`/summarize-progress/${currentSessionId}`);
                        const progress = await response.json();
                        setSummaryProgress(progress);
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
                
                return () => {
                    if (wsRef.current) {
                        wsRef.current.close();
                    }
                };
            }, []);
            
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
                        setDiscoveryStatus('completed');
                        loadReports();
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
                setDiscoveryStatus('starting');
                setMessages([]);
                setProgress({ percentage: 0, description: 'Initializing...' });
                
                try {
                    const response = await fetch('/start-discovery', { method: 'POST' });
                    const result = await response.json();
                    
                    if (result.error) {
                        addMessage('error', { message: result.error });
                        setDiscoveryStatus('error');
                    } else {
                        setDiscoveryStatus('running');
                    }
                } catch (error) {
                    addMessage('error', { message: `Failed to start discovery: ${error.message}` });
                    setDiscoveryStatus('error');
                }
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
                } catch (error) {
                    console.error('Failed to load reports:', error);
                    // Don't crash the UI - just show empty reports
                    setReports([]);
                }
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
                    setSelectedProvider(data.llm.provider || 'openai');
                } catch (error) {
                    console.error('Failed to load config:', error);
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
            
            const openConnectionModal = () => {
                loadConnectionInfo();
                setIsConnectionModalOpen(true);
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
                        
                        // Check if this is an AI summary file
                        if (report.name.startsWith('ai_summary_')) {
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
                        
                        // Check if this is an AI summary file
                        if (report.name.startsWith('ai_summary_')) {
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
            
            const sendChatMessage = async () => {
                if (!chatInput.trim() || isTyping) return;
                
                const userMessage = chatInput.trim();
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
                    const response = await fetch('/chat/stream', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            message: userMessage,
                            history: chatMessages.slice(-10) // Send last 10 messages for context
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
                                            status_timeline: result.status_timeline,
                                            iterations: result.iterations,
                                            execution_time: result.execution_time
                                        });
                                        
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
                    
                    const result = await response.json();
                    
                    if (result.error) {
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
                            <div className="bg-indigo-50 border-l-4 border-indigo-500 p-4 slide-in">
                                <h2 className="text-lg font-semibold text-indigo-900">{data.title}</h2>
                            </div>
                        );
                    
                    case 'success':
                        return (
                            <div className="flex items-center text-green-700 fade-in">
                                <i className="fas fa-check-circle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'error':
                        return (
                            <div className="flex items-center text-red-700 bg-red-50 p-3 rounded fade-in">
                                <i className="fas fa-exclamation-circle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'warning':
                        return (
                            <div className="flex items-center text-yellow-700 bg-yellow-50 p-3 rounded fade-in">
                                <i className="fas fa-exclamation-triangle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'info':
                        return (
                            <div className="flex items-center text-blue-700 fade-in">
                                <i className="fas fa-info-circle mr-2"></i>
                                <span>{data.message}</span>
                            </div>
                        );
                    
                    case 'overview':
                        return (
                            <div className="bg-blue-50 p-4 rounded-lg fade-in">
                                <h3 className="font-semibold text-blue-900 mb-2">Environment Overview</h3>
                                <div className="grid grid-cols-2 gap-2 text-sm">
                                    <div>Indexes: {data.total_indexes}</div>
                                    <div>Source Types: {data.total_sourcetypes}</div>
                                    <div>Data Volume: {data.data_volume_24h}</div>
                                    <div>Active Sources: {data.active_sources}</div>
                                </div>
                            </div>
                        );
                    
                    case 'rate_limit':
                        if (data.event === 'rate_limit_start') {
                            return (
                                <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg fade-in">
                                    <div className="flex items-center text-yellow-700">
                                        <i className="fas fa-clock mr-2"></i>
                                        <span>Rate limit encountered - waiting {data.details.delay}s (attempt {data.details.retry_count}/{data.details.max_retries})</span>
                                    </div>
                                </div>
                            );
                        } else if (data.event === 'rate_limit_countdown') {
                            return (
                                <div className="bg-yellow-50 p-3 rounded">
                                    <div className="flex items-center justify-between text-sm text-yellow-700">
                                        <span>Waiting...</span>
                                        <span>{Math.ceil(data.details.remaining_seconds)}s remaining</span>
                                    </div>
                                    <div className="w-full bg-yellow-200 rounded-full h-2 mt-2">
                                        <div 
                                            className="bg-yellow-500 h-2 rounded-full progress-bar"
                                            style={{ width: `${data.details.percentage}%` }}
                                        ></div>
                                    </div>
                                </div>
                            );
                        } else if (data.event === 'rate_limit_complete') {
                            return (
                                <div className="flex items-center text-green-700 fade-in">
                                    <i className="fas fa-check-circle mr-2"></i>
                                    <span>Rate limit wait complete - resuming</span>
                                </div>
                            );
                        }
                        break;
                    
                    case 'completion':
                        return (
                            <div className="bg-green-50 border border-green-200 p-4 rounded-lg fade-in">
                                <div className="flex items-center text-green-700 mb-2">
                                    <i className="fas fa-trophy mr-2"></i>
                                    <span className="font-semibold">Discovery Complete!</span>
                                </div>
                                <p className="text-sm text-green-600">Duration: {data.duration || 'N/A'}</p>
                                <p className="text-sm text-green-600">Generated {data.report_count || 0} reports</p>
                            </div>
                        );
                    
                    default:
                        return (
                            <div className="text-gray-600 fade-in">
                                <pre className="text-xs">{JSON.stringify(data, null, 2)}</pre>
                            </div>
                        );
                }
            };
            
            return (
                <div className="min-h-screen bg-gray-50">
                    {/* Header */}
                    <header className="bg-white shadow-sm border-b">
                        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                            <div className="flex justify-between items-center py-4">
                                <div className="flex items-center">
                                    <i className="fas fa-search text-2xl text-indigo-600 mr-3"></i>
                                    <h1 className="text-xl font-semibold text-gray-900">Splunk MCP Discovery Tool</h1>
                                </div>
                                <div className="flex items-center space-x-4">
                                    <button
                                        onClick={() => setIsChatOpen(true)}
                                        className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium flex items-center"
                                    >
                                        <i className="fas fa-comments mr-2"></i>
                                        Chat with Splunk
                                    </button>
                                    <div 
                                        className="flex items-center cursor-pointer hover:bg-gray-100 px-3 py-2 rounded-lg transition-colors"
                                        onClick={openConnectionModal}
                                        title="View connection details"
                                    >
                                        <div className={`w-3 h-3 rounded-full mr-2 ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
                                        <span className="text-sm text-gray-600">
                                            {isConnected ? 'Connected' : 'Disconnected'}
                                        </span>
                                    </div>
                                    <button
                                        onClick={startDiscovery}
                                        disabled={discoveryStatus === 'running'}
                                        className={`px-4 py-2 rounded-lg font-medium ${
                                            discoveryStatus === 'running'
                                                ? 'bg-gray-300 cursor-not-allowed'
                                                : 'bg-indigo-600 hover:bg-indigo-700 text-white'
                                        }`}
                                    >
                                        {discoveryStatus === 'running' ? (
                                            <>
                                                <i className="fas fa-spinner fa-spin mr-2"></i>
                                                Running...
                                            </>
                                        ) : (
                                            <>
                                                <i className="fas fa-play mr-2"></i>
                                                Start Discovery
                                            </>
                                        )}
                                    </button>
                                    <button
                                        onClick={openSettings}
                                        className="ml-3 px-4 py-2 rounded-lg font-medium bg-gray-100 hover:bg-gray-200 text-gray-700 border border-gray-300"
                                        title="Settings"
                                    >
                                        <i className="fas fa-cog"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </header>
                    
                    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                            {/* Main Content Area */}
                            <div className="lg:col-span-3">
                                {/* Progress Bar */}
                                {discoveryStatus === 'running' && (
                                    <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
                                        <div className="flex items-center justify-between mb-2">
                                            <h2 className="text-lg font-medium text-gray-900">Discovery Progress</h2>
                                            <span className="text-sm text-gray-500">{Math.round(progress.percentage)}%</span>
                                        </div>
                                        <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
                                            <div 
                                                className="bg-indigo-600 h-3 rounded-full progress-bar"
                                                style={{ width: `${progress.percentage}%` }}
                                            ></div>
                                        </div>
                                        <p className="text-sm text-gray-600">{progress.description}</p>
                                    </div>
                                )}
                                
                                {/* Messages */}
                                <div className="bg-white rounded-lg shadow-sm mb-6">
                                    <div className="p-6 border-b border-gray-200">
                                        <h2 className="text-lg font-medium text-gray-900">Discovery Log</h2>
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
                                        className="h-2 bg-gray-100 border-t border-gray-200 cursor-ns-resize hover:bg-gray-200 flex items-center justify-center group"
                                        onMouseDown={handleLogMouseDown}
                                    >
                                        <div className="w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500"></div>
                                    </div>
                                </div>
                                
                                {/* Report Viewer */}
                                {selectedReport && reportContent && (
                                    <div className="bg-white rounded-lg shadow-sm">
                                        <div className="p-6 border-b border-gray-200">
                                            <div className="flex justify-between items-center">
                                                <h3 className="text-lg font-medium text-gray-900">{selectedReport}</h3>
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
                                                <pre className="text-sm text-gray-800 whitespace-pre-wrap font-mono">
                                                    {JSON.stringify(reportContent.content, null, 2)}
                                                </pre>
                                            ) : (
                                                <div className="prose prose-sm max-w-none">
                                                    <pre className="text-sm text-gray-800 whitespace-pre-wrap font-sans leading-relaxed break-words">
                                                        {reportContent.content}
                                                    </pre>
                                                </div>
                                            )}
                                        </div>
                                        {/* Resize handle */}
                                        <div 
                                            className="h-2 bg-gray-100 border-t border-gray-200 cursor-ns-resize hover:bg-gray-200 flex items-center justify-center group"
                                            onMouseDown={handleReportMouseDown}
                                        >
                                            <div className="w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500"></div>
                                        </div>
                                    </div>
                                )}
                            </div>
                            
                            {/* Reports Sidebar */}
                            <div className="lg:col-span-1">
                                {/* Reports List */}
                                <div className="bg-white rounded-lg shadow-sm">
                                    <div className="p-6 border-b border-gray-200">
                                        <div className="flex justify-between items-center">
                                            <h2 className="text-lg font-medium text-gray-900">Generated Reports</h2>
                                            <button
                                                onClick={loadReports}
                                                className="text-indigo-600 hover:text-indigo-800"
                                            >
                                                <i className="fas fa-refresh"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div className="divide-y divide-gray-200">
                                        {reports.length === 0 ? (
                                            <p className="p-6 text-gray-500 text-center">No reports generated yet</p>
                                        ) : (
                                            (() => {
                                                const hierarchy = groupReportsByHierarchy(reports);
                                                return Object.entries(hierarchy).sort((a, b) => b[1].year - a[1].year).map(([yearKey, yearData]) => (
                                                    <div key={yearKey}>
                                                        {/* Year Header - Only show if not current year */}
                                                        {yearData.visible && (
                                                            <div 
                                                                className="p-3 bg-gradient-to-r from-indigo-100 to-purple-100 border-b cursor-pointer font-semibold"
                                                                onClick={() => toggleYear(yearKey)}
                                                            >
                                                                <div className="flex items-center">
                                                                    <i className={`fas ${expandedYears[yearKey] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-2 text-indigo-600 text-xs`}></i>
                                                                    <span className="text-sm text-indigo-900">{yearData.display}</span>
                                                                </div>
                                                            </div>
                                                        )}
                                                        
                                                        {/* Month Level */}
                                                        {(!yearData.visible || expandedYears[yearKey]) && Object.entries(yearData.months).sort((a, b) => b[1].month - a[1].month).map(([monthKey, monthData]) => (
                                                            <div key={monthKey}>
                                                                {/* Month Header - Only show if not current month or if year is visible */}
                                                                {monthData.visible && (
                                                                    <div 
                                                                        className="p-3 bg-gradient-to-r from-blue-50 to-indigo-50 border-b cursor-pointer"
                                                                        onClick={() => toggleMonth(monthKey)}
                                                                        style={{paddingLeft: yearData.visible ? '1.5rem' : '0.75rem'}}
                                                                    >
                                                                        <div className="flex items-center">
                                                                            <i className={`fas ${expandedMonths[monthKey] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-2 text-blue-600 text-xs`}></i>
                                                                            <span className="text-sm text-blue-900 font-medium">{monthData.display}</span>
                                                                        </div>
                                                                    </div>
                                                                )}
                                                                
                                                                {/* Day Level */}
                                                                {(!monthData.visible || expandedMonths[monthKey]) && Object.entries(monthData.days).sort((a, b) => b[1].day - a[1].day).map(([dayKey, dayData]) => (
                                                                    <div key={dayKey}>
                                                                        {/* Day Header */}
                                                                        <div 
                                                                            className={`p-3 ${dayData.isToday ? 'bg-green-50' : 'bg-gray-50'} hover:bg-gray-100 border-b cursor-pointer`}
                                                                            onClick={() => toggleDay(dayKey)}
                                                                            style={{paddingLeft: monthData.visible ? (yearData.visible ? '3rem' : '1.5rem') : (yearData.visible ? '1.5rem' : '0.75rem')}}
                                                                        >
                                                                            <div className="flex items-center">
                                                                                <i className={`fas ${expandedDays[dayKey] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-2 ${dayData.isToday ? 'text-green-600' : 'text-gray-500'} text-xs`}></i>
                                                                                <span className={`text-sm ${dayData.isToday ? 'text-green-900 font-semibold' : 'text-gray-900 font-medium'}`}>{dayData.display}</span>
                                                                                <span className="ml-2 text-xs text-gray-500">({dayData.sessions.length})</span>
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        {/* Sessions under this day */}
                                                                        {expandedDays[dayKey] && dayData.sessions.map((session) => (
                                                                            <div key={session.timestamp}>
                                                                                {/* Session Header */}
                                                                                <div 
                                                                                    className="p-4 bg-white hover:bg-gray-50 border-b cursor-pointer"
                                                                                    onClick={() => toggleSession(session.timestamp)}
                                                                                    style={{paddingLeft: monthData.visible ? (yearData.visible ? '4.5rem' : '3rem') : (yearData.visible ? '3rem' : '2rem')}}
                                                                                >
                                                                                    <div className="flex items-start justify-between">
                                                                                        <div className="flex items-start flex-1">
                                                                                            <i className={`fas ${expandedSessions[session.timestamp] ? 'fa-chevron-down' : 'fa-chevron-right'} mr-3 text-gray-500 text-xs mt-1`}></i>
                                                                                            <div className="flex-1">
                                                                                                <h3 className="text-sm font-semibold text-gray-900 mb-1">{formatSessionTime(session.timestamp)}</h3>
                                                                                                <div className="flex items-center space-x-3 text-xs text-gray-500">
                                                                                                    <span className="flex items-center">
                                                                                                        <i className="fas fa-file-alt mr-1"></i>
                                                                                                        {session.reports.length} reports
                                                                                                    </span>
                                                                                                </div>
                                                                                            </div>
                                                                                        </div>
                                                                                        <div className="flex items-center space-x-2">
                                                                                            <button
                                                                                                onClick={(e) => {
                                                                                                    e.stopPropagation();
                                                                                                    openSummaryModal(session.timestamp);
                                                                                                }}
                                                                                                className={`text-xs ${session.hasSummary ? 'bg-green-600 hover:bg-green-700' : 'bg-indigo-600 hover:bg-indigo-700'} text-white px-3 py-1 rounded flex items-center space-x-1`}
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
                                                                                    <div className="divide-y divide-gray-100">
                                                                                        {session.reports.map((report) => (
                                                                                            <div
                                                                                                key={report.name}
                                                                                                className={`p-4 hover:bg-gray-50 cursor-pointer ${
                                                                                                    selectedReport === report.name ? 'bg-indigo-50 border-r-4 border-indigo-500' : ''
                                                                                                }`}
                                                                                                onClick={() => loadReport(report.name)}
                                                                                                style={{paddingLeft: monthData.visible ? (yearData.visible ? '6rem' : '4.5rem') : (yearData.visible ? '4.5rem' : '3.5rem')}}
                                                                                            >
                                                                                                <div className="flex items-center justify-between">
                                                                                                    <div className="flex-1">
                                                                                                        <p className="text-sm font-medium text-gray-900">
                                                                                                            {report.name.replace(/_[0-9]{8}_[0-9]{6}/, '')}
                                                                                                        </p>
                                                                                                        <p className="text-xs text-gray-500">{(report.size / 1024).toFixed(1)} KB</p>
                                                                                                    </div>
                                                                                                    <div className="flex items-center space-x-2">
                                                                                                        <span className={`px-2 py-1 text-xs rounded ${
                                                                                                            report.type === 'json' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800'
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
                                                                        ))}
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
                                className="absolute bg-white rounded-xl shadow-2xl w-80"
                                onClick={(e) => e.stopPropagation()}
                                style={{
                                    top: '65px',
                                    left: '50%',
                                    marginLeft: '60px',
                                    boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
                                }}
                            >
                                {/* Speech bubble pointer - pointing to connection indicator above */}
                                <div className="absolute -top-2 left-8 w-4 h-4 bg-white rotate-45 border-l border-t border-gray-200"></div>
                                
                                {/* Modal Header */}
                                <div className="p-4 border-b border-gray-200 flex justify-between items-center relative z-10 bg-white rounded-t-xl">
                                    <div className="flex items-center">
                                        <i className="fas fa-plug text-lg text-indigo-600 mr-2"></i>
                                        <h2 className="text-base font-semibold text-gray-900">Connection Details</h2>
                                    </div>
                                    <button
                                        onClick={() => setIsConnectionModalOpen(false)}
                                        className="text-gray-400 hover:text-gray-600 transition-colors"
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
                            <div className="bg-white rounded-xl shadow-2xl w-full max-w-4xl h-5/6 flex flex-col">
                                {/* Chat Header */}
                                <div className="p-6 border-b border-gray-200 flex justify-between items-center">
                                    <div className="flex items-center">
                                        <i className="fas fa-comments text-2xl text-green-600 mr-3"></i>
                                        <h2 className="text-xl font-semibold text-gray-900">Chat with Splunk</h2>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <button
                                            onClick={() => setChatMessages([])}
                                            className="px-3 py-1 text-sm text-gray-600 hover:text-gray-800"
                                            title="Clear chat"
                                        >
                                            <i className="fas fa-trash"></i>
                                        </button>
                                        <button
                                            onClick={() => setIsChatOpen(false)}
                                            className="text-gray-500 hover:text-gray-700"
                                        >
                                            <i className="fas fa-times text-xl"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Chat Messages */}
                                <div className="flex-1 overflow-y-auto p-6 space-y-4">
                                    {chatMessages.length === 0 && (
                                        <div className="text-center text-gray-500 mt-12">
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
                                                    ? 'bg-red-50 text-red-800 border border-red-200'
                                                    : msg.type === 'warning'
                                                    ? 'bg-amber-50 text-amber-900 border border-amber-200'
                                                    : 'bg-gray-100 text-gray-800'
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
                                                                    <summary className="cursor-pointer text-sm font-medium text-gray-600 hover:text-gray-800 flex items-center">
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
                                                                            <div key={idx} className="flex items-center justify-between px-3 py-2 bg-gradient-to-r from-blue-50 to-purple-50 rounded border-l-4 border-blue-400">
                                                                                <span className="text-sm text-gray-700">{status.action}</span>
                                                                                <span className="text-xs text-gray-500">{status.time.toFixed(1)}s</span>
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                </details>
                                                            )}
                                                            
                                                            {/* Show raw MCP data if available */}
                                                            {msg.mcp_data && (
                                                                <details className="mt-3">
                                                                    <summary className="cursor-pointer text-sm text-gray-600 hover:text-gray-800">
                                                                        <i className="fas fa-database mr-1"></i>
                                                                        View Raw Data
                                                                    </summary>
                                                                    <pre className="mt-2 p-3 bg-gray-200 rounded text-xs overflow-x-auto">
                                                                        {JSON.stringify(msg.mcp_data, null, 2)}
                                                                    </pre>
                                                                </details>
                                                            )}
                                                            
                                                            {/* Indicate if follow-on is expected */}
                                                            {msg.has_follow_on && (
                                                                <div className="mt-2 text-xs text-indigo-600 flex items-center">
                                                                    <i className="fas fa-arrow-right mr-1"></i>
                                                                    <span>Follow-up action available</span>
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
                                                    <div className="flex items-start bg-amber-50 border-l-4 border-amber-400 p-4 rounded">
                                                        <i className="fas fa-exclamation-circle mr-3 mt-1 text-amber-600"></i>
                                                        <p className="flex-1 text-amber-800">{msg.content}</p>
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
                                            <div className="bg-gradient-to-r from-blue-50 to-green-50 text-gray-800 p-4 rounded-lg shadow-sm border border-blue-100">
                                                <div className="flex items-center space-x-3">
                                                    <i className="fas fa-robot text-green-600"></i>
                                                    <div className="flex space-x-1">
                                                        <div className="w-2 h-2 bg-green-500 rounded-full animate-bounce"></div>
                                                        <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                                                        <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                                                    </div>
                                                    {chatStatus && (
                                                        <span className="text-sm text-gray-600 ml-2 animate-pulse">
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
                                <div className="p-6 border-t border-gray-200">
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
                                            className="flex-1 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent resize-none"
                                            rows="3"
                                            disabled={isTyping}
                                        />
                                        <button
                                            onClick={sendChatMessage}
                                            disabled={!chatInput.trim() || isTyping}
                                            className={`px-6 py-3 rounded-lg font-medium ${
                                                chatInput.trim() && !isTyping
                                                    ? 'bg-indigo-600 hover:bg-indigo-700 text-white'
                                                    : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                                            }`}
                                        >
                                            <i className="fas fa-paper-plane"></i>
                                        </button>
                                    </div>
                                    <p className="text-xs text-gray-500 mt-2">
                                        Press Enter to send, Shift+Enter for new line • Ask about indexes, searches, data sources, or get help with SPL queries
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Summary Modal */}
                    {isSummaryModalOpen && (
                        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                            <div className="bg-white rounded-xl shadow-2xl w-full max-w-7xl h-5/6 flex flex-col">
                                {/* Header */}
                                <div className="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-t-xl">
                                    <div className="flex items-center">
                                        <i className={`fas ${summaryData?.from_cache ? 'fa-eye' : 'fa-magic'} text-2xl mr-3`}></i>
                                        <div>
                                            <h2 className="text-2xl font-bold">
                                                AI-Powered Summary
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
                                    <div className="border-b border-gray-200 bg-gray-50">
                                        <div className="flex space-x-1 px-6">
                                            <button
                                                onClick={() => setActiveTab('summary')}
                                                className={`px-6 py-3 font-medium text-sm transition-all ${
                                                    activeTab === 'summary'
                                                        ? 'border-b-2 border-indigo-600 text-indigo-600 bg-white'
                                                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                                                }`}
                                            >
                                                <i className="fas fa-brain mr-2"></i>
                                                Executive Summary
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('queries')}
                                                className={`px-6 py-3 font-medium text-sm transition-all ${
                                                    activeTab === 'queries'
                                                        ? 'border-b-2 border-indigo-600 text-indigo-600 bg-white'
                                                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                                                }`}
                                            >
                                                <i className="fas fa-code mr-2"></i>
                                                SPL Queries ({summaryData.spl_queries?.length || 0})
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('tasks')}
                                                className={`px-6 py-3 font-medium text-sm transition-all ${
                                                    activeTab === 'tasks'
                                                        ? 'border-b-2 border-indigo-600 text-indigo-600 bg-white'
                                                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
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
                                                    <div className="inline-block animate-spin rounded-full h-20 w-20 border-4 border-indigo-200 border-t-indigo-600"></div>
                                                    <i className="fas fa-brain absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-3xl text-indigo-600 animate-pulse"></i>
                                                </div>
                                                
                                                {/* Main Message */}
                                                <h3 className="text-2xl font-bold text-gray-800 mb-4">
                                                    Analyzing Your Splunk Environment
                                                </h3>
                                                
                                                {/* Progress Steps */}
                                                <div className="space-y-3 text-left bg-white rounded-lg shadow-sm border border-gray-200 p-4 mb-4">
                                                    {/* Stage 1: Loading Reports */}
                                                    <div className={`flex items-center text-sm ${summaryProgress.stage === 'loading' ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            ['generating_queries', 'identifying_unknowns', 'loading_reports', 'generating_summary', 'generating_tasks', 'saving', 'complete'].includes(summaryProgress.stage)
                                                                ? 'bg-green-500' 
                                                                : summaryProgress.stage === 'loading'
                                                                    ? 'bg-indigo-500'
                                                                    : 'border-2 border-gray-300'
                                                        }`}>
                                                            {['generating_queries', 'identifying_unknowns', 'loading_reports', 'generating_summary', 'generating_tasks', 'saving', 'complete'].includes(summaryProgress.stage) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : summaryProgress.stage === 'loading' ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={summaryProgress.stage === 'loading' ? 'text-gray-700 font-medium' : 'text-gray-700'}>
                                                            Loading discovery reports...
                                                        </span>
                                                    </div>
                                                    
                                                    {/* Stage 2: Generating Queries */}
                                                    <div className={`flex items-center text-sm ${['generating_queries', 'identifying_unknowns', 'loading_reports'].includes(summaryProgress.stage) ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            ['generating_summary', 'generating_tasks', 'saving', 'complete'].includes(summaryProgress.stage)
                                                                ? 'bg-green-500' 
                                                                : ['generating_queries', 'identifying_unknowns', 'loading_reports'].includes(summaryProgress.stage)
                                                                    ? 'bg-indigo-500'
                                                                    : 'border-2 border-gray-300'
                                                        }`}>
                                                            {['generating_summary', 'generating_tasks', 'saving', 'complete'].includes(summaryProgress.stage) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : ['generating_queries', 'identifying_unknowns', 'loading_reports'].includes(summaryProgress.stage) ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={['generating_queries', 'identifying_unknowns', 'loading_reports'].includes(summaryProgress.stage) ? 'text-gray-700 font-medium' : 'text-gray-500'}>
                                                            Generating SPL queries...
                                                        </span>
                                                    </div>
                                                    
                                                    {/* Stage 3: Creating Tasks */}
                                                    <div className={`flex items-center text-sm ${summaryProgress.stage === 'generating_tasks' ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            ['saving', 'complete'].includes(summaryProgress.stage)
                                                                ? 'bg-green-500' 
                                                                : summaryProgress.stage === 'generating_tasks'
                                                                    ? 'bg-indigo-500'
                                                                    : 'border-2 border-gray-300'
                                                        }`}>
                                                            {['saving', 'complete'].includes(summaryProgress.stage) ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : summaryProgress.stage === 'generating_tasks' ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={summaryProgress.stage === 'generating_tasks' ? 'text-gray-700 font-medium' : 'text-gray-500'}>
                                                            Creating admin tasks...
                                                        </span>
                                                    </div>
                                                    
                                                    {/* Stage 4: Building Summary */}
                                                    <div className={`flex items-center text-sm ${summaryProgress.stage === 'generating_summary' ? 'animate-pulse' : ''}`}>
                                                        <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
                                                            summaryProgress.stage === 'complete'
                                                                ? 'bg-green-500' 
                                                                : summaryProgress.stage === 'generating_summary'
                                                                    ? 'bg-indigo-500'
                                                                    : 'border-2 border-gray-300'
                                                        }`}>
                                                            {summaryProgress.stage === 'complete' ? (
                                                                <i className="fas fa-check text-white text-xs"></i>
                                                            ) : summaryProgress.stage === 'generating_summary' ? (
                                                                <div className="w-2 h-2 bg-white rounded-full animate-ping"></div>
                                                            ) : null}
                                                        </div>
                                                        <span className={summaryProgress.stage === 'generating_summary' ? 'text-gray-700 font-medium' : 'text-gray-500'}>
                                                            Building executive summary...
                                                        </span>
                                                    </div>
                                                </div>
                                                
                                                {/* Progress Bar */}
                                                <div className="mb-4">
                                                    <div className="flex justify-between items-center mb-1">
                                                        <span className="text-xs font-medium text-gray-700">{summaryProgress.message}</span>
                                                        <span className="text-xs font-semibold text-indigo-600">{summaryProgress.progress}%</span>
                                                    </div>
                                                    <div className="w-full bg-gray-200 rounded-full h-2">
                                                        <div 
                                                            className="bg-gradient-to-r from-indigo-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
                                                            style={{width: `${summaryProgress.progress}%`}}
                                                        ></div>
                                                    </div>
                                                </div>
                                                
                                                {/* Fun Facts */}
                                                <div className="text-xs text-gray-500 italic">
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
                                                    <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border-l-4 border-indigo-600 p-6 rounded-r-lg">
                                                        <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                                                            <i className="fas fa-brain text-indigo-600 mr-2"></i>
                                                            Executive Summary
                                                        </h3>
                                                        <div className="prose max-w-none">
                                                            <pre className="whitespace-pre-wrap font-sans text-gray-700">{summaryData.ai_summary}</pre>
                                                        </div>
                                                    </div>
                                                    
                                                    {/* Stats Section */}
                                                    {summaryData.stats && (
                                                        <div className="grid grid-cols-3 gap-4">
                                                            <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-center">
                                                                <div className="text-3xl font-bold text-green-600">{summaryData.stats.total_queries}</div>
                                                                <div className="text-sm text-green-700 mt-1">SPL Queries Generated</div>
                                                            </div>
                                                            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-center">
                                                                <div className="text-3xl font-bold text-blue-600">{summaryData.stats.categories?.length || 0}</div>
                                                                <div className="text-sm text-blue-700 mt-1">Use Case Categories</div>
                                                            </div>
                                                            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 text-center">
                                                                <div className="text-3xl font-bold text-orange-600">{summaryData.stats.unknown_items}</div>
                                                                <div className="text-sm text-orange-700 mt-1">Data Sources Needing Review</div>
                                                            </div>
                                                        </div>
                                                    )}
                                                    
                                                    {/* Unknown Data Section */}
                                                    {summaryData.unknown_data && summaryData.unknown_data.length > 0 && (
                                                        <div>
                                                            <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                                                                <i className="fas fa-question-circle text-orange-600 mr-2"></i>
                                                                Help Us Understand Your Data ({summaryData.unknown_data.length})
                                                            </h3>
                                                            <p className="text-sm text-gray-600 mb-4">
                                                                We found some data sources we're not familiar with. Your answers will help us provide better recommendations.
                                                            </p>
                                                            <div className="space-y-4">
                                                                {summaryData.unknown_data.slice(0, 3).map((item, idx) => (
                                                                    <div key={idx} className="border border-orange-200 rounded-lg p-4 bg-orange-50">
                                                                        <div className="flex items-center justify-between">
                                                                            <h4 className="text-base font-semibold text-gray-900">
                                                                                {item.type === 'index' ? '📦' : '📄'} 
                                                                                <code className="ml-2 px-2 py-1 bg-white rounded text-sm">{item.name}</code>
                                                                            </h4>
                                                                            <span className="text-xs text-gray-500">{item.type}</span>
                                                                        </div>
                                                                        {item.reason && (
                                                                            <p className="text-sm text-gray-600 mt-2">{item.reason}</p>
                                                                        )}
                                                                    </div>
                                                                ))}
                                                                {summaryData.unknown_data.length > 3 && (
                                                                    <p className="text-sm text-gray-500 text-center">
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
                                                <div>
                                                    <div className="flex items-center justify-between mb-4">
                                                        <h3 className="text-xl font-semibold text-gray-900 flex items-center">
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
                                                                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                                                                }`}
                                                            >
                                                                All ({summaryData.spl_queries.length})
                                                            </button>
                                                            <button
                                                                onClick={() => setQueryFilter('ai_finding')}
                                                                className={`px-3 py-1 text-sm font-medium rounded-lg transition-colors flex items-center space-x-1 ${
                                                                    queryFilter === 'ai_finding' 
                                                                        ? 'bg-purple-600 text-white' 
                                                                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
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
                                                                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
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
                                                                query.priority?.startsWith('🔴') ? 'border-red-300 bg-red-50' :
                                                                query.priority?.startsWith('🟠') ? 'border-orange-300 bg-orange-50' :
                                                                query.priority?.startsWith('🟡') ? 'border-yellow-300 bg-yellow-50' :
                                                                'border-gray-200'
                                                            }`}>
                                                                {/* Priority Badge */}
                                                                {query.priority && (
                                                                    <div className="mb-2">
                                                                        <span className={`px-3 py-1 text-xs font-bold rounded-full ${
                                                                            query.priority.startsWith('🔴') ? 'bg-red-600 text-white' :
                                                                            query.priority.startsWith('🟠') ? 'bg-orange-600 text-white' :
                                                                            query.priority.startsWith('🟡') ? 'bg-yellow-600 text-white' :
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
                                                                            <h4 className="text-lg font-semibold text-gray-900">{query.title}</h4>
                                                                            <span className={`px-2 py-1 text-xs rounded-full ${
                                                                                query.category === 'Security & Compliance' ? 'bg-red-100 text-red-700' :
                                                                                query.category === 'Infrastructure & Performance' ? 'bg-blue-100 text-blue-700' :
                                                                                query.category === 'Capacity Planning' ? 'bg-green-100 text-green-700' :
                                                                                'bg-gray-100 text-gray-700'
                                                                            }`}>
                                                                                {query.category}
                                                                            </span>
                                                                            <span className="px-2 py-1 text-xs bg-purple-100 text-purple-700 rounded-full">
                                                                                {query.difficulty}
                                                                            </span>
                                                                        </div>
                                                                        <p className="text-sm text-gray-600 mb-2">{query.description}</p>
                                                                        
                                                                        {/* Finding Reference */}
                                                                        {query.finding_reference && (
                                                                            <div className="mt-2 p-2 bg-indigo-50 border-l-2 border-indigo-600 rounded-r text-xs text-indigo-900">
                                                                                <strong>📋 Discovery Finding:</strong> {query.finding_reference}
                                                                            </div>
                                                                        )}
                                                                        
                                                                        <div className="flex items-center space-x-4 text-xs text-gray-500 mt-2">
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
                                                                    <summary className="cursor-pointer text-sm font-medium text-indigo-600 hover:text-indigo-800">
                                                                        <i className="fas fa-code mr-1"></i>
                                                                        View SPL Code
                                                                    </summary>
                                                                    <pre className="mt-2 p-4 bg-gray-900 text-green-400 rounded text-sm overflow-x-auto">
{query.spl}
                                                                    </pre>
                                                                </details>
                                                                
                                                                {query.business_value && (
                                                                    <div className="mt-3 p-3 bg-yellow-50 border-l-4 border-yellow-400 rounded-r">
                                                                        <p className="text-sm text-yellow-900">
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
                                                <div>
                                                    {summaryData.admin_tasks && summaryData.admin_tasks.length > 0 ? (
                                                        <div>
                                                            <div className="mb-6">
                                                                <h3 className="text-2xl font-bold text-gray-900 mb-2 flex items-center">
                                                                    <i className="fas fa-tasks text-indigo-600 mr-3"></i>
                                                                    Recommended Implementation Tasks
                                                                </h3>
                                                                <p className="text-gray-600">
                                                                    Prioritized tasks based on your environment analysis. Each includes step-by-step guidance and verification queries.
                                                                </p>
                                                            </div>
                                                            
                                                            <div className="space-y-4">
                                                                {summaryData.admin_tasks.map((task, idx) => {
                                                                    const progress = getTaskProgress(currentSessionId, idx);
                                                                    const completionPct = getTaskCompletionPercentage(currentSessionId, idx, task.steps?.length || 0);
                                                                    
                                                                    return (
                                                                    <div key={idx} className={`border-2 rounded-lg overflow-hidden transition-all ${
                                                                        progress.status === 'completed' ? 'border-green-400 bg-green-50 opacity-90' :
                                                                        progress.status === 'in-progress' ? 'border-indigo-400 bg-indigo-50' :
                                                                        task.priority === 'HIGH' ? 'border-red-300 bg-red-50' :
                                                                        task.priority === 'MEDIUM' ? 'border-orange-300 bg-orange-50' :
                                                                        'border-yellow-300 bg-yellow-50'
                                                                    }`}>
                                                                        {/* Task Header */}
                                                                        <div className="p-5 bg-white border-b border-gray-200">
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
                                                                                            'bg-yellow-600 text-white'
                                                                                        }`}>
                                                                                            {task.priority === 'HIGH' ? '🔴 HIGH' : 
                                                                                             task.priority === 'MEDIUM' ? '🟠 MEDIUM' : '🟡 LOW'} PRIORITY
                                                                                        </span>
                                                                                        
                                                                                        {/* Category Badge */}
                                                                                        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                                                                                            task.category === 'Security' ? 'bg-red-100 text-red-700' :
                                                                                            task.category === 'Performance' ? 'bg-blue-100 text-blue-700' :
                                                                                            task.category === 'Compliance' ? 'bg-purple-100 text-purple-700' :
                                                                                            task.category === 'Data Quality' ? 'bg-green-100 text-green-700' :
                                                                                            'bg-gray-100 text-gray-700'
                                                                                        }`}>
                                                                                            {task.category}
                                                                                        </span>
                                                                                        
                                                                                        {/* Time Estimate */}
                                                                                        {task.estimated_time && (
                                                                                            <span className="px-2 py-1 text-xs bg-indigo-100 text-indigo-700 rounded-full">
                                                                                                <i className="fas fa-clock mr-1"></i>
                                                                                                {task.estimated_time}
                                                                                            </span>
                                                                                        )}
                                                                                    </div>
                                                                                    
                                                                                    <h4 className="text-xl font-bold text-gray-900 mb-2">{task.title}</h4>
                                                                                    <p className="text-sm text-gray-700">{task.description}</p>
                                                                                    
                                                                                    {/* Progress Bar */}
                                                                                    <div className="mt-3">
                                                                                        <div className="flex items-center justify-between text-xs text-gray-600 mb-1">
                                                                                            <span className="font-medium">Progress: {completionPct}%</span>
                                                                                            <span>{progress.completedSteps.length} / {task.steps?.length || 0} steps</span>
                                                                                        </div>
                                                                                        <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
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
                                                                                <div className="mt-3 p-3 bg-green-50 border-l-4 border-green-500 rounded-r">
                                                                                    <p className="text-sm text-green-900">
                                                                                        <i className="fas fa-chart-line mr-2"></i>
                                                                                        <strong>Impact:</strong> {task.impact}
                                                                                    </p>
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Task Details - Expandable */}
                                                                        <details className="group" open={progress.status === 'in-progress'}>
                                                                            <summary className="cursor-pointer bg-gradient-to-r from-indigo-50 to-purple-50 px-5 py-3 hover:from-indigo-100 hover:to-purple-100 transition-colors list-none flex items-center justify-between">
                                                                                <span className="font-semibold text-gray-900 flex items-center">
                                                                                    <i className="fas fa-chevron-right mr-2 group-open:rotate-90 transition-transform"></i>
                                                                                    Implementation Steps
                                                                                </span>
                                                                                <span className="text-sm text-gray-600">
                                                                                    {task.steps?.length || 0} steps
                                                                                </span>
                                                                            </summary>
                                                                            
                                                                            <div className="p-5 bg-white space-y-4">
                                                                                {/* Prerequisites */}
                                                                                {task.prerequisites && task.prerequisites.length > 0 && (
                                                                                    <div className="mb-4">
                                                                                        <h5 className="font-semibold text-gray-900 mb-2 flex items-center">
                                                                                            <i className="fas fa-list-check mr-2 text-blue-600"></i>
                                                                                            Prerequisites
                                                                                        </h5>
                                                                                        <ul className="space-y-1">
                                                                                            {task.prerequisites.map((prereq, pIdx) => (
                                                                                                <li key={pIdx} className="text-sm text-gray-700 flex items-start">
                                                                                                    <i className="fas fa-angle-right mr-2 mt-1 text-blue-500"></i>
                                                                                                    <span>{prereq}</span>
                                                                                                </li>
                                                                                            ))}
                                                                                        </ul>
                                                                                    </div>
                                                                                )}
                                                                                
                                                                                {/* Implementation Steps with Checkboxes */}
                                                                                <div>
                                                                                    <h5 className="font-semibold text-gray-900 mb-3 flex items-center">
                                                                                        <i className="fas fa-clipboard-list mr-2 text-indigo-600"></i>
                                                                                        Implementation Steps
                                                                                    </h5>
                                                                                    <div className="space-y-3">
                                                                                        {task.steps?.map((step, sIdx) => {
                                                                                            const isCompleted = progress.completedSteps.includes(step.number);
                                                                                            
                                                                                            return (
                                                                                            <div key={sIdx} className={`border-2 rounded-lg p-4 transition-all ${
                                                                                                isCompleted ? 'border-green-300 bg-green-50' : 'border-gray-200 bg-gray-50'
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
                                                                                                            isCompleted ? 'text-gray-500 line-through' : 'text-gray-900'
                                                                                                        }`}>{step.action}</p>
                                                                                                    </div>
                                                                                                </div>
                                                                                                
                                                                                                {/* SPL Query for this step */}
                                                                                                {step.spl && (
                                                                                                    <div className="mt-3 ml-16">
                                                                                                        <div className="flex items-center justify-between mb-1">
                                                                                                            <span className="text-xs font-semibold text-gray-600">SPL Query:</span>
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
                                                                                        <div className="p-4 bg-blue-50 border-l-4 border-blue-500 rounded-r">
                                                                                            <div className="flex items-center justify-between mb-2">
                                                                                                <h5 className="font-semibold text-blue-900 flex items-center">
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
                                                                                            
                                                                                            <p className="text-sm text-blue-800 mb-2">
                                                                                                <strong>Expected Outcome:</strong> {task.expected_outcome}
                                                                                            </p>
                                                                                            
                                                                                            <details className="mt-2">
                                                                                                <summary className="cursor-pointer text-xs font-semibold text-blue-700 hover:text-blue-900">
                                                                                                    <i className="fas fa-code mr-1"></i>
                                                                                                    View Verification SPL
                                                                                                </summary>
                                                                                                <div className="mt-2 flex items-center justify-between mb-1">
                                                                                                    <span className="text-xs text-blue-700"></span>
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
                                                                                                                <span className="px-3 py-1 bg-yellow-600 text-white text-xs font-bold rounded-full">
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
                                                                                                        verResult.status === 'success' ? 'text-green-900' :
                                                                                                        verResult.status === 'partial' ? 'text-yellow-900' :
                                                                                                        verResult.status === 'failed' ? 'text-red-900' :
                                                                                                        'text-gray-900'
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
                            <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                                <div className="p-6 border-b border-gray-200">
                                    <div className="flex items-center justify-between">
                                        <h2 className="text-2xl font-semibold text-gray-900">
                                            <i className="fas fa-cog mr-2 text-indigo-600"></i>
                                            Settings
                                        </h2>
                                        <button onClick={closeSettings} className="text-gray-500 hover:text-gray-700">
                                            <i className="fas fa-times text-xl"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                <div className="p-6 space-y-6">
                                    {/* MCP Configuration */}
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900 mb-3">
                                            <i className="fas fa-server mr-2 text-green-600"></i>
                                            MCP Server Configuration
                                        </h3>
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
                                                    placeholder={config.mcp.token === '***' ? '(Already Configured)' : 'Enter token'}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="mcp-token"
                                                />
                                            </div>
                                            <div className="flex items-center">
                                                <input 
                                                    type="checkbox" 
                                                    defaultChecked={config.mcp.verify_ssl}
                                                    className="mr-2"
                                                    id="mcp-verify-ssl"
                                                />
                                                <label htmlFor="mcp-verify-ssl" className="text-sm text-gray-700">Verify SSL Certificate</label>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* LLM Configuration */}
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900 mb-3">
                                            <i className="fas fa-brain mr-2 text-purple-600"></i>
                                            LLM Configuration
                                        </h3>
                                        <div className="space-y-3">
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-1">Provider</label>
                                                <select 
                                                    defaultValue={config.llm.provider}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="llm-provider"
                                                    onChange={(e) => setSelectedProvider(e.target.value)}
                                                >
                                                    <option value="openai">OpenAI</option>
                                                    <option value="custom">Custom Endpoint</option>
                                                </select>
                                            </div>
                                            {(selectedProvider === 'custom' || config.llm.provider === 'custom') && (
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                                        Endpoint URL
                                                        <span className="ml-2 text-xs text-gray-500">
                                                            (e.g., http://localhost:11434 for Ollama)
                                                        </span>
                                                    </label>
                                                    <input 
                                                        type="text" 
                                                        defaultValue={config.llm.endpoint_url || ''}
                                                        placeholder="http://localhost:11434"
                                                        className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                        id="llm-endpoint-url"
                                                    />
                                                    <p className="mt-1 text-xs text-gray-500">
                                                        For OpenAI-compatible APIs (Ollama, LM Studio, vLLM, etc.)
                                                    </p>
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
                                                    placeholder={config.llm.api_key === '***' ? '(Already Configured)' : 'Enter API key'}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="llm-api-key"
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-1">Model</label>
                                                <input 
                                                    type="text" 
                                                    defaultValue={config.llm.model}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                                                    id="llm-model"
                                                />
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
                                                                        endpoint_url: (provider === 'custom' && endpointUrlInput) ? endpointUrlInput.value : undefined,
                                                                        max_tokens: parseInt(document.getElementById('llm-max-tokens').value),
                                                                        temperature: parseFloat(document.getElementById('llm-temperature').value)
                                                                    }
                                                                })
                                                            });
                                                            
                                                            // Then test the connection
                                                            const response = await fetch('/api/llm/test-connection', { method: 'POST' });
                                                            const result = await response.json();
                                                            
                                                            let html = '<div className="space-y-2">';
                                                            
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
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Server Configuration */}
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900 mb-3">
                                            <i className="fas fa-server mr-2 text-blue-600"></i>
                                            Server Configuration
                                        </h3>
                                        <div className="space-y-3">
                                            <div className="flex items-start">
                                                <input 
                                                    type="checkbox" 
                                                    defaultChecked={config.server.debug_mode}
                                                    className="mr-2 mt-1"
                                                    id="server-debug-mode"
                                                    onChange={(e) => {
                                                        // Show/hide debug button based on checkbox
                                                        const btn = document.getElementById('open-debug-btn');
                                                        if (btn) btn.style.display = e.target.checked ? 'inline-block' : 'none';
                                                    }}
                                                />
                                                <div>
                                                    <label htmlFor="server-debug-mode" className="text-sm font-medium text-gray-700">
                                                        Debug Mode
                                                    </label>
                                                    <p className="text-xs text-gray-500 mt-1">
                                                        Stream debug logs to a popup window in real-time. No secrets will be shown.
                                                    </p>
                                                    <button
                                                        id="open-debug-btn"
                                                        style={{display: config.server.debug_mode ? 'inline-block' : 'none'}}
                                                        onClick={() => {
                                                                const debugWindow = window.open('', 'debug-logs', 'width=800,height=600,scrollbars=yes');
                                                                if (debugWindow) {
                                                                    const doc = debugWindow.document;
                                                                    doc.open();
                                                                    doc.write('<html><head><title>DT4SMS Debug Logs</title>');
                                                                    doc.write('<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:10px}');
                                                                    doc.write('.log{margin:5px 0;padding:5px;border-left:3px solid #666}');
                                                                    doc.write('.log.info{border-color:#4a9eff}.log.warning{border-color:#ffa500;color:#ffa500}');
                                                                    doc.write('.log.error{border-color:#ff4444;color:#ff4444}.log.query{border-color:#00ff00;color:#00ff00}');
                                                                    doc.write('.log.response{border-color:#ff69b4;color:#ff69b4}.timestamp{color:#888;font-size:0.9em}');
                                                                    doc.write('pre{margin:5px 0;white-space:pre-wrap;word-wrap:break-word}</style></head>');
                                                                    doc.write('<body><h2>🐛 DT4SMS Debug Logs</h2><div id="logs"></div></body></html>');
                                                                    doc.close();
                                                                    const script = doc.createElement('script');
                                                                    script.textContent = 'const ws=new WebSocket("ws://"+location.hostname+":8003/ws/debug");' +
                                                                        'const logsDiv=document.getElementById("logs");' +
                                                                        'ws.onmessage=(e)=>{const d=JSON.parse(e.data);const l=document.createElement("div");' +
                                                                        'l.className="log "+(d.category||"info");' +
                                                                        'let c="<span class=\\\\"timestamp\\\\">["+ new Date(d.timestamp).toLocaleTimeString()+"]</span> ";' +
                                                                        'c+=d.message;if(d.data){c+="<pre>"+JSON.stringify(d.data,null,2)+"</pre>";}' +
                                                                        'l.innerHTML=c;logsDiv.appendChild(l);logsDiv.scrollTop=logsDiv.scrollHeight;};' +
                                                                        'ws.onopen=()=>{const l=document.createElement("div");l.className="log info";' +
                                                                        'l.textContent="✅ Connected";logsDiv.appendChild(l);};' +
                                                                        'ws.onerror=()=>{const l=document.createElement("div");l.className="log error";' +
                                                                        'l.textContent="❌ Error";logsDiv.appendChild(l);};';
                                                                    doc.body.appendChild(script);
                                                                } else {
                                                                    alert('Please allow popups for this site to view debug logs');
                                                                }
                                                            }}
                                                            className="mt-2 px-3 py-1 text-xs bg-blue-100 hover:bg-blue-200 text-blue-700 rounded"
                                                        >
                                                            <i className="fas fa-external-link-alt mr-1"></i>
                                                            Open Debug Window
                                                        </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Action Buttons */}
                                    <div className="flex justify-between items-center pt-4 border-t">
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
                                            className="px-4 py-2 text-sm bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg font-medium"
                                        >
                                            <i className="fas fa-list mr-2"></i>
                                            View Dependencies
                                        </button>
                                        <button
                                            onClick={async () => {
                                                const provider = document.getElementById('llm-provider').value;
                                                const endpointUrlInput = document.getElementById('llm-endpoint-url');
                                                
                                                const settings = {
                                                    mcp: {
                                                        url: document.getElementById('mcp-url').value,
                                                        token: document.getElementById('mcp-token').value || undefined,
                                                        verify_ssl: document.getElementById('mcp-verify-ssl').checked
                                                    },
                                                    llm: {
                                                        provider: provider,
                                                        api_key: document.getElementById('llm-api-key').value || undefined,
                                                        model: document.getElementById('llm-model').value,
                                                        endpoint_url: (provider === 'custom' && endpointUrlInput) ? endpointUrlInput.value : undefined,
                                                        max_tokens: parseInt(document.getElementById('llm-max-tokens').value),
                                                        temperature: parseFloat(document.getElementById('llm-temperature').value)
                                                    },
                                                    server: {
                                                        ...config.server,
                                                        debug_mode: document.getElementById('server-debug-mode').checked
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
    
    # Fix encoding issues on Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    
    print("Starting Splunk MCP Discovery Tool Web Interface")
    print("Access the interface at: http://localhost:8003")
    print("WebSocket endpoint: ws://localhost:8003/ws")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8003,
        log_level="info",
        reload=False  # Set to True for development
    )
