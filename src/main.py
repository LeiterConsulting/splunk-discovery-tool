"""
Discovery Tool for Splunk MCP Server (DT4SMS)
Main application entry point
Version: 1.0.0
"""

import uvicorn
import sys
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web_app import app, config_manager


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
    is_tool_process = ("main.py" in cmdline) or ("web_app.py" in cmdline)
    return is_tool_process and (workspace_norm in cmdline)


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


def _resolve_startup_port(preferred_port: int, max_scan_ports: int = 20) -> int:
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

def main():
    """Main entry point"""
    config = config_manager.get()
    startup_port = _resolve_startup_port(int(config.server.port))
    if startup_port != int(config.server.port):
        print(f" Preferred port {config.server.port} unavailable; using fallback port {startup_port}")
    
    print("=" * 60)
    print(" Discovery Tool for Splunk MCP Server (DT4SMS)")
    print(f" Version: {config.version}")
    print("=" * 60)
    print(f" Web Interface: http://localhost:{startup_port}")
    print(f" Settings: Click gear icon in web interface")
    print("=" * 60)
    
    # Start server
    uvicorn.run(
        app,
        host=config.server.host,
        port=startup_port,
        log_level="info"
    )

if __name__ == "__main__":
    main()
