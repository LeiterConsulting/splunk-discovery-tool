# Discovery Tool for Splunk MCP Server (DT4SMS) - v1.0.0

## Project Overview
Cross-platform Splunk discovery tool with universal installer, encrypted configuration, and web-based settings management.

## Architecture
- **Universal Installer**: Single script supporting Windows/Unix/macOS with OS auto-detection
- **Encrypted Config**: Fernet encryption for MCP/LLM credentials (no plaintext storage)
- **Web UI**: FastAPI backend with settings panel for all configuration
- **Service Mode**: Background daemon with restart/shutdown capabilities

## Development Status
✅ Workspace created
✅ Universal installers created (install.sh, install.ps1)
✅ Encrypted configuration system implemented
✅ FastAPI web application with settings UI
✅ Service management (start/stop/restart/uninstall)
✅ Complete documentation (README.md)
✅ Ready for testing and deployment

## Quick Start
Run `./install.sh` (Unix/macOS) or `.\install.ps1` (Windows) to install and start the application.
Access web interface at http://localhost:8003
