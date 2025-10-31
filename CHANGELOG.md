# Changelog

All notable changes to the Splunk Discovery Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-31

### 🎉 Initial Release

First production-ready release of the Splunk Discovery Tool with AI-powered admin assistance.

### Added

#### Core Features
- **AI-Powered Admin Chat**: Natural language Splunk administration with intelligent SPL query generation
- **Multi-Turn Reasoning**: Automatic query refinement with quality validation (0-100 scale)
- **Smart Convergence Detection**: Prevents infinite loops while allowing data quality improvements
- **Discovery Engine**: Automated Splunk environment scanning via MCP protocol
- **Real-Time WebSocket**: Live updates for discovery progress and chat interactions

#### Configuration & Security
- **Encrypted Configuration**: Fernet encryption for all credentials (no plaintext storage)
- **Web-Based Settings Panel**: Complete configuration management through intuitive UI
- **Universal Installers**: Cross-platform installation scripts for Windows (`install.ps1`) and Unix/macOS (`install.sh`)
- **Service Management**: Background daemon with `--start`, `--stop`, `--restart`, `--uninstall` commands

#### User Interface
- **Modern Web Interface**: React-based frontend with FastAPI backend
- **Three Main Tabs**: Discovery, Chat, Reports
- **Settings Modal**: Comprehensive configuration for MCP server, LLM provider, and web server
- **Debug Mode**: Optional real-time debug window with WebSocket streaming
- **Dependencies Viewer**: Modal showing installed Python packages and versions

#### Quality & Reliability
- **Quality Assessment**: Intelligent scoring system for SPL query results
  - High (≥70): Immediately usable results
  - Moderate (50-69): Accept if actionable or continue refining
  - Low (<50): Force query refinement with format requirements
- **Timestamp Formatting Detection**: Prevents convergence during post-processing steps
- **Diversity Requirements**: SPL query generation with temperature 0.75 to ensure varied approaches
- **Error Handling**: Comprehensive error messages and debug logging

#### Developer Experience
- **Clean Codebase**: Removed unused modules (CLI, classification, recommendations, output)
- **Type Safety**: Pydantic models for configuration and API requests
- **Async/Await**: Modern async Python for efficient I/O operations
- **Documented Code**: Inline comments and clear function signatures

### Technical Details

#### Dependencies
- FastAPI 0.104.0+ (web framework)
- Uvicorn 0.24.0+ (ASGI server)
- Cryptography 41.0.0+ (encryption)
- PyYAML 6.0+ (configuration)
- HTTPX 0.24.0+ (HTTP client)
- AIOHTTP 3.9.0+ (async HTTP)
- OpenAI 1.0.0+ (LLM integration)
- Python 3.8+ (runtime)

#### Architecture
- **Port**: 8003 (configurable)
- **Protocol**: HTTP + WebSocket
- **Storage**: Encrypted config file (`config.encrypted`)
- **Logs**: `dt4sms.log` (when run as service)
- **PID**: `.dt4sms.pid` (service mode)

### Installation
```bash
# Windows
.\install.ps1

# Unix/macOS
./install.sh
```

### Configuration
Access settings at `http://localhost:8003` → ⚙️ Settings icon

Required configuration:
- MCP Server endpoint and bearer token
- LLM API key and model selection

### Known Limitations
- Discovery mode UI in progress (chat mode fully functional)
- Single LLM provider per session (configurable via settings)
- Debug mode secrets sanitization (filters common patterns but may not catch all)

### Future Roadmap (v1.1+)
- Intent alignment validation using semantic similarity
- Enhanced SPL query generation with multi-pass refinement
- Discovery result caching with differential updates
- Support for multiple LLM providers simultaneously
- Export chat history and SPL queries

---

## Release Notes

**v1.0.0** represents the culmination of extensive development and testing to create a production-ready Splunk admin assistant. The focus was on reliability, security, and user experience.

### Highlights
- ✅ **Zero plaintext secrets**: All credentials encrypted at rest
- ✅ **One-command installation**: Universal installers for all platforms
- ✅ **Intelligent query refinement**: Multi-turn reasoning with quality gates
- ✅ **Debug transparency**: Optional debug mode for troubleshooting
- ✅ **Enterprise-ready**: Service mode with proper daemon management

---

[1.0.0]: https://github.com/LeiterConsulting/splunk-discovery-tool/releases/tag/v1.0.0
