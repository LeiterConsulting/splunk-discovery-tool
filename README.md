# 🔍 Splunk Discovery Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/LeiterConsulting/splunk-discovery-tool/releases)

> **AI-powered Splunk environment discovery and admin assistant with MCP integration**

Automatically discover your Splunk deployment, analyze configurations, generate SPL queries, and get intelligent recommendations through an intuitive web interface powered by LLM technology.

## ✨ Features

### 🔍 **Discovery & Analysis**
- Automated Splunk environment scanning via MCP protocol
- Real-time configuration analysis and classification
- Data source identification and relationship mapping

### � **Intelligent Admin Chat**
- Natural language Splunk admin assistance
- Context-aware SPL query generation
- Multi-turn reasoning with quality validation
- Automatic query refinement and optimization

### 🛠️ **Enterprise-Ready**
- **Universal Cross-Platform Installer**: Single script for Windows/Unix/macOS
- **Encrypted Configuration**: Fernet encryption for credentials (no plaintext storage)
- **Web-Based Settings**: Complete configuration management via web UI
- **Service Mode**: Background daemon with restart/shutdown capabilities
- **Debug Mode**: Real-time debug streaming for troubleshooting

## 📋 Prerequisites

- **Python 3.8+**
- **PowerShell 7+** (Windows only - for install.ps1)
- **pip** (Python package installer)
- **MCP Server** for Splunk (connection configured via settings)
- **LLM API Access** (OpenAI, Anthropic, or compatible endpoint)

> **Note for Windows Users**: The PowerShell installer requires PowerShell 7+. Install via `winget install Microsoft.PowerShell` or use `install.sh` with Git Bash instead.

## 🔧 Quick Start

### Windows (PowerShell)

```powershell
# Install and start
.\install.ps1

# Show help
.\install.ps1 -Help

# Stop service
.\install.ps1 -Stop

# Restart service
.\install.ps1 -Restart

# Uninstall
.\install.ps1 -Uninstall
```

### Unix/Linux/macOS (Bash)

```bash
# Make installer executable
chmod +x install.sh

# Install and start
./install.sh

# Show help
./install.sh --help

# Stop service
./install.sh --stop

# Restart service
./install.sh --restart

# Uninstall
./install.sh --uninstall
```

## 🌐 Access

Once started, access the web interface at:

**http://localhost:8003**

## ⚙️ Configuration

### First-Time Setup

1. Open **http://localhost:8003**
2. Click the **⚙️ Settings** icon (top-right)
3. Configure your environment:

**MCP Server Configuration:**
- Endpoint: Your Splunk MCP server URL
- Bearer Token: Authentication token for MCP access
- SSL Verification: Enable/disable certificate validation

**LLM Provider:**
- Provider: OpenAI (default) or custom endpoint
- API Key: Your LLM provider API key
- Model: `gpt-4o-mini` recommended for balance of speed/quality
- Max Tokens: Token limit per request (default: 16000)

**Server Settings:**
- Port: Web interface port (default: 8003)
- Debug Mode: Enable real-time debug streaming

4. Click **Save Settings**
5. Restart the service

### Settings Features

- ✅ **Encrypted Storage**: All credentials encrypted at rest
- ✅ **Live Validation**: Field validation with examples
- ✅ **Debug Mode**: Real-time debug window with WebSocket streaming
- ✅ **Dependencies Viewer**: Check installed package versions
- ✅ **Version Display**: Current application version

## 🔐 Security

- **Encrypted Storage**: All credentials encrypted using Fernet
- **No Plaintext**: Secrets never stored in plaintext
- **Secure Permissions**: Config files set to 0600 (owner read/write only)
- **SSL Support**: Configurable SSL verification for MCP connections
- **CORS/Host Protection**: Configurable security policies

## 📁 File Structure

```
Discovery Tool for Splunk MCP Server/
├── install.sh              # Unix/macOS installer
├── install.ps1             # Windows installer
├── requirements.txt        # Python dependencies
├── src/
│   ├── main.py            # Application entry point
│   ├── web_app.py         # FastAPI web application
│   └── config_manager.py  # Encrypted configuration manager
├── .config.key            # Encryption key (auto-generated, do not share)
├── config.encrypted       # Encrypted configuration file
└── .install_manifest.json # Installation metadata

```

## 🛠️ CLI Reference

### Universal Installer Commands

| Command | Description |
|---------|-------------|
| `(no arguments)` | Install dependencies and start service |
| `--help` / `-Help` | Show help message |
| `--start` / `-Start` | Start the service |
| `--stop` / `-Stop` | Stop the service |
| `--restart` / `-Restart` | Restart the service |
| `--status` / `-Status` | Check service status |
| `--uninstall` / `-Uninstall` | Uninstall (with confirmation) |
| `--force-yes` / `-ForceYes` | Skip confirmation prompts |

### Examples

```bash
# Install and auto-start (first run)
./install.sh

# Check status
./install.sh --status

# Restart after config changes
./install.sh --restart

# Complete uninstall without prompts
./install.sh --uninstall --force-yes
```

## 🔄 Update Process

The installer performs quick version checking:

1. **First Run**: Installs all dependencies, creates manifest
2. **Subsequent Runs**: Quick version check (< 1 second)
3. **Updates Detected**: Auto-reinstalls if version mismatch

## 🗑️ Uninstallation

```bash
# Interactive uninstall (prompts for confirmation)
./install.sh --uninstall

# Automatic uninstall (no prompts)
./install.sh --uninstall --force-yes
```

Uninstall removes:
- Virtual environment (`.venv/`)
- Installation manifest
- Encrypted configuration
- Log files

**Note**: Source code remains intact for reinstallation.

## 🐛 Troubleshooting

### Cannot run script in Windows

Run the following PowerShell command:

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

### Service Won't Start

```bash
# Check logs
tail -f dt4sms.log

# Verify Python installation
python --version  # Should be 3.8+

# Reinstall dependencies
./install.sh --stop
rm -rf .venv .install_manifest.json
./install.sh
```

### Port Already in Use

Change the port in Settings → Web Server → Port (default: 8003)

### Cannot Access from Remote Machine

1. Open Settings → Web Server
2. Update **CORS Allowed Origins** and **Trusted Hosts**
3. Add your IP or use `*` for development (not recommended for production)
4. Restart server

### SSL Certificate Errors (MCP Connection)

1. Open Settings → MCP Server
2. Uncheck "Verify SSL Certificate" for self-signed certificates
3. Or provide CA bundle path for custom certificates

## 📦 Dependencies

Core dependencies (automatically installed):

- **fastapi** - Modern web framework
- **uvicorn[standard]** - High-performance ASGI server
- **cryptography** - Encryption for secure configuration storage
- **pyyaml** - Configuration file parsing
- **httpx** - Modern HTTP client
- **aiohttp** - Async HTTP operations
- **openai** - LLM integration
- **python-multipart** - File upload support

View installed versions: **Settings → View Dependencies** button in web UI

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Issues**: [Report a bug or request a feature](https://github.com/LeiterConsulting/splunk-discovery-tool/issues)
- **Leiter Consulting**: Professional Splunk services and consulting

## 🙏 Acknowledgments

Built with modern Python frameworks and AI technology to simplify Splunk administration.

---

**Made with ❤️ by Leiter Consulting** | Version 1.0.0

## 🤝 Contributing

Contributions welcome!

## 📄 License

MIT

## 🔗 Links

- **GitHub**: [https://github.com/yourusername/dt4sms](https://github.com/yourusername/dt4sms) *(coming soon)*
- **Documentation**: [Wiki](https://github.com/yourusername/dt4sms/wiki) *(coming soon)*
- **Issues**: [Report a bug](https://github.com/yourusername/dt4sms/issues) *(coming soon)*

## 📊 Version History

### 1.0.0 (2025-10-31)

- ✅ Initial release
- ✅ Universal cross-platform installer
- ✅ Encrypted configuration management
- ✅ Web-based settings panel
- ✅ Service mode with restart/shutdown
- ✅ Complete security implementation

---

**Made with ❤️ for Splunk Administrators**
