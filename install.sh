#!/usr/bin/env bash
# Universal Installer for Discovery Tool for Splunk MCP Server (DT4SMS)
# Supports Windows (Git Bash/WSL), macOS, and Linux
# Version: 1.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Version and metadata
VERSION="1.0.0"
APP_NAME="Discovery Tool for Splunk MCP Server"
APP_SHORT="DT4SMS"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_FILE="$INSTALL_DIR/.install_manifest.json"
PID_FILE="$INSTALL_DIR/.dt4sms.pid"
VENV_DIR="$INSTALL_DIR/.venv"
PYPI_INDEX_URL="https://pypi.org/simple"

# Run pip install command with fallback to public PyPI when custom index is unreachable
run_pip_with_fallback() {
    local description="$1"
    shift

    if python -m pip "$@" --disable-pip-version-check --retries 2 --timeout 20; then
        return 0
    fi

    print_msg "$YELLOW" "⚠ ${description} failed with current pip index. Retrying with public PyPI..."

    if python -m pip "$@" --disable-pip-version-check --retries 2 --timeout 20 --index-url "$PYPI_INDEX_URL" --no-cache-dir; then
        return 0
    fi

    print_msg "$RED" "✗ ${description} failed. If a private pip index is configured, verify it is reachable or set PIP_INDEX_URL=https://pypi.org/simple and retry."
    return 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="Linux";;
        Darwin*)    OS="macOS";;
        CYGWIN*|MINGW*|MSYS*) OS="Windows";;
        *)          OS="Unknown";;
    esac
    echo "$OS"
}

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

# Show help
show_help() {
    cat << EOF
${GREEN}${APP_NAME} (${APP_SHORT}) v${VERSION}${NC}

${BLUE}USAGE:${NC}
    ./install.sh [OPTIONS]

${BLUE}OPTIONS:${NC}
    ${GREEN}(no arguments)${NC}    Install dependencies and start service
    ${GREEN}--help${NC}            Show this help message
    ${GREEN}--start${NC}           Start the service
    ${GREEN}--stop${NC}            Stop the service
    ${GREEN}--restart${NC}         Restart the service
    ${GREEN}--status${NC}          Check service status
    ${GREEN}--uninstall${NC}       Uninstall application (prompts for confirmation)
    ${GREEN}--force-yes${NC}       Skip confirmation prompts (use with --uninstall)

${BLUE}EXAMPLES:${NC}
    ./install.sh                    # Install and start
    ./install.sh --stop             # Stop service
    ./install.sh --restart          # Restart service
    ./install.sh --uninstall        # Uninstall with confirmation
    ./install.sh --uninstall --force-yes  # Uninstall without prompts

${BLUE}SERVICE INFO:${NC}
    Default Port: 8003
    Web Interface: http://localhost:8003
    Settings: Click gear icon in web UI

${BLUE}SUPPORT:${NC}
    GitHub: https://github.com/LeiterConsulting/splunk-discovery-tool
    Version: ${VERSION}
EOF
}

# Create manifest of installed dependencies
create_manifest() {
    local python_version=$1
    local pip_version=$2
    
    cat > "$MANIFEST_FILE" << EOF
{
  "version": "${VERSION}",
  "installed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "os": "$(detect_os)",
  "python": {
    "version": "${python_version}",
    "location": "$(command -v python3 || command -v python)"
  },
  "pip": {
    "version": "${pip_version}"
  },
  "dependencies": [
    "fastapi",
    "uvicorn",
    "cryptography",
    "pyyaml",
    "aiohttp",
    "python-multipart",
    "httpx",
    "openai",
    "requests"
  ],
  "virtual_env": "${VENV_DIR}"
}
EOF
    print_msg "$GREEN" "✓ Installation manifest created"
}

# Quick version check
quick_check() {
    if [[ ! -f "$MANIFEST_FILE" ]]; then
        return 1
    fi
    
    # Check if manifest version matches
    if command -v python3 &> /dev/null || command -v python &> /dev/null; then
        PYTHON_CMD=$(command -v python3 || command -v python)
        manifest_version=$($PYTHON_CMD -c "import json; print(json.load(open('$MANIFEST_FILE'))['version'])" 2>/dev/null || echo "")
        if [[ "$manifest_version" == "$VERSION" ]] && [[ -d "$VENV_DIR" ]]; then
            print_msg "$GREEN" "✓ Installation up-to-date (v${VERSION})"
            return 0
        fi
    fi
    return 1
}

# Install dependencies
install_deps() {
    print_msg "$BLUE" "🔧 Installing dependencies..."
    
    # Check for Python
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_msg "$RED" "✗ Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    print_msg "$GREEN" "✓ Python ${PYTHON_VERSION} found"
    
    # Create virtual environment
    if [[ ! -d "$VENV_DIR" ]]; then
        print_msg "$BLUE" "Creating virtual environment..."
        $PYTHON_CMD -m venv "$VENV_DIR"
    fi
    
    # Activate virtual environment
    if [[ "$(detect_os)" == "Windows" ]]; then
        source "$VENV_DIR/Scripts/activate"
    else
        source "$VENV_DIR/bin/activate"
    fi
    
    # Upgrade pip
    print_msg "$BLUE" "Upgrading pip..."
    run_pip_with_fallback "pip upgrade" install --upgrade pip -q
    PIP_VERSION=$(pip --version | awk '{print $2}')
    print_msg "$GREEN" "✓ pip ${PIP_VERSION}"
    
    # Install requirements
    print_msg "$BLUE" "Installing Python packages..."
    run_pip_with_fallback "dependency installation" install -q -r requirements.txt
    print_msg "$GREEN" "✓ All dependencies installed"
    
    # Create manifest
    create_manifest "$PYTHON_VERSION" "$PIP_VERSION"
}

# Start service
start_service() {
    # Check if already running
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            print_msg "$YELLOW" "⚠ Service already running (PID: $PID)"
            return 0
        fi
    fi
    
    print_msg "$BLUE" "🚀 Starting ${APP_SHORT}..."
    
    # Activate virtual environment
    if [[ "$(detect_os)" == "Windows" ]]; then
        source "$VENV_DIR/Scripts/activate"
    else
        source "$VENV_DIR/bin/activate"
    fi
    
    # Start in background
    nohup python "$INSTALL_DIR/src/main.py" > "$INSTALL_DIR/dt4sms.log" 2>&1 &
    echo $! > "$PID_FILE"
    
    sleep 2
    
    # Verify it started
    if ps -p $(cat "$PID_FILE") > /dev/null 2>&1; then
        print_msg "$GREEN" "✓ Service started successfully"
        print_msg "$BLUE" "📡 Web interface: http://localhost:8003"
        print_msg "$BLUE" "📋 Logs: tail -f $INSTALL_DIR/dt4sms.log"
    else
        print_msg "$RED" "✗ Failed to start service. Check logs: $INSTALL_DIR/dt4sms.log"
        exit 1
    fi
}

# Stop service
stop_service() {
    if [[ ! -f "$PID_FILE" ]]; then
        print_msg "$YELLOW" "⚠ Service not running"
        return 0
    fi
    
    PID=$(cat "$PID_FILE")
    if ! ps -p "$PID" > /dev/null 2>&1; then
        print_msg "$YELLOW" "⚠ Service not running (stale PID file)"
        rm -f "$PID_FILE"
        return 0
    fi
    
    print_msg "$BLUE" "🛑 Stopping ${APP_SHORT}..."
    kill "$PID"
    
    # Wait for graceful shutdown
    for i in {1..10}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    # Force kill if still running
    if ps -p "$PID" > /dev/null 2>&1; then
        print_msg "$YELLOW" "Force killing process..."
        kill -9 "$PID"
    fi
    
    rm -f "$PID_FILE"
    print_msg "$GREEN" "✓ Service stopped"
}

# Service status
check_status() {
    if [[ ! -f "$PID_FILE" ]]; then
        print_msg "$YELLOW" "⚠ Service not running"
        return 1
    fi
    
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        print_msg "$GREEN" "✓ Service running (PID: $PID)"
        print_msg "$BLUE" "📡 Web interface: http://localhost:8003"
        return 0
    else
        print_msg "$YELLOW" "⚠ Service not running (stale PID file)"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Uninstall
uninstall() {
    local force_yes=$1
    
    if [[ "$force_yes" != "yes" ]]; then
        print_msg "$YELLOW" "⚠ This will remove ${APP_SHORT} and all its dependencies."
        read -p "Are you sure? (yes/no): " confirmation
        if [[ "$confirmation" != "yes" ]]; then
            print_msg "$BLUE" "Uninstall cancelled"
            exit 0
        fi
    fi
    
    print_msg "$BLUE" "🗑️  Uninstalling ${APP_SHORT}..."
    
    # Stop service
    stop_service 2>/dev/null || true
    
    # Remove virtual environment
    if [[ -d "$VENV_DIR" ]]; then
        print_msg "$BLUE" "Removing virtual environment..."
        rm -rf "$VENV_DIR"
    fi
    
    # Remove manifest
    rm -f "$MANIFEST_FILE"
    
    # Remove logs
    rm -f "$INSTALL_DIR/dt4sms.log"
    
    # Remove encrypted config
    rm -f "$INSTALL_DIR/config.encrypted"
    
    print_msg "$GREEN" "✓ Uninstall complete"
    print_msg "$BLUE" "Source code remains in: $INSTALL_DIR"
}

# Main logic
main() {
    case "${1:-}" in
        --help|-h)
            show_help
            ;;
        --start)
            if quick_check; then
                start_service
            else
                install_deps
                start_service
            fi
            ;;
        --stop)
            stop_service
            ;;
        --restart)
            echo -e "${BLUE}🔄 Restarting $APP_SHORT...${NC}"
            stop_service
            sleep 2
            # Force a fresh start by removing PID file if it exists
            rm -f "$PID_FILE"
            start_service
            ;;
        --status)
            check_status
            ;;
        --uninstall)
            if [[ "${2:-}" == "--force-yes" ]]; then
                uninstall "yes"
            else
                uninstall "no"
            fi
            ;;
        "")
            print_msg "$BLUE" "═══════════════════════════════════════════════════"
            print_msg "$GREEN" " ${APP_NAME}"
            print_msg "$GREEN" " Version ${VERSION}"
            print_msg "$BLUE" "═══════════════════════════════════════════════════"
            echo ""
            
            if quick_check; then
                start_service
            else
                print_msg "$BLUE" "First run detected. Installing dependencies..."
                install_deps
                start_service
            fi
            ;;
        *)
            print_msg "$RED" "Unknown option: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main
main "$@"
