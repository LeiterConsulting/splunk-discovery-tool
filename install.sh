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
LAUNCH_DIR="$(pwd)"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_FILE="$INSTALL_DIR/.install_manifest.json"
PID_FILE="$INSTALL_DIR/.dt4sms.pid"
VENV_DIR="$INSTALL_DIR/.venv"
LOG_FILE="$INSTALL_DIR/dt4sms.log"
REQUIREMENTS_FILE="$INSTALL_DIR/requirements.txt"
DEFAULT_PORT="8003"
PYPI_INDEX_URL="https://pypi.org/simple"
PUBLIC_ONLY="no"
SELECTED_COMMAND=""
FORCE_YES_FLAG="no"

# Parse CLI arguments (supports global flags like --public_only)
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --public_only|--public-only)
                PUBLIC_ONLY="yes"
                ;;
            --force-yes)
                FORCE_YES_FLAG="yes"
                ;;
            --help|-h|--start|--stop|--restart|--status|--uninstall)
                SELECTED_COMMAND="$arg"
                ;;
            "")
                ;;
            *)
                print_msg "$RED" "Unknown option: $arg"
                echo ""
                show_help
                exit 1
                ;;
        esac
    done
}

# Run pip install command with fallback to public PyPI when custom index is unreachable
run_pip_with_fallback() {
    local description="$1"
    shift

    if [[ "$PUBLIC_ONLY" == "yes" ]]; then
        print_msg "$BLUE" "Using public PyPI only (--public_only enabled)..."
        if python -m pip "$@" --disable-pip-version-check --retries 2 --timeout 20 --index-url "$PYPI_INDEX_URL" --no-cache-dir; then
            return 0
        fi
        print_msg "$RED" "✗ ${description} failed while using public PyPI only."
        return 1
    fi

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
    ${GREEN}--public_only${NC}     Use only public PyPI (skip any configured private indexes)
    ${GREEN}--start${NC}           Start the service
    ${GREEN}--stop${NC}            Stop the service
    ${GREEN}--restart${NC}         Restart the service
    ${GREEN}--status${NC}          Check service status
    ${GREEN}--uninstall${NC}       Uninstall application (prompts for confirmation)
    ${GREEN}--force-yes${NC}       Skip confirmation prompts (use with --uninstall)

${BLUE}EXAMPLES:${NC}
    ./install.sh                    # Install and start
    ./install.sh --public_only      # Install via public PyPI only
    ./install.sh --start --public_only
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

# SHA-256 of requirements.txt, so a git pull that changes dependencies triggers a reinstall
requirements_hash() {
    local python_cmd=$1
    "$python_cmd" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$REQUIREMENTS_FILE" 2>/dev/null || echo ""
}

# Create manifest of installed dependencies
create_manifest() {
    local python_version=$1
    local pip_version=$2
    local requirements_sha256
    requirements_sha256=$(requirements_hash python)
    
    cat > "$MANIFEST_FILE" << EOF
{
  "version": "${VERSION}",
  "requirements_sha256": "${requirements_sha256}",
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
        manifest_version=$("$PYTHON_CMD" -c 'import json, sys; print(json.load(open(sys.argv[1])).get("version", ""))' "$MANIFEST_FILE" 2>/dev/null || echo "")
        manifest_requirements=$("$PYTHON_CMD" -c 'import json, sys; print(json.load(open(sys.argv[1])).get("requirements_sha256", ""))' "$MANIFEST_FILE" 2>/dev/null || echo "")
        current_requirements=$(requirements_hash "$PYTHON_CMD")
        if [[ "$manifest_version" == "$VERSION" ]] && [[ -d "$VENV_DIR" ]]; then
            if [[ -n "$current_requirements" ]] && [[ "$manifest_requirements" != "$current_requirements" ]]; then
                print_msg "$YELLOW" "⚠ requirements.txt changed since the last install (for example after git pull). Updating Python packages..."
                return 1
            fi
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
    run_pip_with_fallback "dependency installation" install -q -r "$REQUIREMENTS_FILE"
    print_msg "$GREEN" "✓ All dependencies installed"
    
    # Create manifest
    create_manifest "$PYTHON_VERSION" "$PIP_VERSION"
}

check_frontend_bundle_sync() {
    local sync_check_script="$INSTALL_DIR/tools/check_frontend_sync.py"
    if [[ ! -f "$sync_check_script" ]]; then
        return 0
    fi

    if ! python "$sync_check_script" --quiet; then
        print_msg "$YELLOW" "⚠ Frontend static assets are out of sync with src/web_app.py."
        print_msg "$YELLOW" "  The app can still start, but the shipped static frontend may be stale."
        print_msg "$BLUE" "  Run: npm run build:frontend"
    fi
}

# Port the running app reported in its log (it moves to the next free port when 8003 is busy)
running_port() {
    local port=""
    if [[ -f "$LOG_FILE" ]]; then
        port=$(grep -Eo 'Web Interface: http://localhost:[0-9]+' "$LOG_FILE" 2>/dev/null | tail -1 | grep -Eo '[0-9]+$' || true)
    fi
    echo "${port:-$DEFAULT_PORT}"
}

# Prints the first code file changed after the running service started (empty when none)
code_changed_since_start() {
    if [[ ! -f "$PID_FILE" ]]; then
        return 0
    fi
    find "$INSTALL_DIR/src" "$REQUIREMENTS_FILE" -newer "$PID_FILE" -type f \
        \( -name '*.py' -o -name '*.html' -o -name '*.js' -o -name '*.css' -o -name 'requirements.txt' \) \
        -not -path '*/__pycache__/*' -not -path '*/node_modules/*' -print -quit 2>/dev/null || true
}

warn_if_running_old_code() {
    local changed
    changed=$(code_changed_since_start)
    if [[ -n "$changed" ]]; then
        print_msg "$YELLOW" "⚠ The code changed after the service started (${changed#"$INSTALL_DIR"/} is newer)."
        print_msg "$YELLOW" "  The running service still uses the old version until it restarts."
        print_msg "$BLUE" "  Run: ./install.sh --restart"
    fi
}

# "port pid" for every listener on the ports the app can use (8003 and the 20 fallback ports)
app_port_listeners() {
    local last=$((DEFAULT_PORT + 20))
    if command -v lsof > /dev/null 2>&1; then
        lsof -nP -iTCP:"$DEFAULT_PORT-$last" -sTCP:LISTEN 2>/dev/null \
            | awk 'NR > 1 { n = split($9, parts, ":"); print parts[n], $2 }' | sort -un
    elif command -v ss > /dev/null 2>&1; then
        ss -ltnpH 2>/dev/null | awk -v lo="$DEFAULT_PORT" -v hi="$last" '{
            n = split($4, parts, ":"); port = parts[n] + 0
            if (port >= lo && port <= hi && match($0, /pid=[0-9]+/)) print port, substr($0, RSTART + 4, RLENGTH - 4)
        }' | sort -un
    fi
}

# Install folder of an app process, from its command line or working directory
app_folder_of_pid() {
    local pid="$1" args="$2" folder=""
    case "$args" in
        */src/main.py*)
            folder="${args%%/src/main.py*}"
            if [[ "$folder" == *" /"* ]]; then
                folder="/${folder##* /}"
            fi
            ;;
        *main.py*)
            if [[ -d "/proc/$pid/cwd" ]]; then
                folder=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
            elif command -v lsof > /dev/null 2>&1; then
                folder=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)
            fi
            ;;
    esac
    echo "$folder"
}

# A copy started from another folder keeps answering on its port with its own code, so name each one
report_other_copies() {
    local own_pid="$1" own_port="$2"
    local listeners port pid args folder stop_pids="" header=""
    listeners=$(app_port_listeners)
    if [[ -z "$listeners" ]]; then
        return 0
    fi
    while read -r port pid; do
        if [[ -z "$port" ]] || [[ -z "$pid" ]] || [[ "$pid" == "$own_pid" ]] || [[ "$port" == "$own_port" ]]; then
            continue
        fi
        if [[ -z "$header" ]]; then
            print_msg "$YELLOW" "⚠ Other programs are using the app's ports on this computer:"
            header="yes"
        fi
        args=$(ps -o args= -p "$pid" 2>/dev/null || true)
        if [[ "$args" == *main.py* ]]; then
            folder=$(app_folder_of_pid "$pid" "$args")
            print_msg "$YELLOW" "    port $port: another copy of the app (PID $pid), started from ${folder:-an unknown folder}"
            stop_pids="$stop_pids $pid"
        else
            print_msg "$YELLOW" "    port $port: PID $pid (${args:0:70})"
        fi
    done <<< "$listeners"
    if [[ -n "$stop_pids" ]]; then
        print_msg "$YELLOW" "  A browser or bookmark that opens one of those ports reaches that copy and its code, not this one."
        print_msg "$BLUE" "  To run only this copy: kill${stop_pids} && ./install.sh --restart"
    fi
}
# Warn when an earlier launch from another folder left settings there; the app reads them from the folder it starts in
warn_about_settings_elsewhere() {
    if [[ "$LAUNCH_DIR" == "$INSTALL_DIR" ]]; then
        return 0
    fi
    if [[ -f "$LAUNCH_DIR/config.encrypted" ]] && [[ ! -f "$INSTALL_DIR/config.encrypted" ]]; then
        print_msg "$YELLOW" "⚠ Found saved settings in $LAUNCH_DIR, but the app now always runs from $INSTALL_DIR."
        print_msg "$YELLOW" "  To keep them, stop the app and move config.encrypted, .config.key and security.db into $INSTALL_DIR."
    fi
}

# Start service
start_service() {
    # Check if already running
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            print_msg "$YELLOW" "⚠ Service already running (PID: $PID)"
            print_msg "$BLUE" "📡 Web interface: http://localhost:$(running_port)"
            warn_if_running_old_code
            report_other_copies "$PID" "$(running_port)"
            return 0
        fi
    fi

    warn_about_settings_elsewhere
    
    print_msg "$BLUE" "🚀 Starting ${APP_SHORT}..."
    
    # Activate virtual environment
    if [[ "$(detect_os)" == "Windows" ]]; then
        source "$VENV_DIR/Scripts/activate"
    else
        source "$VENV_DIR/bin/activate"
    fi

    check_frontend_bundle_sync
    
    # main() has already changed to the install folder: settings, keys and output are stored relative to it
    PYTHONUNBUFFERED=1 nohup python "$INSTALL_DIR/src/main.py" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    
    # Wait for the app to report its port (it moves to the next free port when 8003 is busy)
    local started_port=""
    for _ in {1..40}; do
        if ! ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then
            break
        fi
        started_port=$(grep -Eo 'Web Interface: http://localhost:[0-9]+' "$LOG_FILE" 2>/dev/null | tail -1 | grep -Eo '[0-9]+$' || true)
        if [[ -n "$started_port" ]]; then
            break
        fi
        sleep 0.5
    done
    
    # Verify it started
    if ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then
        print_msg "$GREEN" "✓ Service started successfully"
        if [[ -n "$started_port" ]] && [[ "$started_port" != "$DEFAULT_PORT" ]]; then
            print_msg "$YELLOW" "⚠ Port $DEFAULT_PORT is in use (possibly by another copy of the app), so this copy uses port $started_port."
        fi
        print_msg "$BLUE" "📡 Web interface: http://localhost:${started_port:-$DEFAULT_PORT}"
        print_msg "$BLUE" "📋 Logs: tail -f $LOG_FILE"
        report_other_copies "$(cat "$PID_FILE")" "${started_port:-$DEFAULT_PORT}"
    else
        print_msg "$RED" "✗ Failed to start service. Last lines of $LOG_FILE:"
        tail -n 20 "$LOG_FILE" 2>/dev/null || true
        rm -f "$PID_FILE"
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
        report_other_copies "" ""
        return 1
    fi
    
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        print_msg "$GREEN" "✓ Service running (PID: $PID)"
        print_msg "$BLUE" "📡 Web interface: http://localhost:$(running_port)"
        warn_if_running_old_code
        report_other_copies "$PID" "$(running_port)"
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
    rm -f "$LOG_FILE"
    
    # Remove encrypted config
    rm -f "$INSTALL_DIR/config.encrypted"
    
    print_msg "$GREEN" "✓ Uninstall complete"
    print_msg "$BLUE" "Source code remains in: $INSTALL_DIR"
}

# Main logic
main() {
    parse_args "$@"
    cd "$INSTALL_DIR"

    case "${SELECTED_COMMAND:-}" in
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
            if ! quick_check; then
                install_deps
            fi
            start_service
            ;;
        --status)
            check_status
            ;;
        --uninstall)
            if [[ "$FORCE_YES_FLAG" == "yes" ]]; then
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
                print_msg "$BLUE" "Installing dependencies..."
                install_deps
                start_service
            fi
            ;;
        *)
            print_msg "$RED" "Unknown option: ${SELECTED_COMMAND}"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main
main "$@"
