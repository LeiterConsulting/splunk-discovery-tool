# Universal Installer for Discovery Tool for Splunk MCP Server (DT4SMS)
# PowerShell version for Windows
# Version: 1.0.0

param(
    [Parameter(Position=0)]
    [string]$Command = "",
    
    [switch]$Help,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Restart,
    [switch]$Status,
    [switch]$Uninstall,
    [switch]$ForceYes
)

# Check PowerShell version (must be compatible with PS 5.1 syntax)
$psVersion = $PSVersionTable.PSVersion.Major
if ($psVersion -lt 7) {
    Write-Host ""
    Write-Host "ERROR: PowerShell 7+ is required" -ForegroundColor Red
    Write-Host ""
    $versionString = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
    Write-Host "You are running PowerShell $versionString" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please install PowerShell 7+ using one of these methods:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Option 1 - Install via winget (recommended):" -ForegroundColor White
    Write-Host "    winget install Microsoft.PowerShell" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option 2 - Install via MSI:" -ForegroundColor White
    Write-Host "    Download from: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option 3 - Use install.sh with Git Bash (if Git for Windows is installed):" -ForegroundColor White
    Write-Host "    Open Git Bash and run: chmod +x install.sh && ./install.sh" -ForegroundColor Gray
    Write-Host ""
    Write-Host "After installing PowerShell 7+, run this script with:" -ForegroundColor Cyan
    Write-Host "    pwsh .\install.ps1 -Start" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# Check for Python immediately
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "ERROR: Python 3.8+ is required but not found" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Python 3.8+ using one of these methods:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Option 1 - Install via Microsoft Store (easiest):" -ForegroundColor White
    Write-Host "    1. Open Microsoft Store" -ForegroundColor Gray
    Write-Host "    2. Search for 'Python 3.13' or 'Python 3.12'" -ForegroundColor Gray
    Write-Host "    3. Click Install" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option 2 - Install via winget:" -ForegroundColor White
    Write-Host "    winget install Python.Python.3.13" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option 3 - Download installer:" -ForegroundColor White
    Write-Host "    https://www.python.org/downloads/" -ForegroundColor Gray
    Write-Host "    (Make sure to check 'Add Python to PATH' during installation)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "After installing Python, close and reopen this terminal, then run:" -ForegroundColor Yellow
    Write-Host "    pwsh .\install.ps1 -Start" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# Version and metadata
$VERSION = "1.0.0"
$APP_NAME = "Discovery Tool for Splunk MCP Server"
$APP_SHORT = "DT4SMS"
$INSTALL_DIR = $PSScriptRoot
$MANIFEST_FILE = Join-Path $INSTALL_DIR ".install_manifest.json"
$PID_FILE = Join-Path $INSTALL_DIR ".dt4sms.pid"
$VENV_DIR = Join-Path $INSTALL_DIR ".venv"
$LOG_FILE = Join-Path $INSTALL_DIR "dt4sms.log"
$ERR_LOG_FILE = Join-Path $INSTALL_DIR "dt4sms.err.log"

# Colors
$ColorGreen = "Green"
$ColorYellow = "Yellow"
$ColorRed = "Red"
$ColorBlue = "Cyan"

# Print colored message
function Write-ColorMsg {
    param([string]$Color, [string]$Message)
    Write-Host $Message -ForegroundColor $Color
}

# Show help
function Show-Help {
    Write-ColorMsg $ColorGreen "$APP_NAME ($APP_SHORT) v$VERSION"
    Write-Host ""
    Write-ColorMsg $ColorBlue "USAGE:"
    Write-Host "    .\install.ps1 [OPTIONS]"
    Write-Host ""
    Write-ColorMsg $ColorBlue "OPTIONS:"
    Write-Host "    (no arguments)    Install dependencies and start service"
    Write-Host "    -Help             Show this help message"
    Write-Host "    -Start            Start the service"
    Write-Host "    -Stop             Stop the service"
    Write-Host "    -Restart          Restart the service"
    Write-Host "    -Status           Check service status"
    Write-Host "    -Uninstall        Uninstall application (prompts for confirmation)"
    Write-Host "    -ForceYes         Skip confirmation prompts (use with -Uninstall)"
    Write-Host ""
    Write-ColorMsg $ColorBlue "EXAMPLES:"
    Write-Host "    .\install.ps1                    # Install and start"
    Write-Host "    .\install.ps1 -Stop              # Stop service"
    Write-Host "    .\install.ps1 -Restart           # Restart service"
    Write-Host "    .\install.ps1 -Uninstall         # Uninstall with confirmation"
    Write-Host "    .\install.ps1 -Uninstall -ForceYes  # Uninstall without prompts"
    Write-Host ""
    Write-ColorMsg $ColorBlue "SERVICE INFO:"
    Write-Host "    Default Port: 8003"
    Write-Host "    Web Interface: http://localhost:8003"
    Write-Host "    Settings: Click gear icon in web UI"
    Write-Host ""
    Write-ColorMsg $ColorBlue "SUPPORT:"
    Write-Host "    GitHub: https://github.com/LeiterConsulting/splunk-discovery-tool"
    Write-Host "    Version: $VERSION"
}

# Create manifest
function New-Manifest {
    param([string]$PythonVersion, [string]$PipVersion)
    
    $manifest = @{
        version = $VERSION
        installed_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        os = "Windows"
        python = @{
            version = $PythonVersion
            location = (Get-Command python).Source
        }
        pip = @{
            version = $PipVersion
        }
        dependencies = @(
            "fastapi",
            "uvicorn",
            "cryptography",
            "pyyaml",
            "aiohttp",
            "python-multipart",
            "httpx",
            "openai",
            "requests"
        )
        virtual_env = $VENV_DIR
    }
    
    $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $MANIFEST_FILE -Encoding UTF8
    Write-ColorMsg $ColorGreen "✓ Installation manifest created"
}

# Quick version check
function Test-Installation {
    if (-not (Test-Path $MANIFEST_FILE)) {
        return $false
    }
    
    try {
        $manifest = Get-Content $MANIFEST_FILE | ConvertFrom-Json
        if ($manifest.version -eq $VERSION -and (Test-Path $VENV_DIR)) {
            Write-ColorMsg $ColorGreen "✓ Installation up-to-date (v$VERSION)"
            return $true
        }
    } catch {
        # Manifest doesn't exist or is corrupted - PS 5.1 compatible
        Write-Verbose "Manifest check failed" -ErrorAction SilentlyContinue
        return $false
    }
    
    return $false
}

# Install dependencies
function Install-Dependencies {
    Write-ColorMsg $ColorBlue "🔧 Installing dependencies..."
    
    # Python already checked at script start, just show version
    $pythonVersion = (python --version 2>&1) -replace "Python ", ""
    Write-ColorMsg $ColorGreen "✓ Python $pythonVersion found"
    
    # Create virtual environment
    if (-not (Test-Path $VENV_DIR)) {
        Write-ColorMsg $ColorBlue "Creating virtual environment..."
        python -m venv $VENV_DIR
    }
    
    # Activate virtual environment
    $activateScript = Join-Path $VENV_DIR "Scripts\Activate.ps1"
    & $activateScript
    
    # Upgrade pip
    Write-ColorMsg $ColorBlue "Upgrading pip..."
    python -m pip install --upgrade pip -q
    $pipVersion = (pip --version) -replace "pip ", "" -replace " from.*", ""
    Write-ColorMsg $ColorGreen "✓ pip $pipVersion"
    
    # Install requirements
    Write-ColorMsg $ColorBlue "Installing Python packages..."
    pip install -q -r requirements.txt
    Write-ColorMsg $ColorGreen "✓ All dependencies installed"
    
    # Create manifest
    New-Manifest $pythonVersion $pipVersion
}

# Start service
function Start-DT4SMSService {
    # Check if already running
    if (Test-Path $PID_FILE) {
        $processId = Get-Content $PID_FILE
        if ($processId -and (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
            Write-ColorMsg $ColorYellow "⚠ Service already running (PID: $processId)"
            return
        }
    }
    
    Write-ColorMsg $ColorBlue "🚀 Starting $APP_SHORT..."
    
    # Resolve virtual environment python executable
    $venvPython = Join-Path $VENV_DIR "Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        Write-ColorMsg $ColorRed "✗ Virtual environment python not found: $venvPython"
        Write-ColorMsg $ColorYellow "Run .\install.ps1 first to install dependencies."
        exit 1
    }

    # Ensure log file exists
    if (-not (Test-Path $LOG_FILE)) {
        New-Item -Path $LOG_FILE -ItemType File -Force | Out-Null
    }
    if (-not (Test-Path $ERR_LOG_FILE)) {
        New-Item -Path $ERR_LOG_FILE -ItemType File -Force | Out-Null
    }

    # Start in background with log redirection
    $mainScript = Join-Path $INSTALL_DIR "src\main.py"
    try {
        $process = Start-Process -FilePath $venvPython -ArgumentList "`"$mainScript`"" `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $LOG_FILE -RedirectStandardError $ERR_LOG_FILE `
            -ErrorAction Stop
    } catch {
        Write-ColorMsg $ColorRed "✗ Failed to start service process: $($_.Exception.Message)"
        Write-ColorMsg $ColorBlue "📋 Stdout log: $LOG_FILE"
        Write-ColorMsg $ColorBlue "📋 Stderr log: $ERR_LOG_FILE"
        exit 1
    }

    if (-not $process -or -not $process.Id) {
        Write-ColorMsg $ColorRed "✗ Failed to start service. Process handle was not returned."
        Write-ColorMsg $ColorBlue "📋 Stdout log: $LOG_FILE"
        Write-ColorMsg $ColorBlue "📋 Stderr log: $ERR_LOG_FILE"
        exit 1
    }
    $process.Id | Out-File -FilePath $PID_FILE -Encoding UTF8
    
    Start-Sleep -Seconds 2
    
    # Verify it started
    if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
        Write-ColorMsg $ColorGreen "✓ Service started successfully"
        Write-ColorMsg $ColorBlue "📡 Web interface: http://localhost:8003"
        Write-ColorMsg $ColorBlue "📋 Logs: Get-Content $LOG_FILE -Wait"
        Write-ColorMsg $ColorBlue "📋 Errors: Get-Content $ERR_LOG_FILE -Wait"
    } else {
        Write-ColorMsg $ColorRed "✗ Failed to start service. Check logs: $LOG_FILE"
        Write-ColorMsg $ColorBlue "📋 Error log: $ERR_LOG_FILE"
        exit 1
    }
}

# Stop service
function Stop-DT4SMSService {
    if (-not (Test-Path $PID_FILE)) {
        Write-ColorMsg $ColorYellow "⚠ Service not running"
        return
    }
    
    $processId = Get-Content $PID_FILE
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    
    if (-not $process) {
        Write-ColorMsg $ColorYellow "⚠ Service not running (stale PID file)"
        Remove-Item $PID_FILE -Force
        return
    }
    
    Write-ColorMsg $ColorBlue "🛑 Stopping $APP_SHORT..."
    Stop-Process -Id $processId -Force
    
    Start-Sleep -Seconds 2
    Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
    Write-ColorMsg $ColorGreen "✓ Service stopped"
}

# Check status
function Get-ServiceStatus {
    if (-not (Test-Path $PID_FILE)) {
        Write-ColorMsg $ColorYellow "⚠ Service not running"
        return $false
    }
    
    $processId = Get-Content $PID_FILE
    if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
        Write-ColorMsg $ColorGreen "✓ Service running (PID: $processId)"
        Write-ColorMsg $ColorBlue "📡 Web interface: http://localhost:8003"
        return $true
    } else {
        Write-ColorMsg $ColorYellow "⚠ Service not running (stale PID file)"
        Remove-Item $PID_FILE -Force
        return $false
    }
}

# Uninstall
function Uninstall-Application {
    if (-not $ForceYes) {
        Write-ColorMsg $ColorYellow "⚠ This will remove $APP_SHORT and all its dependencies."
        $confirmation = Read-Host "Are you sure? (yes/no)"
        if ($confirmation -ne "yes") {
            Write-ColorMsg $ColorBlue "Uninstall cancelled"
            return
        }
    }
    
    Write-ColorMsg $ColorBlue "🗑️ Uninstalling $APP_SHORT..."
    
    # Stop service
    Stop-DT4SMSService
    
    # Remove virtual environment
    if (Test-Path $VENV_DIR) {
        Write-ColorMsg $ColorBlue "Removing virtual environment..."
        Remove-Item $VENV_DIR -Recurse -Force
    }
    
    # Remove manifest
    Remove-Item $MANIFEST_FILE -Force -ErrorAction SilentlyContinue
    
    # Remove logs
    Remove-Item $LOG_FILE -Force -ErrorAction SilentlyContinue
    Remove-Item $ERR_LOG_FILE -Force -ErrorAction SilentlyContinue
    
    # Remove encrypted config
    Remove-Item (Join-Path $INSTALL_DIR "config.encrypted") -Force -ErrorAction SilentlyContinue
    
    Write-ColorMsg $ColorGreen "✓ Uninstall complete"
    Write-ColorMsg $ColorBlue "Source code remains in: $INSTALL_DIR"
}

# Main logic
if ($Help) {
    Show-Help
} elseif ($Start) {
    if (Test-Installation) {
        Start-DT4SMSService
    } else {
        Install-Dependencies
        Start-DT4SMSService
    }
} elseif ($Stop) {
    Stop-DT4SMSService
} elseif ($Restart) {
    Write-ColorMsg $ColorBlue "🔄 Restarting $APP_SHORT..."
    Stop-DT4SMSService
    Start-Sleep -Seconds 2
    # Force a fresh start by removing PID file if it exists
    Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
    Start-DT4SMSService
} elseif ($Status) {
    Get-ServiceStatus
} elseif ($Uninstall) {
    Uninstall-Application
} else {
    # Default: install and start
    Write-ColorMsg $ColorBlue "═══════════════════════════════════════════════════"
    Write-ColorMsg $ColorGreen " $APP_NAME"
    Write-ColorMsg $ColorGreen " Version $VERSION"
    Write-ColorMsg $ColorBlue "═══════════════════════════════════════════════════"
    Write-Host ""
    
    if (Test-Installation) {
        Start-DT4SMSService
    } else {
        Write-ColorMsg $ColorBlue "First run detected. Installing dependencies..."
        Install-Dependencies
        Start-DT4SMSService
    }
}
