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

# Version and metadata
$VERSION = "1.0.0"
$APP_NAME = "Discovery Tool for Splunk MCP Server"
$APP_SHORT = "DT4SMS"
$INSTALL_DIR = $PSScriptRoot
$MANIFEST_FILE = Join-Path $INSTALL_DIR ".install_manifest.json"
$PID_FILE = Join-Path $INSTALL_DIR ".dt4sms.pid"
$VENV_DIR = Join-Path $INSTALL_DIR ".venv"
$LOG_FILE = Join-Path $INSTALL_DIR "dt4sms.log"

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
    Write-Host "    GitHub: https://github.com/yourusername/dt4sms (coming soon)"
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
            "openai"
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
        return $false
    }
    
    return $false
}

# Install dependencies
function Install-Dependencies {
    Write-ColorMsg $ColorBlue "🔧 Installing dependencies..."
    
    # Check for Python
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-ColorMsg $ColorRed "✗ Python 3 not found. Please install Python 3.8+"
        exit 1
    }
    
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
    pip install -q fastapi "uvicorn[standard]" cryptography pyyaml aiohttp python-multipart httpx openai
    Write-ColorMsg $ColorGreen "✓ All dependencies installed"
    
    # Create manifest
    New-Manifest $pythonVersion $pipVersion
}

# Start service
function Start-Service {
    # Check if already running
    if (Test-Path $PID_FILE) {
        $pid = Get-Content $PID_FILE
        if (Get-Process -Id $pid -ErrorAction SilentlyContinue) {
            Write-ColorMsg $ColorYellow "⚠ Service already running (PID: $pid)"
            return
        }
    }
    
    Write-ColorMsg $ColorBlue "🚀 Starting $APP_SHORT..."
    
    # Activate virtual environment
    $activateScript = Join-Path $VENV_DIR "Scripts\Activate.ps1"
    & $activateScript
    
    # Start in background
    $mainScript = Join-Path $INSTALL_DIR "src\main.py"
    $process = Start-Process -FilePath "python" -ArgumentList $mainScript -NoNewWindow -PassThru -RedirectStandardOutput $LOG_FILE -RedirectStandardError $LOG_FILE
    $process.Id | Out-File -FilePath $PID_FILE -Encoding UTF8
    
    Start-Sleep -Seconds 2
    
    # Verify it started
    if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
        Write-ColorMsg $ColorGreen "✓ Service started successfully"
        Write-ColorMsg $ColorBlue "📡 Web interface: http://localhost:8003"
        Write-ColorMsg $ColorBlue "📋 Logs: Get-Content $LOG_FILE -Wait"
    } else {
        Write-ColorMsg $ColorRed "✗ Failed to start service. Check logs: $LOG_FILE"
        exit 1
    }
}

# Stop service
function Stop-Service {
    if (-not (Test-Path $PID_FILE)) {
        Write-ColorMsg $ColorYellow "⚠ Service not running"
        return
    }
    
    $pid = Get-Content $PID_FILE
    $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
    
    if (-not $process) {
        Write-ColorMsg $ColorYellow "⚠ Service not running (stale PID file)"
        Remove-Item $PID_FILE -Force
        return
    }
    
    Write-ColorMsg $ColorBlue "🛑 Stopping $APP_SHORT..."
    Stop-Process -Id $pid -Force
    
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
    
    $pid = Get-Content $PID_FILE
    if (Get-Process -Id $pid -ErrorAction SilentlyContinue) {
        Write-ColorMsg $ColorGreen "✓ Service running (PID: $pid)"
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
    Stop-Service
    
    # Remove virtual environment
    if (Test-Path $VENV_DIR) {
        Write-ColorMsg $ColorBlue "Removing virtual environment..."
        Remove-Item $VENV_DIR -Recurse -Force
    }
    
    # Remove manifest
    Remove-Item $MANIFEST_FILE -Force -ErrorAction SilentlyContinue
    
    # Remove logs
    Remove-Item $LOG_FILE -Force -ErrorAction SilentlyContinue
    
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
        Start-Service
    } else {
        Install-Dependencies
        Start-Service
    }
} elseif ($Stop) {
    Stop-Service
} elseif ($Restart) {
    Stop-Service
    Start-Sleep -Seconds 1
    Start-Service
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
        Start-Service
    } else {
        Write-ColorMsg $ColorBlue "First run detected. Installing dependencies..."
        Install-Dependencies
        Start-Service
    }
}
