# =============================================================================
# ZTC-Wrapper Installation Script (Windows PowerShell)
# Supports: Windows 10/11
# =============================================================================

$ErrorActionPreference = "Stop"

# Colors
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor $BLUE -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] " -ForegroundColor $GREEN -NoNewline
    Write-Host $Message
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor $RED -NoNewline
    Write-Host $Message
}

function Print-Banner {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor $BLUE
    Write-Host "  ZTC-Wrapper Installation Script" -ForegroundColor $BLUE
    Write-Host "  Zero-Trust AI Agent Security" -ForegroundColor $BLUE
    Write-Host "==========================================" -ForegroundColor $BLUE
    Write-Host ""
}

function Check-Python {
    Write-Status "Checking Python..."

    # Try 'py' launcher first (Windows Python Launcher)
    $pythonCmd = $null
    if (Get-Command "py" -ErrorAction SilentlyContinue) {
        $pyVersion = & py --version 2>&1
        if ($pyVersion -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 11) {
                $pythonCmd = "py"
                Write-Success "Python found: $pyVersion"
                Write-Success "Python 3.11+ OK"
                return $pythonCmd
            } else {
                Write-Error-Custom "Python 3.11+ required (found $pyVersion)"
                return $null
            }
        }
    }

    # Try 'python' directly
    if (Get-Command "python" -ErrorAction SilentlyContinue) {
        $pyVersion = & python --version 2>&1
        if ($pyVersion -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 11) {
                $pythonCmd = "python"
                Write-Success "Python found: $pyVersion"
                Write-Success "Python 3.11+ OK"
                return $pythonCmd
            } else {
                Write-Error-Custom "Python 3.11+ required (found $pyVersion)"
                return $null
            }
        }
    }

    # Try 'python3' (for Windows Subsystem for Linux or MSYS)
    if (Get-Command "python3" -ErrorAction SilentlyContinue) {
        $pyVersion = & python3 --version 2>&1
        if ($pyVersion -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 11) {
                $pythonCmd = "python3"
                Write-Success "Python found: $pyVersion"
                Write-Success "Python 3.11+ OK"
                return $pythonCmd
            } else {
                Write-Error-Custom "Python 3.11+ required (found $pyVersion)"
                return $null
            }
        }
    }

    Write-Error-Custom "Python 3 not found"
    Write-Host ""
    Write-Host "Install Python 3.11+ from: https://www.python.org/downloads/" -ForegroundColor $YELLOW
    Write-Host "Make sure to check 'Add Python to PATH' during installation." -ForegroundColor $YELLOW
    return $null
}

function Check-Git {
    Write-Status "Checking Git..."
    if (Get-Command "git" -ErrorAction SilentlyContinue) {
        $gitVersion = & git --version 2>&1
        Write-Success "Git found: $gitVersion"
        return $true
    } else {
        Write-Status "Git not found (optional - needed for cloning)"
        return $false
    }
}

function Check-Pip {
    param([string]$PythonCmd)
    Write-Status "Checking pip..."
    if (& $PythonCmd -m pip --version 2>$null) {
        return $true
    } else {
        Write-Error-Custom "pip not found"
        Write-Host "Ensure 'pip' is included in your Python installation." -ForegroundColor $YELLOW
        return $false
    }
}

function Install-ZTC {
    param([string]$PythonCmd)

    Write-Status "Installing ZTC-Wrapper..."

    # Create venv if not exists
    if (-Not (Test-Path "venv")) {
        Write-Status "Creating virtual environment..."
        & $PythonCmd -m venv venv
        Write-Success "Virtual environment created"
    } else {
        Write-Success "Virtual environment already exists"
    }

    # Activate venv
    Write-Status "Activating virtual environment..."
    & ".\venv\Scripts\Activate.ps1"

    # Upgrade pip
    Write-Status "Upgrading pip..."
    & $PythonCmd -m pip install --upgrade pip --quiet

    # Install dependencies
    if (Test-Path "requirements.txt") {
        Write-Status "Installing dependencies..."
        & $PythonCmd -m pip install -r requirements.txt --quiet
        Write-Success "Dependencies installed"
    } else {
        Write-Error-Custom "requirements.txt not found"
        exit 1
    }

    # Install dev dependencies
    Write-Status "Installing dev tools (pytest, pytest-cov)..."
    & $PythonCmd -m pip install pytest pytest-cov --quiet
    Write-Success "Dev tools installed"

    Write-Host ""
    Write-Host "==========================================" -ForegroundColor $GREEN
    Write-Host "  INSTALLATION COMPLETE" -ForegroundColor $GREEN
    Write-Host "==========================================" -ForegroundColor $GREEN
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor $BLUE
    Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor $YELLOW
    Write-Host "  python -m src.cli --help" -ForegroundColor $YELLOW
    Write-Host ""
    Write-Host "Web Dashboard:" -ForegroundColor $BLUE
    Write-Host "  python server.py" -ForegroundColor $YELLOW
    Write-Host ""
    Write-Host "Quick run (no activation):" -ForegroundColor $BLUE
    Write-Host "  .\run.bat --help" -ForegroundColor $YELLOW
    Write-Host ""
}

# =============================================================================
# Main
# =============================================================================

Print-Banner

$pythonCmd = Check-Python
if (-Not $pythonCmd) {
    Write-Host ""
    Write-Host "Installation aborted. Please install Python 3.11+ first." -ForegroundColor $RED
    exit 1
}

Check-Git | Out-Null

if (-Not (Check-Pip -PythonCmd $pythonCmd)) {
    Write-Host ""
    Write-Host "Installation aborted. Please install pip first." -ForegroundColor $RED
    exit 1
}

Install-ZTC -PythonCmd $pythonCmd
