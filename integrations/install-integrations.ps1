# =============================================================================
# AG-Wrapper Integration Installer (PowerShell)
# 
# This script integrates AG-Wrapper with popular AI coding assistants.
# Run as: .\install-integrations.ps1
# =============================================================================

param(
    [string[]] $Integrations = @("vscode", "cursor", "nova", "alice", "build"),
    [switch] $All,
    [switch] $Uninstall
)

$ErrorActionPreference = "Stop"

# Colors
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"

function Write-Status { param([string]$Message) Write-Host "[INFO] " -ForegroundColor $BLUE -NoNewline; Write-Host $Message }
function Write-Success { param([string]$Message) Write-Host "[OK] " -ForegroundColor $GREEN -NoNewline; Write-Host $Message }
function Write-Warn { param([string]$Message) Write-Host "[WARN] " -ForegroundColor $YELLOW -NoNewline; Write-Host $Message }
function Write-Error-Custom { param([string]$Message) Write-Host "[ERROR] " -ForegroundColor $RED -NoNewline; Write-Host $Message }

function Get-AGPath {
    # Find AG-Wrapper installation
    $scriptDir = Split-Path -Parent $PSCommandPath
    if ($scriptDir -match "integrations") {
        $agRoot = Split-Path -Parent $scriptDir
    } else {
        $agRoot = $scriptDir
    }
    
    $venvPython = Join-Path $agRoot "venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }
    
    # Fallback to system python
    return "python"
}

function Install-VSCode {
    Write-Status "Installing VSCode integration..."
    
    $vscodeDir = "$env:USERPROFILE\.vscode\extensions"
    $workspaceDir = Get-Location
    
    # Create VSCode settings
    $vscodeSettings = @{
        "agWrapper.enabled" = $true
        "agWrapper.pythonPath" = Get-AGPath
        "agWrapper.blockOnCritical" = $true
        "agWrapper.pruneContext" = $true
    }
    
    # Copy integration files
    $sourceDir = Join-Path $PSScriptRoot "vscode"
    if (Test-Path $sourceDir) {
        $targetDir = Join-Path $workspaceDir ".vscode"
        if (-Not (Test-Path $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir | Out-Null
        }
        
        Copy-Item (Join-Path $sourceDir "tasks.json") $targetDir -ErrorAction SilentlyContinue
        Copy-Item (Join-Path $sourceDir "settings.json") $targetDir -ErrorAction SilentlyContinue
        Write-Success "VSCode files copied to .vscode/"
    }
    
    Write-Success "VSCode integration installed"
    Write-Status "Press Ctrl+Shift+P and run 'Tasks: Run Task' to use AG tasks"
}

function Install-Cursor {
    Write-Status "Installing Cursor integration..."
    
    $workspaceDir = Get-Location
    
    # Cursor uses VSCode config + MCP
    $sourceDir = Join-Path $PSScriptRoot "cursor"
    $targetDir = Join-Path $workspaceDir ".cursor"
    
    if (-Not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir | Out-Null
    }
    
    if (Test-Path $sourceDir) {
        Copy-Item (Join-Path $sourceDir "mcp.json") $targetDir -ErrorAction SilentlyContinue
    }
    
    Write-Success "Cursor integration installed"
    Write-Status "Cursor will use MCP server configuration"
}

function Install-Nova {
    Write-Status "Installing Nova AI integration..."
    
    $novaDir = "$env:USERPROFILE\.nova"
    if (-Not (Test-Path $novaDir)) {
        New-Item -ItemType Directory -Path $novaDir | Out-Null
    }
    
    # Create Nova config
    $config = @"
[ag]
enabled = true
python_path = python
project_root = .
block_on_critical = true
prune_context = true
sanitize_input = true
sanitize_output = true
"@
    
    $configPath = Join-Path $novaDir "ag.conf"
    $config | Out-File -FilePath $configPath -Encoding utf8
    
    Write-Success "Nova integration installed"
}

function Install-Alice {
    Write-Status "Installing Alice AI integration..."
    
    $aliceDir = "$env:USERPROFILE\.alice"
    if (-Not (Test-Path $aliceDir)) {
        New-Item -ItemType Directory -Path $aliceDir | Out-Null
    }
    
    # Create Alice config
    $config = @"
ag:
  enabled: true
  python_path: python
  project_root: .
  security:
    block_on_critical: true
    scan_on_generate: true
  sanitize:
    input: true
    output: true
"@
    
    $configPath = Join-Path $aliceDir "ag.yaml"
    $config | Out-File -FilePath $configPath -Encoding utf8
    
    # Environment variables
    $envContent = @"
export AG_ENABLED=true
export AG_BLOCK_CRITICAL=true
export AG_SANITIZE_OUTPUT=true
"@
    
    $envPath = Join-Path $aliceDir "env"
    $envContent | Out-File -FilePath $envPath -Encoding utf8
    
    Write-Success "Alice integration installed"
}

function Install-Build {
    Write-Status "Installing Build AI integration..."
    
    $buildDir = "$env:USERPROFILE\.build"
    if (-Not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }
    
    # Create Build config
    $config = @"
version: "1.0"
ag:
  enabled: true
  mode: "wrapper"
  wrapper:
    input_hook: "python -m src.cli sanitize clean"
    output_hook: "python -m src.cli shield scan"
    block_on_critical: true
"@
    
    $configPath = Join-Path $buildDir "ag.yaml"
    $config | Out-File -FilePath $configPath -Encoding utf8
    
    # Environment
    $envContent = @"
export BUILD_AG_ENABLED=1
export BUILD_AG_BLOCK=1
export BUILD_AG_SANITIZE=1
"@
    
    $envPath = Join-Path $buildDir "env"
    $envContent | Out-File -FilePath $envPath -Encoding utf8
    
    Write-Success "Build integration installed"
}

function Uninstall-All {
    Write-Status "Uninstalling all integrations..."
    
    $dirs = @(
        "$env:USERPROFILE\.nova",
        "$env:USERPROFILE\.alice", 
        "$env:USERPROFILE\.build"
    )
    
    foreach ($dir in $dirs) {
        if (Test-Path $dir) {
            Remove-Item (Join-Path $dir "ag.*") -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $dir "env") -ErrorAction SilentlyContinue
        }
    }
    
    # Remove .vscode integration files
    $vscodeFiles = @("tasks.json", "settings.json")
    $workspaceDir = Get-Location
    foreach ($file in $vscodeFiles) {
        $path = Join-Path $workspaceDir ".vscode\$file"
        if (Test-Path $path) {
            Remove-Item $path -ErrorAction SilentlyContinue
        }
    }
    
    Write-Success "All integrations uninstalled"
}

# Main
Write-Host ""
Write-Host "==========================================" -ForegroundColor $BLUE
Write-Host "  AG-Wrapper Integration Installer" -ForegroundColor $BLUE
Write-Host "==========================================" -ForegroundColor $BLUE
Write-Host ""

if ($Uninstall) {
    Uninstall-All
    exit 0
}

if ($All) {
    $Integrations = @("vscode", "cursor", "nova", "alice", "build")
}

foreach ($integration in $Integrations) {
    switch ($integration.ToLower()) {
        "vscode" { Install-VSCode }
        "cursor" { Install-Cursor }
        "nova"   { Install-Nova }
        "alice"  { Install-Alice }
        "build"  { Install-Build }
        default  { Write-Warn "Unknown integration: $integration" }
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor $GREEN
Write-Host "  Installation Complete!" -ForegroundColor $GREEN
Write-Host "==========================================" -ForegroundColor $GREEN
Write-Host ""
Write-Host "Usage examples:" -ForegroundColor $BLUE
Write-Host "  python -m src.cli sanitize scan file.py" -ForegroundColor $YELLOW
Write-Host "  python -m src.cli shield scan file.py" -ForegroundColor $YELLOW
Write-Host "  python -m src.cli prune extract file.py --task 'fix bug'" -ForegroundColor $YELLOW
Write-Host ""