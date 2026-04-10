#!/bin/bash
# =============================================================================
# AG-Wrapper Integration Installer (Bash/Shell)
# 
# This script integrates AG-Wrapper with popular AI coding assistants.
# Run as: ./install-integrations.sh
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INTEGRATIONS=()
INSTALL_ALL=false
UNINSTALL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            INSTALL_ALL=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --vscode|--cursor|--nova|--alice|--build)
            INTEGRATIONS+=("${1:2}")
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--all] [--vscode] [--cursor] [--nova] [--alice] [--build] [--uninstall]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get ZTC path
get_ag_python() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local ag_root="$(cd "$script_dir/.." && pwd)"
    
    if [ -f "$ag_root/venv/bin/python" ]; then
        echo "$ag_root/venv/bin/python"
    else
        echo "python3"
    fi
}

install_vscode() {
    echo -e "${BLUE}[INFO]${NC} Installing VSCode integration..."
    
    local workspace_dir="$(pwd)"
    local source_dir="$(dirname "${BASH_SOURCE[0]}")/vscode"
    
    # Create .vscode directory
    mkdir -p "$workspace_dir/.vscode"
    
    # Copy files
    if [ -d "$source_dir" ]; then
        [ -f "$source_dir/tasks.json" ] && cp "$source_dir/tasks.json" "$workspace_dir/.vscode/"
        [ -f "$source_dir/settings.json" ] && cp "$source_dir/settings.json" "$workspace_dir/.vscode/"
    fi
    
    # Update python path in tasks.json
    if [ -f "$workspace_dir/.vscode/tasks.json" ]; then
        local ag_python=$(get_ag_python)
        sed -i "s|python.exe|$(basename $ag_python)|g" "$workspace_dir/.vscode/tasks.json"
        sed -i "s|venv/Scripts/python.exe|venv/bin/python|g" "$workspace_dir/.vscode/tasks.json"
    fi
    
    echo -e "${GREEN}[OK]${NC} VSCode integration installed"
    echo -e "${BLUE}[INFO]${NC} Press Ctrl+Shift+P and run 'Tasks: Run Task' to use ZTC tasks"
}

install_cursor() {
    echo -e "${BLUE}[INFO]${NC} Installing Cursor integration..."
    
    local workspace_dir="$(pwd)"
    local source_dir="$(dirname "${BASH_SOURCE[0]}")/cursor"
    local target_dir="$workspace_dir/.cursor"
    
    mkdir -p "$target_dir"
    
    if [ -d "$source_dir" ]; then
        [ -f "$source_dir/mcp.json" ] && cp "$source_dir/mcp.json" "$target_dir/"
    fi
    
    echo -e "${GREEN}[OK]${NC} Cursor integration installed"
}

install_nova() {
    echo -e "${BLUE}[INFO]${NC} Installing Nova AI integration..."
    
    local nova_dir="$HOME/.nova"
    mkdir -p "$nova_dir"
    
    cat > "$nova_dir/ag.conf" << 'EOF'
[ag]
enabled = true
python_path = python3
project_root = .
block_on_critical = true
prune_context = true
sanitize_input = true
sanitize_output = true
EOF
    
    echo -e "${GREEN}[OK]${NC} Nova integration installed"
}

install_alice() {
    echo -e "${BLUE}[INFO]${NC} Installing Alice AI integration..."
    
    local alice_dir="$HOME/.alice"
    mkdir -p "$alice_dir"
    
    cat > "$alice_dir/ag.yaml" << 'EOF'
ag:
  enabled: true
  python_path: python3
  project_root: .
  security:
    block_on_critical: true
    scan_on_generate: true
  sanitize:
    input: true
    output: true
EOF
    
    cat > "$alice_dir/env" << 'EOF'
export AG_ENABLED=true
export AG_BLOCK_CRITICAL=true
export AG_SANITIZE_OUTPUT=true
EOF
    
    echo -e "${GREEN}[OK]${NC} Alice integration installed"
}

install_build() {
    echo -e "${BLUE}[INFO]${NC} Installing Build AI integration..."
    
    local build_dir="$HOME/.build"
    mkdir -p "$build_dir"
    
    cat > "$build_dir/ag.yaml" << 'EOF'
version: "1.0"
ag:
  enabled: true
  mode: "wrapper"
  wrapper:
    input_hook: "python3 -m src.cli sanitize clean"
    output_hook: "python3 -m src.cli shield scan"
    block_on_critical: true
EOF
    
    cat > "$build_dir/env" << 'EOF'
export BUILD_AG_ENABLED=1
export BUILD_AG_BLOCK=1
export BUILD_AG_SANITIZE=1
EOF
    
    echo -e "${GREEN}[OK]${NC} Build integration installed"
}

uninstall_all() {
    echo -e "${BLUE}[INFO]${NC} Uninstalling all integrations..."
    
    # Remove configs
    rm -f "$HOME/.nova/ag.conf" 2>/dev/null || true
    rm -f "$HOME/.alice/ag.yaml" 2>/dev/null || true
    rm -f "$HOME/.alice/env" 2>/dev/null || true
    rm -f "$HOME/.build/ag.yaml" 2>/dev/null || true
    rm -f "$HOME/.build/env" 2>/dev/null || true
    
    # Remove .vscode files
    rm -f ".vscode/tasks.json" 2>/dev/null || true
    rm -f ".vscode/settings.json" 2>/dev/null || true
    
    echo -e "${GREEN}[OK]${NC} All integrations uninstalled"
}

# Main
echo ""
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}  AG-Wrapper Integration Installer${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""

if [ "$UNINSTALL" = true ]; then
    uninstall_all
    exit 0
fi

if [ "$INSTALL_ALL" = true ]; then
    INTEGRATIONS=("vscode" "cursor" "nova" "alice" "build")
fi

if [ ${#INTEGRATIONS[@]} -eq 0 ]; then
    echo "No integrations specified. Use --all or specify --vscode --cursor etc."
    echo "Usage: $0 [--all] [--vscode] [--cursor] [--nova] [--alice] [--build] [--uninstall]"
    exit 1
fi

for integration in "${INTEGRATIONS[@]}"; do
    case $integration in
        vscode)  install_vscode  ;;
        cursor)  install_cursor  ;;
        nova)    install_nova    ;;
        alice)   install_alice   ;;
        build)   install_build   ;;
        *)       echo -e "${YELLOW}[WARN]${NC} Unknown integration: $integration" ;;
    esac
done

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "${BLUE}Usage examples:${NC}"
echo -e "  $(get_ag_python) -m src.cli sanitize scan file.py"
echo -e "  $(get_ag_python) -m src.cli shield scan file.py"
echo -e "  $(get_ag_python) -m src.cli prune extract file.py --task 'fix bug'"
echo ""