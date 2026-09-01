#!/bin/bash
# =============================================================================
# AIGatekeeper Installation Script
# Zero-Trust AI Agent Security
# https://github.com/Leoshi123/AIGatekeeper
#
# Supports: Ubuntu, Debian, Fedora, Arch, macOS, CachyOS
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Print Functions
# =============================================================================

print_banner() {
    echo -e "${MAGENTA}"
    echo "        _    _____       _     _"
    echo "       / \\  |_   _| __ _| |__ | |_ ___  ___ _ __"
    echo "      / _ \\   | || '__| '_ \\| __/ _ \\/ _ \\ '__|"
    echo "     / ___ \\  | || |  | |_) | ||  __/  __/ |"
    echo "    /_/   \\_\\ |_||_|  |_.__/ \\__\\___|\\___|_|"
    echo ""
    echo "    🛡️  Zero-Trust AI Agent Security"
    echo "    Detect: zombie code, SQLi, XSS, prompt injection"
    echo "    Tools: sanitizer, AST pruner, MCP server"
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[-]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${CYAN}===${NC} ${BOLD}$1${NC} ${CYAN}===${NC}"
    echo ""
}

# =============================================================================
# Detection
# =============================================================================

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            # CachyOS detection
            if [[ "$ID" == *"cachyos"* ]] || [[ "$ID_LIKE" == *"arch"* ]]; then
                if grep -qi "cachyos" /etc/os-release 2>/dev/null; then
                    echo "cachyos"
                else
                    echo "arch"
                fi
            elif [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" == *"debian"* ]]; then
                echo "debian"
            elif [[ "$ID" == "fedora" || "$ID" == "rhel" || "$ID" == "centos" ]]; then
                echo "fedora"
            else
                echo "linux"
            fi
        else
            echo "linux"
        fi
    else
        echo "unknown"
    fi
}

check_python() {
    print_header "Checking Python"

    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        print_success "Python found: $PYTHON_VERSION"

        # Parse version - need 3.10+
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 10 ]; then
            print_success "Python 3.10+ OK"
            export PYTHON=python3
            return 0
        else
            print_error "Python 3.10+ required (found $PYTHON_VERSION)"
            return 1
        fi
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
        print_success "Python found: $PYTHON_VERSION"

        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        if [ "$PYTHON_MAJOR" -eq 2 ]; then
            print_error "Python 2 not supported"
            return 1
        fi

        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        if [ "$PYTHON_MINOR" -ge 10 ]; then
            print_success "Python 3.10+ OK"
            export PYTHON=python
            return 0
        else
            print_error "Python 3.10+ required (found $PYTHON_VERSION)"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

# =============================================================================
# OS-specific Dependencies
# =============================================================================

install_deps_debian() {
    print_header "Installing dependencies (Debian/Ubuntu)"
    print_status "Updating packages..."
    sudo apt-get update -y
    print_status "Installing: python3, python3-pip, python3-venv, git, curl..."
    sudo apt-get install -y python3 python3-pip python3-venv git curl
    print_success "Dependencies installed"
}

install_deps_fedora() {
    print_header "Installing dependencies (Fedora/RHEL)"
    print_status "Installing: python3, python3-pip, git, curl..."
    sudo dnf install -y python3 python3-pip git curl
    print_success "Dependencies installed"
}

install_deps_arch() {
    print_header "Installing dependencies (Arch Linux)"
    print_status "Installing: python, python-pip, git, curl..."
    sudo pacman -S --noconfirm python python-pip git curl
    print_success "Dependencies installed"
}

install_deps_cachyos() {
    print_header "Installing dependencies (CachyOS)"
    print_status "CachyOS detected - using pacman with optimizations..."
    print_status "Installing: python, python-pip, git, curl..."
    sudo pacman -S --noconfirm python python-pip git curl
    print_success "Dependencies installed"
}

install_deps_macos() {
    print_header "Checking dependencies (macOS)"

    # Check for Homebrew
    if ! command -v brew &> /dev/null; then
        print_warning "Homebrew not found"
        print_status "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_status "Installing Python via Homebrew..."
        brew install python3
    fi

    # Check git
    if ! command -v git &> /dev/null; then
        print_status "Installing git via Homebrew..."
        brew install git
    fi

    print_success "Dependencies ready"
}

# =============================================================================
# Main Installation
# =============================================================================

install_aigatekeeper() {
    print_header "Installing AIGatekeeper"

    # Get script directory or use current
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Check if we're in the repo already
    if [ -f "$SCRIPT_DIR/pyproject.toml" ] && [ -d "$SCRIPT_DIR/src" ]; then
        INSTALL_DIR="$SCRIPT_DIR"
        print_status "Installing from existing directory: $INSTALL_DIR"
    else
        # Clone from GitHub
        print_status "Cloning from GitHub..."
        if [ -d "AIGatekeeper" ]; then
            print_warning "Directory 'AIGatekeeper' already exists"
            print_status "Pulling latest changes..."
            cd AIGatekeeper && git pull && cd ..
        else
            git clone https://github.com/Leoshi123/AIGatekeeper.git
        fi
        INSTALL_DIR="$(pwd)/AIGatekeeper"
    fi

    cd "$INSTALL_DIR"

    # Create venv if not exists
    if [ ! -d ".venv" ]; then
        print_status "Creating virtual environment..."
        $PYTHON -m venv .venv
    fi

    # Activate venv
    print_status "Activating virtual environment..."
    source .venv/bin/activate

    # Upgrade pip
    print_status "Upgrading pip..."
    pip install --upgrade pip

    # Install in editable mode
    print_status "Installing AIGatekeeper (editable mode)..."
    pip install -e .

    print_success "AIGatekeeper installed!"

    # Verify
    print_status "Verifying installation..."
    if command -v aigatekeeper &> /dev/null; then
        VERSION=$(aigatekeeper --version 2>&1)
        print_success "Command 'aigatekeeper' available: $VERSION"
    elif python -c "from src.cli import cli; print('OK')" &>/dev/null; then
        print_success "Python module available"
    else
        print_warning "Command not in PATH. Use:"
        echo "    source .venv/bin/activate"
        echo "    aigatekeeper --help"
    fi
}

print_next_steps() {
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "${BOLD}                    🚀 INSTALLATION COMPLETE${NC}"
    echo -e "${CYAN}================================================================================${NC}"
    echo ""
    echo -e "${BOLD}Quick Start:${NC}"
    echo ""
    echo "  # Activate environment (if needed)"
    echo "  source .venv/bin/activate"
    echo ""
    echo "  # Initialize in your project"
    echo "  cd your-project"
    echo "  aigatekeeper init"
    echo ""
    echo "  # Scan for prompt injection"
    echo "  aigatekeeper scan-prompt \"Ignore all previous instructions\""
    echo ""
    echo "  # List available prompts"
    echo "  aigatekeeper prompt list"
    echo ""
    echo "  # Secure git push"
    echo "  aigatekeeper push \"feat: add security feature\""
    echo ""
    echo -e "${BOLD}Also try:${NC}"
    echo "  ag --help                     # Alias for aigatekeeper"
    echo "  aigatekeeper shield scan .    # Scan for zombie code"
    echo "  aigatekeeper hooks install    # Install pre-commit hooks"
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    print_banner

    OS=$(detect_os)
    print_status "Detected OS: $OS"
    echo ""

    # Check Python
    check_python || {
        echo ""
        case $OS in
            debian)
                print_error "Install Python 3.10+ with:"
                echo "    sudo apt-get install python3 python3-pip"
                ;;
            fedora)
                print_error "Install Python 3.10+ with:"
                echo "    sudo dnf install python3 python3-pip"
                ;;
            arch|cachyos)
                print_error "Install Python 3.10+ with:"
                echo "    sudo pacman -S python python-pip"
                ;;
            macos)
                print_error "Install Python 3.10+ with:"
                echo "    brew install python3"
                ;;
            *)
                print_error "Install Python 3.10+ from https://python.org"
                ;;
        esac
        exit 1
    }

    # Install OS-specific deps
    case $OS in
        debian) install_deps_debian ;;
        fedora) install_deps_fedora ;;
        arch) install_deps_arch ;;
        cachyos) install_deps_cachyos ;;
        macos) install_deps_macos ;;
        linux)
            print_warning "Generic Linux - assuming dependencies are installed"
            ;;
        *)
            print_warning "Unknown OS - assuming dependencies are installed"
            ;;
    esac

    # Install AIGatekeeper
    install_aigatekeeper

    # Done
    print_next_steps
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_banner
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -h, --help    Show this help message"
            echo ""
            echo "Install via curl:"
            echo "  curl -fsSL https://raw.githubusercontent.com/Leoshi123/AIGatekeeper/main/install.sh | bash"
            echo ""
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

main "$@"
