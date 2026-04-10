#!/bin/bash
# =============================================================================
# ZTC-Wrapper Installation Script
# Supports: Ubuntu, Debian, Fedora, Arch, macOS
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "  ZTC-Wrapper Installation Script"
    echo "  Zero-Trust AI Agent Security"
    echo "=========================================="
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "$ID" in
                ubuntu|debian) echo "debian" ;;
                fedora|rhel|centos) echo "fedora" ;;
                arch) echo "arch" ;;
                *) echo "linux" ;;
            esac
        else
            echo "linux"
        fi
    else
        echo "unknown"
    fi
}

check_python() {
    print_status "Checking Python..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        print_success "Python found: $PYTHON_VERSION"
        
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        if [ "$PYTHON_MINOR" -ge 11 ]; then
            print_success "Python 3.11+ OK"
            return 0
        else
            print_error "Python 3.11+ required"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

install_deps_debian() {
    print_status "Installing deps for Debian/Ubuntu..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv git
    print_success "Done"
}

install_deps_fedora() {
    print_status "Installing deps for Fedora..."
    sudo dnf install -y python311 python3-pip git
    print_success "Done"
}

install_deps_arch() {
    print_status "Installing deps for Arch..."
    sudo pacman -S --noconfirm python python-pip git
    print_success "Done"
}

install_deps_macos() {
    print_status "Checking macOS deps..."
    if ! command -v python3 &> /dev/null; then
        print_status "Installing Python via Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        brew install python3
    fi
    print_success "Done"
}

install_ag() {
    print_status "Installing AG-Wrapper..."
    
    # Create venv
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install pytest pytest-cov
    
    print_success "AG-Wrapper installed!"
    echo ""
    echo "=========================================="
    echo "  INSTALLATION COMPLETE"
    echo "=========================================="
    echo ""
    echo "Usage:"
    echo "  source venv/bin/activate"
    echo "  python -m src.cli --help"
    echo ""
    echo "Web Dashboard:"
    echo "  python server.py"
    echo ""
}

main() {
    print_banner
    
    OS=$(detect_os)
    print_status "Detected OS: $OS"
    
    check_python || exit 1
    
    case $OS in
        debbian) install_deps_debian ;;
        fedora) install_deps_fedora ;;
        arch) install_deps_arch ;;
        macos) install_deps_macos ;;
    esac
    
    install_ag
}

main "$@"
