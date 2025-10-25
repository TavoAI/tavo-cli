#!/bin/bash

# Tavo AI CLI Build Script
# This script automates the setup and build process for the Tavo AI CLI

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    # Check Python
    if ! command_exists python3; then
        log_error "Python 3 is required but not installed."
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        log_success "Python $PYTHON_VERSION found"
    else
        log_error "Python 3.8+ is required. Found: $PYTHON_VERSION"
        exit 1
    fi

    # Check pip
    if ! command_exists pip3; then
        log_error "pip3 is required but not installed."
        exit 1
    fi
    log_success "pip3 found"

    # Check git
    if ! command_exists git; then
        log_error "git is required but not installed."
        exit 1
    fi
    log_success "git found"

    # Check make
    if ! command_exists make; then
        log_error "make is required but not installed."
        exit 1
    fi
    log_success "make found"
}

# Setup Python environment
setup_python_env() {
    log_info "Setting up Python virtual environment..."

    # Check if pipenv is available, otherwise use venv
    if command_exists pipenv; then
        log_info "Using pipenv for environment management"
        pipenv install --dev
        log_success "Python environment setup complete with pipenv"
    else
        log_info "Using venv for environment management"
        python3 -m venv .venv
        source .venv/bin/activate
        pip install -r requirements-dev.txt
        pip install -e .
        log_success "Python environment setup complete with venv"
    fi
}

# Download Tavo Scanner binary
download_tavo_scanner() {
    log_info "Building Tavo Scanner from source..."

    # Create bin directory
    mkdir -p bin

    # Check if tavo-sdk repository exists
    if [ ! -d "../tavo-sdk" ]; then
        log_error "tavo-sdk repository not found at ../tavo-sdk"
        log_error "Please clone tavo-sdk repository alongside tavo-cli"
        exit 1
    fi

    # Check if scanner package exists
    if [ ! -d "../tavo-sdk/packages/scanner" ]; then
        log_error "Scanner package not found in tavo-sdk"
        exit 1
    fi

    log_info "Building scanner binary..."

    # Change to scanner directory and build
    cd ../tavo-sdk/packages/scanner

    # Check if binary already exists
    if [ -f "dist/tavo-scanner" ]; then
        log_info "Scanner binary already exists, copying..."
        mkdir -p ../../tavo-cli/bin
        cp dist/tavo-scanner ../../tavo-cli/bin/
        cd ../../tavo-cli
        chmod +x bin/tavo-scanner
        log_success "Tavo Scanner binary copied"
        return
    fi

    # Download engines if needed
    if [ ! -d "engines" ] || [ -z "$(ls -A engines)" ]; then
        log_info "Downloading scanner engines..."
        chmod +x download_engines.sh
        ./download_engines.sh
    fi

    # Build the binary
    log_info "Building scanner binary with PyInstaller..."
    if command_exists pyinstaller; then
        pyinstaller --onefile --hidden-import yaml --add-data "engines:engines" --name tavo-scanner tavo_scanner.py
    else
        log_error "PyInstaller not found. Please install with: pip install pyinstaller"
        exit 1
    fi

    # Copy binary to CLI bin directory
    if [ -f "dist/tavo-scanner" ]; then
        mkdir -p ../../tavo-cli/bin
        cp dist/tavo-scanner ../../tavo-cli/bin/
        cd ../../tavo-cli
        chmod +x bin/tavo-scanner
        log_success "Tavo Scanner binary built and copied"
    else
        log_error "Failed to build Tavo Scanner binary"
        cd ../../tavo-cli
        exit 1
    fi
}

# Setup configuration
setup_config() {
    log_info "Setting up configuration..."

    # Create config directory
    CONFIG_DIR="$HOME/.tavo"
    mkdir -p "$CONFIG_DIR/rules"

    # Create default config if it doesn't exist
    CONFIG_FILE="$CONFIG_DIR/config.json"
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << EOF
{
    "version": "1.0.0",
    "cache_ttl_hours": 24,
    "api_endpoints": [
        "https://api.tavoai.net/rules/opengrep",
        "https://api.tavoai.net/rules/opa"
    ],
    "log_level": "INFO"
}
EOF
        log_success "Default configuration created at $CONFIG_FILE"
    else
        log_info "Configuration already exists at $CONFIG_FILE"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    # Check if CLI is available
    if command_exists pipenv; then
        if pipenv run python main.py --help >/dev/null 2>&1; then
            log_success "CLI installation verified"
        else
            log_warning "CLI verification failed, but continuing..."
        fi
    else
        if python main.py --help >/dev/null 2>&1; then
            log_success "CLI installation verified"
        else
            log_warning "CLI verification failed, but continuing..."
        fi
    fi

    # Check Tavo Scanner (check bundled binary first)
    if [ -f "bin/tavo-scanner" ]; then
        log_success "Tavo Scanner binary found (bundled)"
    elif command_exists tavo-scanner; then
        log_success "Tavo Scanner found in PATH"
    else
        log_warning "Tavo Scanner binary not found in expected locations"
        log_info "You can download it manually or run this build script"
    fi

    # Test basic functionality
    log_info "Testing basic functionality..."
    if command_exists pipenv; then
        if pipenv run python main.py rules list >/dev/null 2>&1; then
            log_success "Basic functionality test passed"
        else
            log_warning "Basic functionality test failed - this may be expected if no rules are configured"
        fi
    else
        if python main.py rules list >/dev/null 2>&1; then
            log_success "Basic functionality test passed"
        else
            log_warning "Basic functionality test failed - this may be expected if no rules are configured"
        fi
    fi
}

# Print usage information
print_usage() {
    log_info "Installation complete!"
    echo ""
    echo "Usage:"
    echo "  # Activate environment (if using venv)"
    echo "  source .venv/bin/activate"
    echo ""
    echo "  # Or use pipenv"
    echo "  pipenv shell"
    echo ""
    echo "  # Basic commands"
    echo "  python main.py --help"
    echo "  python main.py rules list"
    echo "  python main.py scan /path/to/repo"
    echo ""
    echo "For more information, see README.md"
}

# Main build process
main() {
    echo "========================================"
    echo "  Tavo AI CLI Build Script"
    echo "========================================"
    echo ""

    check_requirements
    echo ""

    setup_python_env
    echo ""

    download_tavo_scanner
    echo ""

    setup_config
    echo ""

    verify_installation
    echo ""

    print_usage
    echo ""

    log_success "Build completed successfully! 🎉"
}

# Run main function
main "$@"