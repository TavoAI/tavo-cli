#!/bin/bash

# Tavo.AI CLI Build Script
# This script automates the setup and build process for the Tavo.AI CLI

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
        log_warning "pipenv not found, using venv"
        python3 -m venv .venv
        source .venv/bin/activate
        pip install -r requirements-dev.txt
        pip install -e .
        log_success "Python environment setup complete with venv"
    fi
}

# Build OpenGrep
build_opengrep() {
    log_info "Building OpenGrep..."

    if [ ! -d "opengrep" ]; then
        log_error "OpenGrep submodule not found. Run 'git submodule update --init --recursive'"
        exit 1
    fi

    cd opengrep

    # Check if already built
    if [ -f "_build/install/default/bin/opengrep-core" ]; then
        log_info "OpenGrep already built, skipping..."
        cd ..
        return
    fi

    log_info "Building OpenGrep from source..."
    log_info "Note: This may require system dependencies. See opengrep/INSTALL.md for details."

    # Try to install system dependencies if we're on a supported system
    if command_exists apt-get; then
        log_info "Detected Debian/Ubuntu system, installing dependencies..."
        sudo apt-get update
        sudo apt-get install -y libpcre2-dev pkg-config build-essential || {
            log_warning "Failed to install system dependencies automatically."
            log_warning "Please install manually: sudo apt-get install libpcre2-dev pkg-config build-essential"
        }
    elif command_exists yum; then
        log_info "Detected RHEL/CentOS system, installing dependencies..."
        sudo yum install -y pcre2-devel pkgconfig gcc gcc-c++ || {
            log_warning "Failed to install system dependencies automatically."
            log_warning "Please install manually: sudo yum install pcre2-devel pkgconfig gcc gcc-c++"
        }
    elif command_exists brew; then
        log_info "Detected macOS with Homebrew, installing dependencies..."
        brew install pcre2 pkg-config || {
            log_warning "Failed to install system dependencies automatically."
            log_warning "Please install manually: brew install pcre2 pkg-config"
        }
    else
        log_warning "Unknown system. Please ensure you have:"
        log_warning "  - PCRE2 development libraries"
        log_warning "  - pkg-config"
        log_warning "  - GCC/Clang compiler"
        log_warning "See opengrep/INSTALL.md for detailed instructions."
    fi

    # Clean and build
    make clean
    if make; then
        log_success "OpenGrep built successfully"
    else
        log_error "Failed to build OpenGrep. This is common due to missing system dependencies."
        log_info "You can try the following alternatives:"
        echo "  1. Install system dependencies manually (see above)"
        echo "  2. Use the pre-built binary: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash"
        echo "  3. Skip OpenGrep build for now and install it separately later"
        echo ""
        read -p "Continue with setup anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    cd ..
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
        "https://api.tavo.ai/rules/opengrep",
        "https://api.tavo.ai/rules/opa"
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
        if pipenv run tavo --help >/dev/null 2>&1; then
            log_success "CLI installation verified"
        else
            log_error "CLI installation failed"
            exit 1
        fi
    else
        source .venv/bin/activate
        if tavo --help >/dev/null 2>&1; then
            log_success "CLI installation verified"
        else
            log_error "CLI installation failed"
            exit 1
        fi
    fi

    # Check OpenGrep (be more flexible about location)
    if [ -f "opengrep/_build/install/default/bin/opengrep-core" ]; then
        log_success "OpenGrep binary found (built from source)"
    elif [ -f "opengrep/bin/opengrep" ]; then
        log_success "OpenGrep binary found (symlink)"
    elif command_exists opengrep; then
        log_success "OpenGrep found in PATH"
    else
        log_warning "OpenGrep binary not found in expected locations"
        log_info "You can install it later using: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash"
    fi

    # Test basic functionality
    log_info "Testing basic functionality..."
    if command_exists pipenv; then
        if pipenv run tavo rules list >/dev/null 2>&1; then
            log_success "Basic functionality test passed"
        else
            log_warning "Basic functionality test failed - this may be expected if no rules are configured"
        fi
    else
        if tavo rules list >/dev/null 2>&1; then
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
    echo "  tavo --help"
    echo "  tavo rules list"
    echo "  tavo scan /path/to/repo"
    echo ""
    echo "For more information, see README.md"
}

# Main build process
main() {
    echo "========================================"
    echo "  Tavo.AI CLI Build Script"
    echo "========================================"
    echo ""

    check_requirements
    echo ""

    setup_python_env
    echo ""

    build_opengrep
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