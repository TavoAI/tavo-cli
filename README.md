# Tavo.AI CLI

A comprehensive security scanning tool that combines **OpenGrep** pattern-based analysis with **OPA (Open Policy Agent)** policy evaluation for advanced LLM security assessments.

## 🚀 Features

- **Hybrid Scanning**: Combines static analysis (OpenGrep) with policy-based evaluation (OPA)
- **Rule Management**: Flexible rule system supporting bundled, API-fetched, and local rules
- **SARIF Output**: Industry-standard security report format
- **LLM Security Focus**: Specialized rules for LLM applications and AI systems
- **Batch AI Analysis**: Optional AI-powered analysis for advanced analysis and rules
- **Modular Architecture**: Clean separation of concerns for easy extension

## 📋 Table of Contents

- [Installation](#️-installation)
- [Authentication](#-authentication)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Architecture](#️-architecture)
- [Rule Management](#-rule-management)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- Git
- pipenv (recommended) or pip

### Automated Setup

```bash
# Clone the repository
git clone https://github.com/TavoAI/tavo-cli.git
cd tavo-cli

# Run the automated build script
./build.sh
```

The build script will:

- Set up Python virtual environment
- Install all dependencies
- Build OpenGrep from source
- Configure the CLI for use

### Manual Setup

#### Using pipenv (recommended)

```bash
# Clone with submodules
git clone --recursive https://github.com/TavoAI/tavo-cli.git
cd tavo-cli

# Install dependencies
pipenv install --dev

# Activate environment
pipenv shell

# Build OpenGrep
cd opengrep
make
cd ..

# Install the CLI
pip install -e .
```

#### Using pip

```bash
# Clone with submodules
git clone --recursive https://github.com/TavoAI/tavo-cli.git
cd tavo-cli

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt

# Build OpenGrep
cd opengrep
make
cd ..

# Install the CLI
pip install -e .
```

## � Authentication

Tavo CLI supports two authentication methods: **JWT-based account authentication** (recommended) and **API key authentication** (non-interactive).

### JWT Authentication (Recommended for Interactive Use)

JWT authentication provides secure, account-aware access with automatic token management and is ideal for active tool usage.

#### Login

```bash
tavo auth login
```

This initiates OAuth2 device code flow:

1. CLI requests device and user codes from Tavo API
2. Displays verification URL and user code
3. User visits URL in browser and enters code
4. CLI polls for approval and stores JWT tokens

Example output:

```bash
🔐 Starting device code authentication...
📱 Go to: https://app.tavoai.net/auth/device
🔢 Enter code: ABCD-1234
⏳ Waiting for approval...
✅ Successfully authenticated as user@example.com
```

#### Check Authentication Status

```bash
tavo auth whoami
```

Shows current authenticated user:

```bash
👤 Authenticated as: user@example.com
📧 Email: user@example.com
📝 Name: John Doe
```

#### Logout

```bash
tavo auth logout
```

Clears stored authentication tokens.

### API Key Authentication (For Embedded Integrations)

API key authentication is designed for embedded integrations, automated systems, and environments where JWT tokens might expire and not be renewable (such as GitHub Actions, CI/CD pipelines, and other headless environments).

#### Set API Key

```bash
tavo config set-api-key
```

Prompts for API key and stores it securely.

#### View API Key (Masked)

```bash
tavo config get-api-key
```

#### Remove API Key

```bash
tavo config clear-api-key
```

### Authentication Priority

When both JWT tokens and API keys are configured:

1. **JWT tokens are used first** (preferred for interactive use)
2. **API keys serve as fallback** for embedded integrations

### Configuration Storage

Authentication data is stored securely in `~/.tavo/config.json`:

```json
{
  "auth": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe"
    }
  },
  "api_key": "tavo-sk-... (fallback)"
}
```

### Future Authentication Methods

Additional authentication methods including OIDC will be available in future releases.

## �🚀 Quick Start

```bash
# Scan a repository for LLM security issues
tavo scan /path/to/your/repo

# List available rule categories
tavo rules list

# Export rules to files
tavo rules export --type opengrep --output my_rules.yml
tavo rules export --type opa --output my_policies.json

# Validate policies with OPA
tavo validate /path/to/repo
```

## 📖 Usage

### Basic Scanning

```bash
tavo scan /path/to/repo [OPTIONS]

Options:
  --rules-dir TEXT     Directory containing OpenGrep rules [default: .opengrep]
  --opa-policy TEXT    Directory for OPA Rego policies [default: opa/policies]
  --output TEXT        Output SARIF report file [default: scan_report.sarif]
  --ai-batch           Enable batch AI analysis for advanced analysis and rules
```

### Rule Management

```bash
# List all available rules
tavo rules list

# Export OpenGrep rules to YAML
tavo rules export --type opengrep --output rules.yml

# Export OPA policies to JSON
tavo rules export --type opa --output policies.json

# Refresh rules from API (when implemented)
tavo rules refresh
```

### Policy Validation

```bash
tavo validate /path/to/repo [OPTIONS]

Options:
  --opa-policy TEXT    Directory for OPA Rego policies [default: opa/policies]
```

## 🏗️ Architecture

```bash
tavo-cli/
├── main.py                 # CLI entry point
├── tavo_cli/
│   └── rules/
│       ├── __init__.py
│       ├── rule_manager.py # Core rule management
│       └── bundled_rules.json # Pre-packaged rules
├── opengrep/               # Git submodule
├── test/                   # Test files and examples
└── build.sh               # Automated build script
```

### Components

- **CLI Layer**: Click-based command interface
- **Rule Manager**: Handles rule loading, caching, and API integration
- **OpenGrep Integration**: Static analysis engine
- **OPA Integration**: Policy evaluation engine
- **SARIF Generator**: Standardized security reporting

## 📋 Rule Management

### Rule Sources

1. **Bundled Rules**: Pre-packaged rules included with the CLI
2. **API Rules**: Fresh rules fetched from Tavo.AI API
3. **Local Rules**: Custom rules in your repository

### Rule Types

- **OpenGrep Rules**: YAML-based pattern matching rules
- **OPA Policies**: Rego-based policy evaluation rules

### Bundled Rules Include

- **LLM Security**: Prompt injection, data leakage, model poisoning
- **Financial Compliance**: PCI DSS, SOX requirements
- **Healthcare**: HIPAA compliance rules

## 🔧 Development

### Setup Development Environment

```bash
# Install development dependencies
pipenv install --dev

# Run tests
pipenv run pytest

# Run linting
pipenv run flake8

# Type checking
pipenv run mypy
```

### Building OpenGrep

```bash
# From the opengrep submodule
cd opengrep
make

# Or for development builds
make dev
```

### Testing

```bash
# Run all tests
pipenv run pytest

# Run specific test file
pipenv run pytest test/test_rule_manager.py

# Run with coverage
pipenv run pytest --cov=tavo_cli
```

### Adding New Rules

1. **OpenGrep Rules**: Add to `tavo_cli/rules/bundled_rules.json` under `opengrep` section
2. **OPA Policies**: Add to `tavo_cli/rules/bundled_rules.json` under `opa` section
3. **Test**: Run `tavo rules list` to verify

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `pipenv run pytest`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add type hints for new functions
- Write comprehensive tests
- Update documentation for API changes
- Use conventional commit messages

## 📊 CI/CD

The project uses GitHub Actions for continuous integration:

- **Linting**: flake8 for code style
- **Type Checking**: mypy for static type analysis
- **Testing**: pytest with coverage reporting
- **Build**: Automated building of OpenGrep and CLI package

## 📈 Performance

- **Rule Caching**: API-fetched rules cached for 24 hours
- **Incremental Scanning**: Only scan changed files when possible
- **Parallel Processing**: Multi-threaded rule evaluation
- **Memory Efficient**: Streaming processing for large codebases

## 🔒 Security

- **Dependency Scanning**: Automated vulnerability checks
- **Rule Updates**: Regular security rule updates via API
- **Safe Execution**: Sandboxed rule evaluation
- **Audit Logging**: Comprehensive security event logging

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

### Dependencies

This project builds upon and integrates with several open source projects:

- **[OpenGrep](https://github.com/opengrep/opengrep)** - LGPL 2.1 License
- **[Open Policy Agent (OPA)](https://www.openpolicyagent.org/)** - Apache License 2.0

The Apache 2.0 license is compatible with both LGPL and Apache licenses used by our dependencies.

## 🙏 Acknowledgments

- [OpenGrep](https://github.com/opengrep/opengrep) - Static analysis engine
- [Open Policy Agent](https://www.openpolicyagent.org/) - Policy evaluation
- [OWASP](https://owasp.org/) - Security best practices
- [SARIF](https://sarifweb.azurewebsites.net/) - Security reporting standard

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/TavoAI/tavo-cli/issues)
- **Discussions**: [GitHub Discussions](https://github.com/TavoAI/tavo-cli/discussions)
- **Documentation**: [Wiki](https://github.com/TavoAI/tavo-cli/wiki)

---

**Tavo.AI CLI** - Advanced security scanning for the AI era 🛡️

Licensed under the [Apache License 2.0](LICENSE)
