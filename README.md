# TAVO CLI

TAVO (Open Policy Agent Verification and Testing) CLI tool provides an easy-to-use command-line interface for managing OPA policies.

## Installation

### Using pip

```bash
pip install tavo-cli
```

### Using Homebrew (macOS)

```bash
brew tap TavoAI/tavo
brew install tavo
```

## Usage

### Start the development server

```bash
# Start the server with default settings
tavo server start-dev

# Use prebuilt policies
tavo server start-dev --pre-built

# Specify a custom database file
tavo server start-dev --db-filename my_db.json

# Use prebuilt policies and specify custom database
tavo server start-dev --pre-built --db-filename my_db.json
```

## Development

The CLI package is located in the `src` directory. To set up the development environment:

```bash
pip install -e .
```

## Project Structure

- `src/`: Core package directory
  - `server.py`: The main server implementation
  - `policy_store.py`: Policy storage implementation
  - `cli.py`: CLI implementation
  - `__main__.py`: CLI entry point
- `tests/`: Test directory
- `.github/workflows/`: CI/CD configuration

## License

MIT 