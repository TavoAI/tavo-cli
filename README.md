# TAVO CLI

TAVO (Open Policy Agent Verification and Testing) CLI tool provides an easy-to-use command-line interface for managing OPA policies.

## Prerequisites

Before installing TAVO CLI, you need to have Open Policy Agent (OPA) installed on your system.

### Installing OPA

#### macOS (ARM 64-bit)
```bash
brew install opa
```

Or

```bash
curl -L -o opa https://openpolicyagent.org/downloads/v1.3.0/opa_darwin_arm64_static
chmod 755 ./opa
```

#### Linux
```bash
curl -L -o opa https://openpolicyagent.org/downloads/v1.3.0/opa_linux_amd64_static
chmod 755 ./opa
```

Verify the installation:
```bash
opa version
```

## Installation

### Using pip

Upcoming

### Using Homebrew (macOS)

```bash
brew tap TavoAI/tavocli
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

### API Reference

The TAVO server provides the following REST APIs:

#### Policy Management

- **GET /policies/{policy_name}**
  - Retrieves a policy by name
  - Response: Policy details in JSON format

- **GET /policies**
  - Retrieves all policies
  - Query Parameters:
    - `domain`: Filter policies by domain
    - `applicability`: Filter by applicability (`input`, `output`, or `both`)
  - Response: List of policies in JSON format

- **POST /policies**
  - Creates or updates a policy
  - Request Body:
    ```json
    {
      "policy_name": "my_policy",
      "policy_description": "A brief description of the policy",
      "policy_applicability": "input",
      "policy_content": "package myapp\n ... rego code ...",
      "active": true
    }
    ```
  - Response: Created/updated policy details

- **DELETE /policies/{policy_name}**
  - Deletes a policy by name
  - Response: 204 No Content on success

- **DELETE /policies**
  - Deletes a policy using the name in request body
  - Request Body:
    ```json
    {
      "policy_name": "my_policy"
    }
    ```
  - Response: 204 No Content on success

#### Policy Activation

- **PUT /policies/{policy_name}/status**
  - Activates or deactivates a policy
  - Request Body:
    ```json
    {
      "active": true
    }
    ```
  - Response: Updated policy details

#### Policy Evaluation

- **POST /policies/{policy_name}/evaluate**
  - Evaluates input data against a specific policy
  - Request Body:
    ```json
    {
      "input": {
        "content_type": "input",
        "content": "example content to evaluate",
        "config": {
          "parameter1": true,
          "parameter2": false
        }
      }
    }
    ```
  - Response:
    ```json
    {
      "allow": true/false,
      "rejection_reasons": []
    }
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

## TODO

1. Explain different usage of MongoDbPolicyDataStore and LocalPolicyDataStore for state management for each policy
2. Add an architecture diagram to illustrate the purpose of this server

## License

MIT 