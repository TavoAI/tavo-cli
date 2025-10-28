import click
import subprocess
import json
import os
import time
import requests
from pathlib import Path
from typing import Optional

# Constants
TAVO_CONFIG_DIR = ".tavo"
RULES_CACHE_DIR = "rules"
CONFIG_FILE = "config.json"


def get_config_dir() -> Path:
    """Get the Tavo configuration directory."""
    return Path.home() / TAVO_CONFIG_DIR


def get_config_file() -> Path:
    """Get the configuration file path."""
    return get_config_dir() / CONFIG_FILE


def load_config() -> dict:
    """Load configuration from file."""
    config_file = get_config_file()
    if config_file.exists():
        try:
            return json.loads(config_file.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def save_config(config: dict) -> None:
    """Save configuration to file."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = get_config_file()
    config_file.write_text(json.dumps(config, indent=2))


def get_api_key() -> Optional[str]:
    """Get API key from config or environment."""
    # Check environment variable first
    api_key = os.getenv("TAVO_API_KEY")
    if api_key:
        return api_key

    # Check config file
    config = load_config()
    return config.get("api_key")


def get_session_token() -> Optional[str]:
    """Get session token from config or environment."""
    # Check environment variable first
    session_token = os.getenv("TAVO_SESSION_TOKEN")
    if session_token:
        return session_token

    # Check config file
    config = load_config()
    return config.get("session_token")


def get_auth_tokens() -> Optional[dict]:
    """Get JWT tokens from config."""
    config = load_config()
    auth = config.get("auth", {})
    if auth.get("access_token") and auth.get("refresh_token"):
        return auth
    return None


def get_current_user() -> Optional[dict]:
    """Get current authenticated user info."""
    config = load_config()
    return config.get("auth", {}).get("user")


def is_authenticated() -> bool:
    """Check if user is authenticated with JWT tokens."""
    tokens = get_auth_tokens()
    return tokens is not None


def has_api_access() -> bool:
    """Check if user has API access configured (API key, JWT, or session token)."""
    return (
        get_api_key() is not None
        or is_authenticated()
        or get_session_token() is not None
    )


def get_base_url() -> str:
    """Get the base URL for the Tavo API."""
    return os.getenv("TAVO_API_URL", "https://api.tavoai.net")


def make_api_request(method: str, endpoint: str, **kwargs) -> requests.Response:
    """Make an authenticated API request."""
    base_url = get_base_url()
    url = f"{base_url}{endpoint}"

    headers = kwargs.pop("headers", {})

    # Add authentication
    tokens = get_auth_tokens()
    if tokens:
        headers["Authorization"] = f"Bearer {tokens['access_token']}"
    elif get_session_token():
        headers["X-Session-Token"] = get_session_token()
    elif get_api_key():
        headers["X-API-Key"] = get_api_key()

    return requests.request(method, url, headers=headers, **kwargs)


def save_auth_tokens(access_token: str, refresh_token: str, user_info: dict) -> None:
    """Save authentication tokens and user info to config."""
    config = load_config()
    config["auth"] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user_info,
    }
    save_config(config)


def clear_auth_tokens() -> None:
    """Clear authentication tokens from config."""
    config = load_config()
    if "auth" in config:
        del config["auth"]
        save_config(config)


@click.group()
def cli():
    """Tavo AI CLI for LLM security scanning."""
    pass


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option(
    "--rules-dir", default=".tavo", help="Directory containing Tavo Scanner rules."
)
@click.option(
    "--opa-policy", default="opa/policies", help="Directory for OPA Rego policies."
)
@click.option("--output", default="scan_report.sarif", help="Output SARIF report file.")
@click.option(
    "--ai-batch", is_flag=True, help="Enable batch AI polling for ambiguous issues."
)
@click.option(
    "--api", is_flag=True, help="Use Tavo API for enhanced scanning and reporting."
)
@click.option(
    "--static-plugins",
    help="Comma-separated list of static analysis plugin IDs to run.",
)
@click.option(
    "--dynamic-plugins",
    help="Comma-separated list of dynamic testing plugin IDs to run.",
)
@click.option(
    "--plugin-config",
    type=click.Path(exists=True),
    help="Path to plugin configuration JSON file.",
)
def scan(
    repo_path,
    rules_dir,
    opa_policy,
    output,
    ai_batch,
    api,
    static_plugins,
    dynamic_plugins,
    plugin_config,
):
    """Run security scans on a repository."""
    repo_path = Path(repo_path)

    # Check API access
    if api and not has_api_access():
        click.echo("❌ API access required but no authentication found.", err=True)
        click.echo("   Authenticate with:", err=True)
        click.echo("   • 'tavo auth login' (recommended)", err=True)
        click.echo("   • 'tavo config set-session-token'", err=True)
        click.echo("   • 'tavo config set-api-key'", err=True)
        return

    if not api and not has_api_access():
        click.echo("⚠️  Running in local mode without authentication.")
        click.echo("   Local scanning provides basic analysis only.")
        click.echo("   For enhanced AI analysis and reporting,")
        click.echo("   authenticate with:")
        click.echo("   Run 'tavo auth login' or 'tavo config set-api-key'")
        click.echo()

    if api:
        # API-based scanning
        return scan_with_api(
            repo_path, output, static_plugins, dynamic_plugins, plugin_config
        )
    else:
        # Local scanning with warnings
        return scan_local(
            repo_path,
            rules_dir,
            opa_policy,
            output,
            ai_batch,
            static_plugins,
            dynamic_plugins,
            plugin_config,
        )


def scan_with_api(
    repo_path: Path,
    output: str,
    static_plugins: Optional[str] = None,
    dynamic_plugins: Optional[str] = None,
    plugin_config: Optional[str] = None,
) -> None:
    """Scan repository using Tavo API."""
    if not has_api_access():
        click.echo("❌ No authentication configured.", err=True)
        click.echo("   Authenticate with:", err=True)
        click.echo("   • 'tavo auth login' (recommended)", err=True)
        click.echo("   • 'tavo config set-session-token'", err=True)
        click.echo("   • 'tavo config set-api-key'", err=True)
        return

    try:
        click.echo(f"🔍 Scanning {repo_path} via Tavo API...")

        # For now, show that API scanning would work
        # This is a placeholder until the full API integration is implemented
        click.echo("✅ API scan initiated (placeholder)")
        click.echo("   Full API integration coming soon...")

        # TODO: Implement actual API scanning when endpoints are ready

    except Exception as e:
        click.echo(f"❌ API scan failed: {e}", err=True)


def scan_local(
    repo_path: Path,
    rules_dir: str,
    opa_policy: str,
    output: str,
    ai_batch: bool,
    static_plugins: Optional[str] = None,
    dynamic_plugins: Optional[str] = None,
    plugin_config: Optional[str] = None,
) -> None:
    """Run local scanning with Tavo Scanner."""
    rules_path = repo_path / rules_dir
    opa_path = repo_path / opa_policy

    # Ensure rules directory exists with example rules
    if not rules_path.exists():
        click.echo(
            f"Rules directory {rules_path} not found. " "Creating with example rules."
        )
        create_example_rules(rules_path)

    # Run Tavo Scanner - try multiple possible locations
    scanner_cmd = None

    # Try bundled binary first
    bundled_path = Path(__file__).parent / "bin" / "tavo-scanner"
    if bundled_path.exists():
        scanner_cmd = str(bundled_path)
    else:
        # Try system PATH
        import shutil

        if shutil.which("tavo-scanner"):
            scanner_cmd = "tavo-scanner"
        else:
            click.echo("Error: Tavo Scanner not found.")
            click.echo("Please ensure Tavo Scanner is installed.")
            click.echo("Run: ./build.sh")
            return

    # Use tavo-scanner with JSON format
    cmd = [scanner_cmd, "--format", "json", str(repo_path)]

    # Add plugin options if specified
    if static_plugins:
        cmd.extend(["--static-plugins", static_plugins])
    if dynamic_plugins:
        cmd.extend(["--dynamic-plugins", dynamic_plugins])
    if plugin_config:
        cmd.extend(["--plugin-config", plugin_config])

    # Add API key if available for plugin marketplace access
    api_key = get_api_key()
    if api_key:
        cmd.extend(["--api-key", api_key])

    click.echo(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = []

        if result.returncode == 0:
            # Parse JSON output directly
            try:
                scan_results = json.loads(result.stdout)
                # Tavo Scanner returns findings in different format - adjust as needed
                findings = scan_results.get("results", scan_results.get("findings", []))
                click.echo(f"Tavo Scanner completed. Found {len(findings)} issues.")
            except json.JSONDecodeError:
                click.echo(f"Failed to parse JSON output: {result.stdout}")
                findings = []
        else:
            click.echo(
                f"Tavo Scanner error (exit code {result.returncode}): {result.stderr}"
            )
            if result.stdout:
                click.echo(f"Tavo Scanner stdout: {result.stdout}")
            findings = []

        # Save results to SARIF file
        sarif_output = generate_sarif_report(findings)
        output_path = Path(output)
        output_path.write_text(json.dumps(sarif_output, indent=2), encoding="utf-8")
        click.echo(f"Report saved to {output}")

        # Show upgrade prompt
        if not has_api_access():
            click.echo()
            click.echo("🚀 Upgrade to API-powered scanning for:")
            click.echo("   • AI-enhanced vulnerability analysis")
            click.echo("   • Advanced rule filtering")
            click.echo("   • Cloud-based reporting and tracking")
            click.echo("   Run 'tavo config set-api-key' to get started!")

    except subprocess.TimeoutExpired:
        click.echo("Scan timed out after 5 minutes")
    except Exception as e:
        click.echo(f"Scan failed: {e}")


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option(
    "--opa-policy", default="opa/policies", help="Directory for OPA Rego policies."
)
def validate(repo_path, opa_policy):
    """Run OPA validation for local policy checks (e.g., RAG compliance)."""
    opa_path = Path(repo_path) / opa_policy
    if not opa_path.exists():
        click.echo(f"OPA policies directory {opa_path} not found.")
        return

    # Placeholder: Run OPA eval (requires OPA installed)
    cmd = [
        "opa",
        "eval",
        "--data",
        str(opa_path),
        "--input",
        '{"test": "data"}',
        "data.policy.allow",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        click.echo(result.stdout or result.stderr)
    except FileNotFoundError:
        click.echo("OPA not found. Please install Open Policy Agent.")


def run_opa_checks(opa_path, findings):
    """Run OPA policy checks on findings."""
    # opa_path and findings are reserved for future OPA integration
    opa_findings = []
    # Placeholder for OPA integration
    # This would evaluate Rego policies against the findings
    return opa_findings


def generate_sarif(findings, repo_path):
    """Generate SARIF format from findings."""
    # repo_path is reserved for future use in artifact location URIs
    runs = [
        {
            "tool": {"driver": {"name": "TavoAI Scanner", "version": "1.0"}},
            "results": [
                {
                    "ruleId": f.get("check_id", f.get("id", "unknown")),
                    "message": {
                        "text": f.get("extra", {}).get("message", f.get("message", ""))
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.get("path", "")},
                                "region": {
                                    "startLine": f.get("start", {}).get("line", 1),
                                    "endLine": f.get("end", {}).get("line", 1),
                                },
                            }
                        }
                    ],
                }
                for f in findings
                if f
            ],
        }
    ]
    return {"version": "2.1.0", "runs": runs}


def create_example_rules(rules_dir):
    """Create example OpenGrep rules for OWASP LLM Top 10."""
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / "llm_rules.yml"
    rule_content = """
rules:
  - id: prompt-injection
    message: Potential prompt injection without sanitization.
    languages: [python]
    patterns:
      - pattern: openai.ChatCompletion.create(..., $INPUT)
        where: not exists-parent prompt.format($INPUT, ...)
    severity: WARNING
  - id: model-theft
    message: Unencrypted model save detected.
    languages: [python]
    patterns:
      - pattern: torch.save($MODEL, ...)
        where: not exists-parent encrypt(...)
    severity: ERROR
  - id: insecure-api-key
    message: Hardcoded API key detected.
    languages: [python]
    patterns:
      - pattern: $KEY = "$VALUE"
        where:
          - $VALUE matches "tavo-sk-.*"
          - not $KEY matches "(?i)test|example|dummy"
    severity: ERROR
"""
    rule_file.write_text(rule_content)
    click.echo(f"Created example rules in {rule_file}")


@cli.group()
def rules():
    """Commands for managing Tavo Scanner rules."""
    pass


@rules.command("list")
def list_rules():
    """List all available rule categories."""
    try:
        from tavo_cli.rules import RuleManager, RuleManagerConfig

        config = RuleManagerConfig(
            cache_dir=Path.home() / TAVO_CONFIG_DIR / RULES_CACHE_DIR
        )
        manager = RuleManager(config)

        available_rules = manager.list_available_rules()

        click.echo("Available rule categories:")
        for rule_type, categories in available_rules.items():
            click.echo(f"\n{rule_type.upper()}:")
            for category in categories:
                click.echo(f"  - {category}")

    except ImportError as e:
        click.echo(f"Rule management not available: {e}", err=True)


@rules.command("export")
@click.argument("rule_type", type=click.Choice(["tavo-scanner", "opa"]))
@click.argument("category")
@click.argument("output_path", type=click.Path())
def export_rules(rule_type, category, output_path):
    """Export rules to a file for use with Tavo Scanner or OPA."""
    try:
        from tavo_cli.rules import RuleManager, RuleManagerConfig

        config = RuleManagerConfig(
            cache_dir=Path.home() / TAVO_CONFIG_DIR / RULES_CACHE_DIR
        )
        manager = RuleManager(config)

        output_file = Path(output_path)
        manager.export_rules_to_file(rule_type, category, output_file)

        click.echo(f"Exported {rule_type} {category} rules to {output_path}")

    except ImportError as e:
        click.echo(f"Rule management not available: {e}", err=True)
    except Exception as e:
        click.echo(f"Error exporting rules: {e}", err=True)


@rules.command("refresh")
def refresh_rules():
    """Refresh rules from remote API endpoints."""
    try:
        from tavo_cli.rules import RuleManager, RuleManagerConfig

        config = RuleManagerConfig(
            cache_dir=Path.home() / TAVO_CONFIG_DIR / RULES_CACHE_DIR
        )
        manager = RuleManager(config)

        if manager.refresh_rules_from_api():
            click.echo("Rules refreshed successfully from API")
        else:
            click.echo("Rule refresh not yet implemented or failed")

    except ImportError as e:
        click.echo(f"Rule management not available: {e}", err=True)


def generate_sarif_report(findings: list) -> dict:
    """Generate SARIF report from findings."""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Tavo CLI",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/TavoAI/tavo-cli",
                    }
                },
                "results": [],
            }
        ],
    }

    for finding in findings:
        result = {
            "ruleId": finding.get("id", "unknown"),
            "level": finding.get("severity", "warning").lower(),
            "message": {"text": finding.get("message", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get("path", "")},
                        "region": {"startLine": finding.get("line", 1)},
                    }
                }
            ],
        }
        sarif["runs"][0]["results"].append(result)

    return sarif


@cli.group()
def config():
    """Commands for configuring Tavo CLI."""
    pass


@cli.group()
def auth():
    """Commands for authentication and account management."""
    pass


@auth.command()
def login():
    """Authenticate with Tavo using device code flow."""
    user = get_current_user()
    if user:
        click.echo(f"✅ Already authenticated as {user['email']}")
        return

    click.echo("🔐 Starting device code authentication...")

    try:
        # Step 1: Get device code
        response = make_api_request("POST", "/api/v1/device/code")
        if response.status_code != 200:
            click.echo(f"❌ Failed to get device code: {response.text}")
            return

        device_data = response.json()
        device_code = device_data["device_code"]
        user_code = device_data["user_code"]
        verification_uri = device_data["verification_uri"]

        click.echo(f"📱 Go to: {verification_uri}")
        click.echo(f"🔢 Enter code: {user_code}")
        click.echo("⏳ Waiting for approval...")

        # Step 2: Poll for token
        max_attempts = 60  # 5 minutes max
        attempt = 0

        while attempt < max_attempts:
            time.sleep(5)  # Wait 5 seconds between polls
            attempt += 1

            token_response = requests.post(
                f"{get_base_url()}/api/v1/device/token",
                data={
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )

            if token_response.status_code == 200:
                token_data = token_response.json()

                # Get user info
                user_response = make_api_request(
                    "GET",
                    "/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {token_data['access_token']}"},
                )
                if user_response.status_code == 200:
                    user_info = user_response.json()

                    # Save authentication
                    save_auth_tokens(
                        token_data["access_token"],
                        token_data["refresh_token"],
                        user_info,
                    )

                    click.echo(f"✅ Successfully authenticated as {user_info['email']}")
                    return
                else:
                    click.echo(f"❌ Failed to get user info: {user_response.text}")
                    return

            elif token_response.status_code == 400:
                error_data = token_response.json()
                error = error_data.get("error")

                if error == "authorization_pending":
                    click.echo(f"⏳ Still waiting... ({attempt}/{max_attempts})")
                    continue
                elif error == "expired_token":
                    click.echo("❌ Device code expired. Please try again.")
                    return
                elif error == "access_denied":
                    click.echo("❌ Access denied by user.")
                    return
                else:
                    click.echo(f"❌ Authentication failed: {error}")
                    return
            else:
                click.echo(f"❌ Unexpected response: {token_response.status_code}")
                return

        click.echo("❌ Authentication timed out. Please try again.")

    except requests.RequestException as e:
        click.echo(f"❌ Network error: {e}")
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}")


@auth.command()
def logout():
    """Clear authentication tokens."""
    if not is_authenticated():
        click.echo("ℹ️  Not currently authenticated")
        return

    clear_auth_tokens()
    # Also clear session token and API key
    config = load_config()
    config.pop("session_token", None)
    config.pop("api_key", None)
    save_config(config)
    click.echo("✅ Successfully logged out")


@auth.command()
def whoami():
    """Show current authenticated user."""
    user = get_current_user()
    if user:
        click.echo(f"👤 Authenticated as: {user['email']}")
        click.echo(f"📧 Email: {user['email']}")
        if user.get("first_name") or user.get("last_name"):
            name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            click.echo(f"📝 Name: {name}")
    else:
        click.echo("❌ Not authenticated")
        click.echo("   Run 'tavo auth login' to authenticate")


@config.command("set-api-key")
def set_api_key():
    """Set API key for Tavo API access (alternative to JWT auth)."""
    user = get_current_user()
    if user:
        click.echo(f"⚠️  Already authenticated as {user['email']}")
        click.echo("   API key will be used as fallback authentication")

    current_key = get_api_key()
    if current_key:
        masked_key = current_key[:8] + "..." if len(current_key) > 8 else current_key
        click.echo(f"Current API key: {masked_key}")

    api_key = click.prompt("Enter your Tavo API key", hide_input=True)
    if not api_key:
        click.echo("❌ API key cannot be empty")
        return

    config = load_config()
    config["api_key"] = api_key
    save_config(config)
    click.echo("✅ API key configured successfully")
    click.echo("   Note: JWT authentication (tavo auth login) is preferred")


@config.command("get-api-key")
def get_api_key_command():
    """Display current API key (masked)."""
    api_key = get_api_key()
    if api_key:
        masked_key = api_key[:8] + "..." if len(api_key) > 8 else api_key
        click.echo(f"API key: {masked_key}")
    else:
        click.echo("No API key configured")
        click.echo("Run 'tavo config set-api-key' to configure")


@config.command("clear-api-key")
def clear_api_key():
    """Remove API key configuration."""
    config = load_config()
    if "api_key" in config:
        del config["api_key"]
        save_config(config)
        click.echo("✅ API key cleared")
    else:
        click.echo("No API key configured")


@config.command("set-session-token")
def set_session_token():
    """Set session token for Tavo API access (web-based auth)."""
    user = get_current_user()
    if user:
        click.echo(f"⚠️  Already authenticated as {user['email']}")
        click.echo("   Session token will be used as fallback authentication")

    current_token = get_session_token()
    if current_token:
        masked_token = (
            current_token[:8] + "..." if len(current_token) > 8 else current_token
        )
        click.echo(f"Current session token: {masked_token}")

    session_token = click.prompt("Enter your Tavo session token", hide_input=True)
    if not session_token:
        click.echo("❌ Session token cannot be empty")
        return

    config = load_config()
    config["session_token"] = session_token
    save_config(config)
    click.echo("✅ Session token configured successfully")
    click.echo("   Note: JWT authentication (tavo auth login) is preferred")


@config.command("get-session-token")
def get_session_token_command():
    """Display current session token (masked)."""
    session_token = get_session_token()
    if session_token:
        masked_token = (
            session_token[:8] + "..." if len(session_token) > 8 else session_token
        )
        click.echo(f"Session token: {masked_token}")
    else:
        click.echo("No session token configured")
        click.echo("Run 'tavo config set-session-token' to configure")


@config.command("clear-session-token")
def clear_session_token():
    """Remove session token configuration."""
    config = load_config()
    if "session_token" in config:
        del config["session_token"]
        save_config(config)
        click.echo("✅ Session token cleared")
    else:
        click.echo("No session token configured")


@cli.group()
def registry():
    """Manage plugins from the TavoAI marketplace."""
    pass


@registry.command("browse")
@click.option(
    "--plugin-type",
    help="Filter by plugin type (static_analysis, dynamic_testing, proxy_filtering, log_analysis)",
)
@click.option("--category", help="Filter by category")
@click.option("--pricing-tier", help="Filter by pricing tier (free, paid, enterprise)")
@click.option("--search", help="Search plugins by name or description")
@click.option("--page", default=1, type=int, help="Page number")
@click.option("--per-page", default=20, type=int, help="Results per page")
def browse_marketplace(plugin_type, category, pricing_tier, search, page, per_page):
    """Browse available plugins in the marketplace."""
    if not has_api_access():
        click.echo("❌ Authentication required to browse marketplace", err=True)
        click.echo("   Run 'tavo auth login' to authenticate")
        return

    try:
        response = make_api_request(
            "GET",
            "/api/v1/plugins/marketplace",
            params={
                "plugin_type": plugin_type,
                "category": category,
                "pricing_tier": pricing_tier,
                "search": search,
                "page": page,
                "per_page": per_page,
            },
        )
        response.raise_for_status()
        data = response.json()

        plugins = data.get("items", [])
        total = data.get("total", 0)

        if not plugins:
            click.echo("No plugins found matching your criteria.")
            return

        click.echo(
            f"\n🔌 Available Plugins (Page {page}, {len(plugins)} of {total} total)\n"
        )

        for plugin in plugins:
            click.echo(f"  📦 {plugin['name']} (v{plugin['version']})")
            click.echo(f"     ID: {plugin['id']}")
            click.echo(f"     Type: {plugin['plugin_type']}")
            click.echo(f"     Pricing: {plugin['pricing_tier']}")
            if plugin.get("description"):
                desc = (
                    plugin["description"][:80] + "..."
                    if len(plugin["description"]) > 80
                    else plugin["description"]
                )
                click.echo(f"     {desc}")
            click.echo(f"     Downloads: {plugin.get('download_count', 0)}")
            click.echo()

        if page * per_page < total:
            click.echo(f"💡 Use --page {page + 1} to see more results")

    except requests.exceptions.RequestException as e:
        click.echo(f"❌ Failed to browse marketplace: {e}", err=True)


@registry.command("install")
@click.argument("plugin_id")
def install_plugin(plugin_id):
    """Install a plugin from the marketplace."""
    if not has_api_access():
        click.echo("❌ Authentication required to install plugins", err=True)
        click.echo("   Run 'tavo auth login' to authenticate")
        return

    try:
        click.echo(f"📥 Installing plugin {plugin_id}...")

        # Call installation endpoint
        response = make_api_request(
            "POST",
            f"/api/v1/plugins/{plugin_id}/install",
        )
        response.raise_for_status()

        click.echo("✅ Plugin installed successfully")
        click.echo(f"   Use it in scans with: --static-plugins {plugin_id}")
        click.echo("   Or: --dynamic-plugins {plugin_id}")

    except requests.exceptions.RequestException as e:
        click.echo(f"❌ Failed to install plugin: {e}", err=True)


@registry.command("list")
def list_installed():
    """List locally installed plugins."""
    if not has_api_access():
        click.echo("❌ Authentication required to list plugins", err=True)
        click.echo("   Run 'tavo auth login' to authenticate")
        return

    try:
        response = make_api_request("GET", "/api/v1/plugins/installed")
        response.raise_for_status()
        installations = response.json()

        if not installations:
            click.echo("No plugins installed.")
            click.echo("Browse available plugins with: tavo registry browse")
            return

        click.echo(f"\n🔌 Installed Plugins ({len(installations)} total)\n")

        for install in installations:
            plugin = install.get("plugin", {})
            click.echo(
                f"  📦 {plugin.get('name', 'Unknown')} (v{plugin.get('version', '?')})"
            )
            click.echo(f"     ID: {install['plugin_id']}")
            click.echo(f"     Type: {plugin.get('plugin_type', 'unknown')}")
            click.echo(f"     Installed: {install['installed_at'][:10]}")
            click.echo()

    except requests.exceptions.RequestException as e:
        click.echo(f"❌ Failed to list plugins: {e}", err=True)


@registry.command("info")
@click.argument("plugin_id")
def plugin_info(plugin_id):
    """Get detailed information about a plugin."""
    if not has_api_access():
        click.echo("❌ Authentication required", err=True)
        click.echo("   Run 'tavo auth login' to authenticate")
        return

    try:
        response = make_api_request("GET", f"/api/v1/plugins/{plugin_id}")
        response.raise_for_status()
        plugin = response.json()

        click.echo(f"\n📦 {plugin['name']}")
        click.echo(f"{'=' * (len(plugin['name']) + 3)}")
        click.echo(f"ID: {plugin['id']}")
        click.echo(f"Version: {plugin['version']}")
        click.echo(f"Type: {plugin['plugin_type']}")
        click.echo(f"Author: {plugin.get('author', 'Unknown')}")
        click.echo(f"License: {plugin.get('license', 'Unknown')}")
        click.echo(f"Pricing: {plugin['pricing_tier']}")
        click.echo(f"Downloads: {plugin.get('download_count', 0)}")
        click.echo(f"Official: {'Yes' if plugin.get('is_official') else 'No'}")
        click.echo(f"Approved: {'Yes' if plugin.get('is_approved') else 'No'}")

        if plugin.get("description"):
            click.echo(f"\nDescription:\n{plugin['description']}")

        if plugin.get("compatible_scanner_version"):
            click.echo(
                f"\nCompatible Scanner Version: {plugin['compatible_scanner_version']}"
            )

        if plugin.get("dependencies"):
            click.echo(f"\nDependencies:")
            deps = plugin["dependencies"]
            if deps.get("python"):
                click.echo(f"  Python: {deps['python']}")
            if deps.get("packages"):
                click.echo(f"  Packages:")
                for pkg in deps["packages"]:
                    click.echo(f"    - {pkg}")

        click.echo(f"\nInstall with: tavo registry install {plugin_id}")

    except requests.exceptions.RequestException as e:
        click.echo(f"❌ Failed to get plugin info: {e}", err=True)


@registry.command("uninstall")
@click.argument("plugin_id")
@click.confirmation_option(prompt="Are you sure you want to uninstall this plugin?")
def uninstall_plugin(plugin_id):
    """Uninstall a plugin."""
    # For now, this just removes the installation record
    # The actual plugin files would need to be removed from the local cache
    click.echo("⚠️  Plugin uninstallation not yet implemented")
    click.echo("   This feature will be available in a future release")


if __name__ == "__main__":
    cli()
