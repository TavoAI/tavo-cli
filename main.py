import click
import subprocess
import json
import os
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
    api_key = os.getenv('TAVO_API_KEY')
    if api_key:
        return api_key

    # Check config file
    config = load_config()
    return config.get('api_key')


def has_api_access() -> bool:
    """Check if user has API access configured."""
    return get_api_key() is not None


@click.group()
def cli():
    """Tavo.AI CLI for LLM security scanning."""
    pass


@cli.command()
@click.argument('repo_path', type=click.Path(exists=True))
@click.option('--rules-dir', default='.opengrep',
              help='Directory containing OpenGrep rules.')
@click.option('--opa-policy', default='opa/policies',
              help='Directory for OPA Rego policies.')
@click.option('--output', default='scan_report.sarif',
              help='Output SARIF report file.')
@click.option('--ai-batch', is_flag=True,
              help='Enable batch AI polling for ambiguous issues.')
@click.option('--api', is_flag=True,
              help='Use Tavo API for enhanced scanning and reporting.')
def scan(repo_path, rules_dir, opa_policy, output, ai_batch, api):
    """Run security scans on a repository."""
    repo_path = Path(repo_path)

    # Check API access
    if api and not has_api_access():
        click.echo("❌ API access required but no API key found.", err=True)
        click.echo("   Run 'tavo config set-api-key' to configure.", err=True)
        return

    if not api and not has_api_access():
        click.echo("⚠️  Running in local mode without API key.")
        click.echo("   Local scanning provides basic analysis only.")
        click.echo("   For enhanced AI analysis and reporting,")
        click.echo("   configure an API key:")
        click.echo("   Run 'tavo config set-api-key' to enable full features.")
        click.echo()

    if api:
        # API-based scanning
        return scan_with_api(repo_path, output)
    else:
        # Local scanning with warnings
        return scan_local(repo_path, rules_dir, opa_policy, output, ai_batch)


def scan_with_api(repo_path: Path, output: str) -> None:
    """Scan repository using Tavo API."""
    try:
        # Import here to avoid dependency issues
        from tavo import TavoClient
    except ImportError:
        click.echo("❌ Tavo Python SDK not found.", err=True)
        click.echo("   Install with: pip install tavo-python-sdk", err=True)
        return

    api_key = get_api_key()
    if not api_key:
        click.echo("❌ No API key configured.", err=True)
        return

    async def run_scan():
        async with TavoClient(api_key=api_key) as client:
            click.echo(f"🔍 Scanning {repo_path} via Tavo API...")

            # Create scan request
            scan_request = {
                "repositoryUrl": f"file://{repo_path.absolute()}",
                "scanType": "full"
            }

            # Start scan
            scan_result = await client.scans.create(scan_request)
            click.echo(f"✅ Scan created: {scan_result.id}")

            # Wait for completion (simplified)
            click.echo("⏳ Processing... (this may take a few minutes)")

            # Get results
            results = await client.scans.results(scan_result.id)
            click.echo(f"🎯 Found {len(results.get('vulnerabilities', []))}")
            click.echo("   vulnerabilities")

            # Generate report
            report_request = {
                "scanId": scan_result.id,
                "reportType": "sarif",
                "format": "sarif"
            }

            report = await client.reports.create(report_request)
            click.echo(f"📄 Report generated: {report.id}")

            # Save to file
            output_path = Path(output)
            if report.content:
                output_path.write_text(json.dumps(report.content, indent=2))
                click.echo(f"💾 Report saved to {output}")
            else:
                click.echo("⚠️  Report content not available yet")

    # Run async function
    import asyncio
    asyncio.run(run_scan())


def scan_local(repo_path: Path, rules_dir: str, opa_policy: str,
                output: str, ai_batch: bool) -> None:
    """Run local scanning with OpenGrep and OPA."""
    rules_path = repo_path / rules_dir
    opa_path = repo_path / opa_policy

    # Ensure rules directory exists with example rules
    if not rules_path.exists():
        click.echo(f"Rules directory {rules_path} not found. "
                   "Creating with example rules.")
        create_example_rules(rules_path)

    # Run OpenGrep - try multiple possible locations
    opengrep_cmd = None

    # Try built binary first
    built_path = (Path(__file__).parent /
                  "../opengrep/_build/install/default/bin/opengrep-core")
    if built_path.exists():
        opengrep_cmd = str(built_path)
    else:
        # Try symlink
        symlink_path = Path(__file__).parent / "../opengrep/bin/opengrep"
        if symlink_path.exists():
            opengrep_cmd = str(symlink_path)
        else:
            # Try system PATH
            import shutil
            if shutil.which("opengrep"):
                opengrep_cmd = "opengrep"
            else:
                click.echo("Error: OpenGrep not found.")
                click.echo("Build it with: cd opengrep && make")
                click.echo("Or install: curl -fsSL")
                click.echo("  https://raw.githubusercontent.com/opengrep/")
                click.echo("  opengrep/main/install.sh | bash")
                return

    cmd = [opengrep_cmd, 'scan', '--config', str(rules_path),
           '--json', str(repo_path)]
    click.echo(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=300)
        findings = []

        # Try to extract JSON from stdout
        # (it might be mixed with formatted output)
        stdout_output = result.stdout.strip()
        json_start = stdout_output.find('{')
        json_end = stdout_output.rfind('}') + 1

        if json_start != -1 and json_end > json_start:
            json_content = stdout_output[json_start:json_end]
            try:
                scan_results = json.loads(json_content)
                findings = scan_results.get('results', [])
                click.echo("OpenGrep scan completed. "
                           f"Found {len(findings)} issues.")
            except json.JSONDecodeError:
                click.echo(f"Failed to parse JSON content: {json_content}")
                findings = []
        else:
            click.echo(f"No JSON found in output. stdout: {stdout_output}")
            findings = []

        if result.returncode != 0 and not findings:
            click.echo("OpenGrep error "
                       f"(exit code {result.returncode}): {result.stderr}")
            if result.stdout:
                click.echo(f"OpenGrep stdout: {result.stdout}")
        else:
            click.echo("OpenGrep error "
                       f"(exit code {result.returncode}): {result.stderr}")
            if result.stdout:
                click.echo(f"OpenGrep stdout: {result.stdout}")

        # Save results to SARIF file
        sarif_output = generate_sarif_report(findings)
        output_path = Path(output)
        output_path.write_text(
            json.dumps(sarif_output, indent=2), encoding='utf-8'
        )
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
    rules_path = Path(repo_path) / rules_dir
    opa_path = Path(repo_path) / opa_policy

    # Ensure rules directory exists with example rules
    if not rules_path.exists():
        click.echo(f"Rules directory {rules_path} not found. "
                   "Creating with example rules.")
        create_example_rules(rules_path)

    # Run OpenGrep - try multiple possible locations
    opengrep_cmd = None

    # Try built binary first
    built_path = (Path(__file__).parent /
                  "../opengrep/_build/install/default/bin/opengrep-core")
    if built_path.exists():
        opengrep_cmd = str(built_path)
    else:
        # Try symlink
        symlink_path = Path(__file__).parent / "../opengrep/bin/opengrep"
        if symlink_path.exists():
            opengrep_cmd = str(symlink_path)
        else:
            # Try system PATH
            import shutil
            if shutil.which("opengrep"):
                opengrep_cmd = "opengrep"
            else:
                click.echo("Error: OpenGrep not found.")
                click.echo("Build it with: cd opengrep && make")
                click.echo("Or install: curl -fsSL")
                click.echo("  https://raw.githubusercontent.com/opengrep/")
                click.echo("  opengrep/main/install.sh | bash")
                return

    cmd = [opengrep_cmd, 'scan', '--config', str(rules_path),
           '--json', repo_path]
    click.echo(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=300)
        findings = []

        # Try to extract JSON from stdout
        # (it might be mixed with formatted output)
        stdout_output = result.stdout.strip()
        json_start = stdout_output.find('{')
        json_end = stdout_output.rfind('}') + 1

        if json_start != -1 and json_end > json_start:
            json_content = stdout_output[json_start:json_end]
            try:
                scan_results = json.loads(json_content)
                findings = scan_results.get('results', [])
                click.echo("OpenGrep scan completed. "
                           f"Found {len(findings)} issues.")
            except json.JSONDecodeError:
                click.echo(f"Failed to parse JSON content: {json_content}")
                findings = []
        else:
            click.echo(f"No JSON found in output. stdout: {stdout_output}")
            findings = []

        if result.returncode != 0 and not findings:
            click.echo("OpenGrep error "
                       f"(exit code {result.returncode}): {result.stderr}")
            if result.stdout:
                click.echo(f"OpenGrep stdout: {result.stdout}")
        else:
            click.echo("OpenGrep error "
                       f"(exit code {result.returncode}): {result.stderr}")
            if result.stderr:
                click.echo(f"OpenGrep stderr: {result.stderr}")

    except subprocess.TimeoutExpired:
        click.echo("OpenGrep scan timed out after 5 minutes")
        findings = []
    except FileNotFoundError:
        click.echo("OpenGrep binary not found.")
        click.echo("Please ensure OpenGrep is built.")
        return

    # Run OPA for additional policy checks
    if opa_path.exists():
        click.echo("Running OPA policy checks...")
        opa_findings = run_opa_checks(opa_path, findings)
        findings.extend(opa_findings)

    # Generate SARIF report
    sarif_report = generate_sarif(findings, repo_path)
    with open(output, 'w') as f:
        json.dump(sarif_report, f, indent=2)
    click.echo(f"Scan complete. SARIF report saved to {output}.")

    if ai_batch and findings:
        click.echo("Escalating ambiguous findings to AI...")
        # Implement batch logic here


@cli.command()
@click.argument('repo_path', type=click.Path(exists=True))
@click.option('--opa-policy', default='opa/policies',
              help='Directory for OPA Rego policies.')
def validate(repo_path, opa_policy):
    """Run OPA validation for local policy checks (e.g., RAG compliance)."""
    opa_path = Path(repo_path) / opa_policy
    if not opa_path.exists():
        click.echo(f"OPA policies directory {opa_path} not found.")
        return

    # Placeholder: Run OPA eval (requires OPA installed)
    cmd = ['opa', 'eval', '--data', str(opa_path),
           '--input', '{"test": "data"}', 'data.policy.allow']
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
    runs = [{
        "tool": {"driver": {"name": "TavoAI Scanner", "version": "1.0"}},
        "results": [
            {
                "ruleId": f.get('check_id', f.get('id', 'unknown')),
                "message": {
                    "text": f.get('extra', {}).get('message',
                                                   f.get('message', ''))
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get('path', '')},
                        "region": {
                            "startLine": f.get('start', {}).get('line', 1),
                            "endLine": f.get('end', {}).get('line', 1)
                        }
                    }
                }]
            } for f in findings if f
        ]
    }]
    return {"version": "2.1.0", "runs": runs}


def create_example_rules(rules_dir):
    """Create example OpenGrep rules for OWASP LLM Top 10."""
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / 'llm_rules.yml'
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
          - $VALUE matches "sk-.*"
          - not $KEY matches "(?i)test|example|dummy"
    severity: ERROR
"""
    rule_file.write_text(rule_content)
    click.echo(f"Created example rules in {rule_file}")


@cli.group()
def rules():
    """Commands for managing OpenGrep and OPA rules."""
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
@click.argument('rule_type', type=click.Choice(['opengrep', 'opa']))
@click.argument('category')
@click.argument('output_path', type=click.Path())
def export_rules(rule_type, category, output_path):
    """Export rules to a file for use with OpenGrep or OPA."""
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
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Tavo CLI",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/TavoAI/tavo-cli"
                }
            },
            "results": []
        }]
    }

    for finding in findings:
        result = {
            "ruleId": finding.get("id", "unknown"),
            "level": finding.get("severity", "warning").lower(),
            "message": {
                "text": finding.get("message", "")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.get("path", "")
                    },
                    "region": {
                        "startLine": finding.get("line", 1)
                    }
                }
            }]
        }
        sarif["runs"][0]["results"].append(result)

    return sarif


@cli.group()
def config():
    """Commands for configuring Tavo CLI."""
    pass


@config.command("set-api-key")
def set_api_key():
    """Set API key for Tavo API access."""
    current_key = get_api_key()
    if current_key:
        masked_key = current_key[:8] + "..." if len(current_key) > 8 else current_key
        click.echo(f"Current API key: {masked_key}")

    api_key = click.prompt("Enter your Tavo API key", hide_input=True)
    if not api_key:
        click.echo("❌ API key cannot be empty")
        return

    config = load_config()
    config['api_key'] = api_key
    save_config(config)
    click.echo("✅ API key configured successfully")
    click.echo("   You can now use 'tavo scan --api' for enhanced scanning")


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
    if 'api_key' in config:
        del config['api_key']
        save_config(config)
        click.echo("✅ API key cleared")
    else:
        click.echo("No API key configured")


if __name__ == '__main__':
    cli()
