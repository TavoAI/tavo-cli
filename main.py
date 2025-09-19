import click
import subprocess
import json
from pathlib import Path


# Constants
TAVO_CONFIG_DIR = ".tavo"
RULES_CACHE_DIR = "rules"


@click.group()
def cli():
    """Tavo.AI CLI for heuristic LLM security scans using OpenGrep and OPA."""
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
def scan(repo_path, rules_dir, opa_policy, output, ai_batch):
    """Run heuristic scans on a repo using OpenGrep and OPA Rego."""
    rules_path = Path(repo_path) / rules_dir
    opa_path = Path(repo_path) / opa_policy

    # Ensure rules directory exists with example rules
    if not rules_path.exists():
        click.echo(f"Rules directory {rules_path} not found. "
                   "Creating with example rules.")
        create_example_rules(rules_path)

    # Run OpenGrep
    opengrep_path = Path(__file__).parent / "../opengrep/bin/opengrep"
    if not opengrep_path.exists():
        # Try to find opengrep in PATH
        opengrep_cmd = "opengrep"
    else:
        opengrep_cmd = str(opengrep_path)

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
        click.echo("OpenGrep binary not found at "
                   f"{opengrep_path}. Please ensure OpenGrep is built.")
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


if __name__ == '__main__':
    cli()
