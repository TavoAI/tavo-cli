# CLI - Universal Security Tool Registry Commands

**Project**: TavoAI CLI  
**Initiative**: Universal Security Tool Registry  
**Status**: 📋 Planning Phase  
**Owner**: CLI Team  

---

## Overview

This document details the implementation tasks for adding Registry support to the TavoAI CLI tool. The CLI will provide command-line access to:

1. Registry marketplace browsing and search
2. Bundle installation and management
3. Local and cloud rule execution
4. Bundle creation and publishing
5. Usage tracking and cost monitoring

**Reference**: See `../architecting/REGISTRY_TODO.md` for complete architecture.

Try to utilize the tavo-sdk

---

## Phase 1: Registry Commands (Week 9-10 - 2 weeks)

### Task 1.1: Registry Command Group
**File**: `src/cli/commands/registry.py`

Create main registry command group:

```python
import click
from tavoai import RegistryClient
from .utils import get_api_key, format_table, print_success, print_error

@click.group()
def registry():
    """Manage TavoAI security rule bundles"""
    pass

@registry.command('list')
@click.option('--type', '-t', type=click.Choice(['code_rule', 'proxy_rule', 'zap_attack', 'all']), default='all', help='Filter by artifact type')
@click.option('--category', '-c', help='Filter by category')
@click.option('--pricing', '-p', type=click.Choice(['free', 'paid', 'enterprise', 'all']), default='all', help='Filter by pricing tier')
@click.option('--search', '-s', help='Search bundles by name or description')
@click.option('--limit', '-l', default=20, help='Number of results to show')
def list_bundles(type, category, pricing, search, limit):
    """List available bundles in the marketplace"""
    try:
        client = RegistryClient(api_key=get_api_key())
        
        filters = {}
        if type != 'all':
            filters['artifact_type'] = type
        if category:
            filters['category'] = category
        if pricing != 'all':
            filters['pricing_tier'] = pricing
        if search:
            filters['search'] = search
        
        filters['per_page'] = limit
        
        result = client.browse_marketplace(**filters)
        
        if not result['items']:
            print_error("No bundles found matching your criteria")
            return
        
        # Format as table
        data = []
        for bundle in result['items']:
            data.append([
                bundle['name'],
                bundle['version'],
                bundle['pricing_tier'],
                f"{bundle['rating']:.1f}★",
                bundle['download_count'],
            ])
        
        headers = ['Name', 'Version', 'Tier', 'Rating', 'Downloads']
        print(format_table(data, headers))
        
        if result['pages'] > 1:
            print(f"\nShowing {result['page']} of {result['pages']} pages")
        
    except Exception as e:
        print_error(f"Failed to list bundles: {e}")
        raise click.Abort()

@registry.command('search')
@click.argument('query')
@click.option('--limit', '-l', default=10, help='Number of results')
def search_bundles(query, limit):
    """Search for bundles by name, description, or tags"""
    try:
        client = RegistryClient(api_key=get_api_key())
        
        result = client.browse_marketplace(
            search=query,
            per_page=limit
        )
        
        if not result['items']:
            print_error(f"No bundles found for '{query}'")
            return
        
        for bundle in result['items']:
            print(f"\n{bundle['name']} ({bundle['version']})")
            print(f"  {bundle['description']}")
            print(f"  Rating: {bundle['rating']:.1f}★ | Downloads: {bundle['download_count']} | {bundle['pricing_tier']}")
            print(f"  Tags: {', '.join(bundle.get('tags', []))}")
        
    except Exception as e:
        print_error(f"Search failed: {e}")
        raise click.Abort()

@registry.command('info')
@click.argument('bundle_id')
def bundle_info(bundle_id):
    """Show detailed information about a bundle"""
    try:
        client = RegistryClient(api_key=get_api_key())
        bundle = client.get_bundle(bundle_id)
        
        print(f"\n{bundle['name']} (v{bundle['version']})")
        print("=" * 60)
        print(f"\nDescription: {bundle['description']}")
        print(f"Category: {bundle['category']}")
        print(f"Pricing: {bundle['pricing_tier']}")
        print(f"Rating: {bundle['rating']:.1f}★ ({bundle['reviews_count']} reviews)")
        print(f"Downloads: {bundle['download_count']}")
        print(f"Organization: {bundle['organization_id']}")
        print(f"Official: {'Yes' if bundle['is_official'] else 'No'}")
        
        print(f"\nArtifacts ({len(bundle['artifacts'])}):")
        for artifact in bundle['artifacts']:
            print(f"  - {artifact['name']} ({artifact['type']})")
        
        if bundle.get('changelog'):
            print(f"\nChangelog:")
            print(bundle['changelog'])
        
    except Exception as e:
        print_error(f"Failed to get bundle info: {e}")
        raise click.Abort()
```

**Dependencies**:
- Click for CLI framework
- tavo-sdk (Python SDK)
- Existing CLI utilities

**Testing**:
- Test each command with various options
- Test error handling (no API key, network errors)
- Test table formatting

**Acceptance Criteria**:
- [ ] All commands work correctly
- [ ] Proper error handling
- [ ] User-friendly output
- [ ] Handles pagination

---

### Task 1.2: Installation Commands
**File**: `src/cli/commands/registry.py` (continued)

Add installation commands:

```python
@registry.command('install')
@click.argument('bundle_id')
@click.option('--download-only', '-d', is_flag=True, help='Download without installing')
@click.option('--output', '-o', help='Output path for downloaded bundle')
def install_bundle(bundle_id, download_only, output):
    """Install a bundle from the marketplace"""
    try:
        client = RegistryClient(api_key=get_api_key())
        
        # Get bundle info
        bundle = client.get_bundle(bundle_id)
        
        if download_only:
            # Download bundle file
            output_path = output or f"{bundle['id']}-{bundle['version']}.tavoai-bundle"
            
            with click.progressbar(
                length=100,
                label=f"Downloading {bundle['name']}"
            ) as bar:
                client.download_bundle(bundle_id, output_path)
                bar.update(100)
            
            print_success(f"Downloaded to {output_path}")
        else:
            # Install bundle
            with click.progressbar(
                length=100,
                label=f"Installing {bundle['name']}"
            ) as bar:
                installation = client.install_bundle(bundle_id)
                bar.update(100)
            
            print_success(f"Installed {bundle['name']} v{bundle['version']}")
            
            # Also download for local use
            local_bundle_manager = LocalBundleManager()
            local_bundle_manager.install(bundle_id)
        
    except Exception as e:
        print_error(f"Installation failed: {e}")
        raise click.Abort()

@registry.command('uninstall')
@click.argument('bundle_id')
@click.option('--force', '-f', is_flag=True, help='Uninstall without confirmation')
def uninstall_bundle(bundle_id, force):
    """Uninstall a bundle"""
    try:
        local_bundle_manager = LocalBundleManager()
        bundle = local_bundle_manager.get_bundle(bundle_id)
        
        if not bundle:
            print_error(f"Bundle '{bundle_id}' not found locally")
            return
        
        if not force:
            if not click.confirm(f"Uninstall {bundle['name']}?"):
                return
        
        local_bundle_manager.uninstall(bundle_id)
        print_success(f"Uninstalled {bundle['name']}")
        
    except Exception as e:
        print_error(f"Uninstall failed: {e}")
        raise click.Abort()

@registry.command('installed')
def list_installed():
    """List installed bundles"""
    try:
        local_bundle_manager = LocalBundleManager()
        bundles = local_bundle_manager.list_installed()
        
        if not bundles:
            print_error("No bundles installed")
            return
        
        data = []
        for bundle in bundles:
            data.append([
                bundle['name'],
                bundle['version'],
                bundle['installed_at'],
            ])
        
        headers = ['Name', 'Version', 'Installed']
        print(format_table(data, headers))
        
    except Exception as e:
        print_error(f"Failed to list installed bundles: {e}")
        raise click.Abort()

@registry.command('update')
@click.argument('bundle_id', required=False)
@click.option('--all', '-a', is_flag=True, help='Update all bundles')
def update_bundles(bundle_id, all):
    """Update installed bundles"""
    try:
        local_bundle_manager = LocalBundleManager()
        
        if all:
            updates = local_bundle_manager.check_updates()
            
            if not updates:
                print_success("All bundles are up to date")
                return
            
            print(f"Found {len(updates)} updates:")
            for update in updates:
                print(f"  {update['name']}: {update['current_version']} → {update['latest_version']}")
            
            if click.confirm("Update all?"):
                client = RegistryClient(api_key=get_api_key())
                for update in updates:
                    client.install_bundle(update['id'])
                    print_success(f"Updated {update['name']}")
        
        elif bundle_id:
            # Update specific bundle
            client = RegistryClient(api_key=get_api_key())
            bundle = client.get_bundle(bundle_id)
            
            local_bundle = local_bundle_manager.get_bundle(bundle_id)
            if not local_bundle:
                print_error(f"Bundle '{bundle_id}' not installed")
                return
            
            if bundle['version'] == local_bundle['version']:
                print_success(f"{bundle['name']} is already up to date")
                return
            
            client.install_bundle(bundle_id)
            print_success(f"Updated {bundle['name']} to v{bundle['version']}")
        
        else:
            print_error("Specify bundle ID or use --all")
            raise click.Abort()
        
    except Exception as e:
        print_error(f"Update failed: {e}")
        raise click.Abort()
```

**Dependencies**:
- Task 1.1
- Local bundle manager (SDK)

**Testing**:
- Test bundle installation
- Test download-only mode
- Test uninstallation
- Test updates

**Acceptance Criteria**:
- [ ] Installation works
- [ ] Download creates .tavoai-bundle file
- [ ] Uninstall removes bundle
- [ ] Update checks work
- [ ] Progress indicators shown

---

### Task 1.3: Execution Commands
**File**: `src/cli/commands/registry.py` (continued)

Add rule execution commands:

```python
@registry.command('execute')
@click.argument('rule_id')
@click.argument('target', type=click.Path(exists=True))
@click.option('--mode', '-m', type=click.Choice(['cloud', 'local']), default='cloud', help='Execution mode')
@click.option('--output', '-o', type=click.Choice(['text', 'json', 'sarif']), default='text', help='Output format')
@click.option('--save', '-s', type=click.Path(), help='Save results to file')
def execute_rule(rule_id, target, mode, output, save):
    """Execute a rule against code"""
    try:
        client = RegistryClient(api_key=get_api_key())
        
        # Read target file
        with open(target, 'r') as f:
            code = f.read()
        
        # Detect language
        language = detect_language(target)
        
        # Execute rule
        with click.progressbar(
            length=100,
            label=f"Executing rule"
        ) as bar:
            result = client.execute_code_rule(
                rule_id=rule_id,
                code=code,
                language=language,
                file_path=target,
                execution_mode=mode
            )
            bar.update(100)
        
        # Format output
        if output == 'text':
            print_text_results(result)
        elif output == 'json':
            print(json.dumps(result, indent=2))
        elif output == 'sarif':
            print_sarif_results(result)
        
        # Save if requested
        if save:
            with open(save, 'w') as f:
                json.dump(result, f, indent=2)
            print_success(f"Results saved to {save}")
        
    except Exception as e:
        print_error(f"Execution failed: {e}")
        raise click.Abort()

def print_text_results(result):
    """Print results in text format"""
    print("\n" + "=" * 60)
    print("HEURISTIC RESULTS")
    print("=" * 60)
    
    if result.get('heuristics', {}).get('findings'):
        for finding in result['heuristics']['findings']:
            severity_color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue',
            }.get(finding['severity'], 'white')
            
            click.echo(
                click.style(f"\n[{finding['severity'].upper()}] ", fg=severity_color) +
                f"Line {finding['line']}: {finding['message']}"
            )
    else:
        print("\nNo heuristic findings")
    
    if result.get('aiAnalysis'):
        print("\n" + "=" * 60)
        print("AI ANALYSIS")
        print("=" * 60)
        
        ai = result['aiAnalysis']
        severity_color = {
            'critical': 'red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
        }.get(ai['severity'], 'white')
        
        click.echo(
            click.style(f"\n[{ai['severity'].upper()}] ", fg=severity_color) +
            f"Confidence: {ai['confidence']:.0%}"
        )
        print(f"\n{ai['description']}")
        print(f"\nRemediation: {ai['remediation']}")
        print(f"\nOWASP Mapping: {', '.join(ai['owasp_mapping'])}")
    
    print("\n" + "=" * 60)
    print("METRICS")
    print("=" * 60)
    print(f"\nExecution time: {result['executionTimeMs']}ms")
    if result.get('aiAnalysis'):
        print(f"Tokens used: {result['aiAnalysis']['tokensUsed']}")
        print(f"Cost: ${result['aiAnalysis']['costUsd']:.4f}")

@registry.command('scan')
@click.argument('bundle_id')
@click.argument('target', type=click.Path(exists=True))
@click.option('--recursive', '-r', is_flag=True, help='Scan directory recursively')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def scan_with_bundle(bundle_id, target, recursive, output):
    """Scan code with all rules in a bundle"""
    try:
        local_bundle_manager = LocalBundleManager()
        bundle = local_bundle_manager.get_bundle(bundle_id)
        
        if not bundle:
            print_error(f"Bundle '{bundle_id}' not installed. Run 'tavo registry install {bundle_id}' first.")
            return
        
        # Get all files to scan
        if os.path.isfile(target):
            files = [target]
        elif recursive:
            files = []
            for root, _, filenames in os.walk(target):
                for filename in filenames:
                    if is_code_file(filename):
                        files.append(os.path.join(root, filename))
        else:
            files = [f for f in os.listdir(target) if is_code_file(f)]
        
        print(f"Scanning {len(files)} files with {len(bundle['artifacts'])} rules...")
        
        client = RegistryClient(api_key=get_api_key())
        all_results = []
        
        with click.progressbar(length=len(files) * len(bundle['artifacts'])) as bar:
            for file_path in files:
                with open(file_path, 'r') as f:
                    code = f.read()
                
                language = detect_language(file_path)
                
                for artifact in bundle['artifacts']:
                    result = client.execute_code_rule(
                        rule_id=artifact['id'],
                        code=code,
                        language=language,
                        file_path=file_path
                    )
                    
                    if result.get('heuristics', {}).get('findings') or result.get('aiAnalysis'):
                        all_results.append({
                            'file': file_path,
                            'rule': artifact['name'],
                            'result': result
                        })
                    
                    bar.update(1)
        
        # Print summary
        print(f"\n\nFound {len(all_results)} issues across {len(files)} files")
        
        if output:
            with open(output, 'w') as f:
                json.dump(all_results, f, indent=2)
            print_success(f"Results saved to {output}")
        
    except Exception as e:
        print_error(f"Scan failed: {e}")
        raise click.Abort()
```

**Dependencies**:
- Task 1.1, 1.2
- Language detection utility

**Testing**:
- Test single file execution
- Test bundle scanning
- Test recursive scanning
- Test output formats

**Acceptance Criteria**:
- [ ] Executes rules correctly
- [ ] Supports multiple output formats
- [ ] Progress indicators work
- [ ] Batch scanning efficient

---

### Task 1.4: Publishing Commands
**File**: `src/cli/commands/registry.py` (continued)

Add bundle creation and publishing:

```python
@registry.command('create')
@click.option('--name', prompt=True, help='Bundle name')
@click.option('--description', prompt=True, help='Bundle description')
@click.option('--category', prompt=True, type=click.Choice(['security', 'compliance', 'performance', 'quality']), help='Bundle category')
@click.option('--pricing', prompt=True, type=click.Choice(['free', 'paid', 'enterprise']), help='Pricing tier')
@click.option('--rules', '-r', multiple=True, type=click.Path(exists=True), help='Rule YAML files to include')
def create_bundle(name, description, category, pricing, rules):
    """Create a new bundle from rule files"""
    try:
        if not rules:
            print_error("At least one rule file required. Use --rules option.")
            return
        
        # Parse all rule files
        artifacts = []
        for rule_file in rules:
            with open(rule_file, 'r') as f:
                rule_yaml = f.read()
                artifacts.append({'rule_yaml': rule_yaml})
        
        # Create bundle via API
        client = RegistryClient(api_key=get_api_key())
        
        bundle = client.create_bundle({
            'name': name,
            'description': description,
            'version': '1.0.0',
            'artifact_type': 'code_rule',
            'category': category,
            'pricing_tier': pricing,
            'artifacts': artifacts,
        })
        
        print_success(f"Created bundle '{name}' (ID: {bundle['id']})")
        print(f"\nTo publish: tavo registry publish {bundle['id']}")
        
    except Exception as e:
        print_error(f"Bundle creation failed: {e}")
        raise click.Abort()

@registry.command('publish')
@click.argument('bundle_id')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
def publish_bundle(bundle_id, force):
    """Publish a bundle to the marketplace"""
    try:
        client = RegistryClient(api_key=get_api_key())
        
        # Get bundle details
        bundle = client.get_bundle(bundle_id)
        
        print(f"\nPublishing: {bundle['name']}")
        print(f"Version: {bundle['version']}")
        print(f"Pricing: {bundle['pricing_tier']}")
        print(f"Artifacts: {len(bundle['artifacts'])}")
        
        if not force:
            if not click.confirm("\nPublish to marketplace?"):
                return
        
        # Publish
        published = client.publish_bundle(bundle_id)
        
        print_success(f"Published {bundle['name']} v{bundle['version']}")
        print(f"\nView at: https://marketplace.tavoai.com/bundles/{bundle_id}")
        
    except Exception as e:
        print_error(f"Publish failed: {e}")
        raise click.Abort()
```

**Dependencies**:
- Task 1.1-1.3

**Testing**:
- Test bundle creation
- Test publishing
- Test validation errors

**Acceptance Criteria**:
- [ ] Can create bundles
- [ ] Can publish to marketplace
- [ ] Validation works
- [ ] Clear success/error messages

---

### Task 1.5: Usage Tracking Commands
**File**: `src/cli/commands/registry.py` (continued)

Add usage tracking commands:

```python
@registry.command('usage')
@click.option('--period', '-p', type=click.Choice(['day', 'week', 'month', 'all']), default='month', help='Time period')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed breakdown')
def show_usage(period, detailed):
    """Show registry usage and costs"""
    try:
        from .utils import UsageTracker
        
        client = RegistryClient(api_key=get_api_key())
        tracker = UsageTracker(client)
        
        usage = tracker.get_current_usage(period)
        
        print(f"\nUsage Summary ({period})")
        print("=" * 60)
        print(f"Executions: {usage['executions']}")
        print(f"Tokens used: {usage['tokens_used']:,}")
        print(f"Cost: ${usage['cost_usd']:.2f}")
        print(f"Budget remaining: ${usage['budget_remaining']:.2f}")
        
        if detailed:
            breakdown = tracker.get_cost_breakdown()
            
            print(f"\nCost Breakdown by Model:")
            print("-" * 60)
            for model, cost in breakdown.items():
                print(f"  {model}: ${cost:.2f}")
        
    except Exception as e:
        print_error(f"Failed to get usage: {e}")
        raise click.Abort()

@registry.command('set-budget')
@click.argument('limit', type=float)
def set_budget(limit):
    """Set monthly budget limit (USD)"""
    try:
        from .utils import UsageTracker
        
        client = RegistryClient(api_key=get_api_key())
        tracker = UsageTracker(client)
        
        tracker.set_budget_limit(limit)
        print_success(f"Budget limit set to ${limit:.2f}/month")
        
    except Exception as e:
        print_error(f"Failed to set budget: {e}")
        raise click.Abort()
```

**Dependencies**:
- Task 1.3
- SDK usage tracker

**Testing**:
- Test usage display
- Test budget setting
- Test detailed breakdown

**Acceptance Criteria**:
- [ ] Shows current usage
- [ ] Shows cost breakdown
- [ ] Can set budget limits
- [ ] Clear formatting

---

## Utility Functions

### Task 2.1: Language Detection
**File**: `src/cli/utils/language_detector.py`

Detect programming language from file:

```python
import os

LANGUAGE_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cs': 'csharp',
}

def detect_language(file_path: str) -> str:
    """Detect programming language from file extension"""
    _, ext = os.path.splitext(file_path)
    return LANGUAGE_EXTENSIONS.get(ext.lower(), 'unknown')

def is_code_file(filename: str) -> bool:
    """Check if file is a code file"""
    _, ext = os.path.splitext(filename)
    return ext.lower() in LANGUAGE_EXTENSIONS
```

---

### Task 2.2: Output Formatters
**File**: `src/cli/utils/formatters.py`

Format output for different formats:

```python
from typing import List, Dict, Any
from tabulate import tabulate

def format_table(data: List[List], headers: List[str]) -> str:
    """Format data as table"""
    return tabulate(data, headers=headers, tablefmt='simple')

def format_sarif(results: Dict[str, Any]) -> str:
    """Convert results to SARIF format"""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TavoAI",
                    "version": "1.0.0",
                }
            },
            "results": []
        }]
    }
    
    # Convert findings to SARIF results
    for finding in results.get('heuristics', {}).get('findings', []):
        sarif['runs'][0]['results'].append({
            "ruleId": finding['rule_id'],
            "level": severity_to_sarif_level(finding['severity']),
            "message": {"text": finding['message']},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": results.get('file_path', 'unknown')},
                    "region": {"startLine": finding['line']}
                }
            }]
        })
    
    return json.dumps(sarif, indent=2)

def severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level"""
    mapping = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
    }
    return mapping.get(severity, 'note')
```

---

## Testing

### Unit Tests
**Location**: `tests/test_registry_commands.py`

Test all registry commands:

```python
def test_list_bundles():
    # Test bundle listing
    pass

def test_search_bundles():
    # Test search functionality
    pass

def test_install_bundle():
    # Test bundle installation
    pass

def test_execute_rule():
    # Test rule execution
    pass

def test_create_bundle():
    # Test bundle creation
    pass
```

**Coverage Target**: 80%

---

### Integration Tests
**Location**: `tests/integration/test_registry_integration.py`

Test CLI integration with API:

```python
def test_end_to_end_workflow():
    # Test: search -> install -> execute -> uninstall
    pass

def test_create_and_publish():
    # Test: create bundle -> publish
    pass
```

---

## Configuration

### Task 3.1: Config File Support
**File**: `src/cli/config.py`

Add registry configuration:

```python
import os
from pathlib import Path
import yaml

class RegistryConfig:
    """Registry configuration management"""
    
    def __init__(self):
        self.config_dir = Path.home() / '.tavoai'
        self.config_file = self.config_dir / 'config.yaml'
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load configuration from file"""
        if self.config_file.exists():
            with open(self.config_file) as f:
                return yaml.safe_load(f) or {}
        return {}
    
    def save_config(self):
        """Save configuration to file"""
        self.config_dir.mkdir(exist_ok=True)
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f)
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()
```

---

## Documentation

### Task 4.1: CLI Help Documentation
**File**: `docs/registry-cli.md`

Create comprehensive CLI documentation:

```markdown
# TavoAI Registry CLI

## Installation

```bash
pip install tavoai-cli
```

## Configuration

Set your API key:

```bash
export TAVOAI_API_KEY="tavo_live_..."
# or
tavo config set api_key "tavo_live_..."
```

## Commands

### Browsing Marketplace

```bash
# List all bundles
tavo registry list

# Filter by type
tavo registry list --type code_rule --pricing free

# Search
tavo registry search "prompt injection"

# Get bundle info
tavo registry info tavoai-owasp-llm-top-10
```

### Installing Bundles

```bash
# Install bundle
tavo registry install tavoai-owasp-llm-top-10

# Download only
tavo registry install tavoai-owasp-llm-top-10 --download-only

# List installed
tavo registry installed

# Update bundle
tavo registry update tavoai-owasp-llm-top-10

# Update all
tavo registry update --all

# Uninstall
tavo registry uninstall tavoai-owasp-llm-top-10
```

### Executing Rules

```bash
# Execute single rule
tavo registry execute rule-id mycode.py

# Scan with entire bundle
tavo registry scan tavoai-owasp-llm-top-10 ./src

# Recursive scan
tavo registry scan tavoai-owasp-llm-top-10 ./src --recursive

# Save results
tavo registry execute rule-id mycode.py --save results.json

# SARIF output
tavo registry execute rule-id mycode.py --output sarif
```

### Creating & Publishing

```bash
# Create bundle
tavo registry create \
  --name "My Custom Rules" \
  --description "Custom security rules" \
  --category security \
  --pricing free \
  --rules rule1.yaml \
  --rules rule2.yaml

# Publish
tavo registry publish bundle-id
```

### Usage Tracking

```bash
# View usage
tavo registry usage

# Detailed breakdown
tavo registry usage --detailed --period month

# Set budget
tavo registry set-budget 50.00
```
```

---

## Success Criteria

### Functionality
- [ ] All registry commands work
- [ ] Bundle installation works (cloud + local)
- [ ] Rule execution works (cloud + local)
- [ ] Publishing workflow complete
- [ ] Usage tracking accurate

### Quality
- [ ] 80%+ test coverage
- [ ] Error handling comprehensive
- [ ] User-friendly output
- [ ] Performance acceptable

### User Experience
- [ ] Clear help messages
- [ ] Progress indicators
- [ ] Informative errors
- [ ] Consistent formatting

---

## Notes

- Integrate with existing CLI architecture
- Use Click framework consistently
- Follow existing CLI patterns and conventions
- Coordinate with SDK team for API client
- Add shell completion support
- Consider adding interactive mode for complex workflows

---

**Last Updated**: October 25, 2025  
**Next Review**: After Phase 1 completion

