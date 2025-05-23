#!/usr/bin/env python3

import click
import os
import sys
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path

# This will help us find the main server script relative to the CLI location
def get_server_script_path():
    # Get the directory where the package is installed
    package_dir = Path(__file__).resolve().parent
    
    # Look for server.py in the package directory and parent directories
    candidates = [
        package_dir / "server.py",
        package_dir.parent / "server.py",
        Path.cwd() / "server.py"
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    
    # If we couldn't find it, return a default that assumes it's in the current directory
    return "server.py"

@click.group()
def tavo():
    """TAVO - Open Policy Agent Verification and Testing CLI tool."""
    pass

@tavo.command("scan")
@click.option("--project", help="Path to the project directory to scan", required=True)
def scan(project):
    """Scan a project for policy compliance."""
    
    # Display scanning message
    click.echo("\n🔍 Running Tavo Assessment Scan...")
    
    # Mock scan results - in a real implementation, this would call actual scanning logic
    click.echo("\n📁 Project: tavo-demo")
    click.echo("🧠 Detected GenAI integration: OpenAI (gpt-4)")
    click.echo("📄 Detected policies: 3")
    
    click.echo("\n---")
    
    # Add a delay before showing results
    time.sleep(2)
    
    # Policy violations
    click.echo("\n❌ MISSING CONTROLS DETECTED (1 issue)")
    
    click.echo("\n1. ⭕ Insufficient Privacy Controls")
    click.echo("  → Risk: CRITICAL")
    click.echo("  → File: ")
    click.echo("    - app/agents/compliance_agent.py")
    click.echo("    - .gitlab-ci.yml")
    click.echo("  💡 Remediation: Implement data minimization and privacy by design principles.")
    
    click.echo("\n---")
    
    # Summary
    click.echo("❌ 1 missing control identified!")
    
    # Interactive section to add controls and mitigations
    if click.confirm("\nWould you like to add controls and mitigations?", default=False):
        click.echo("\n🛡️ Adding controls and mitigations...")
        
        # Simulate a loading effect
        time.sleep(1)
        
        fix_branch = "tavo-fix-721f21c5671121z2651b20ffd80k8d12"
        files_to_update = [
            ".gitlab-ci.yml",
            "app/agents/compliance_agent.py",
            "app/data/compliance_docs/eu_ai_act_regulations.txt",
            "app/services/pii_masker.py",
            "app/tests/validation/test_eu_ai_act_compliance.py"
        ]
        
        try:
            # Checkout each file from the fix branch
            for file in files_to_update:
                # Create directory if it doesn't exist (for new files)
                file_dir = os.path.dirname(file)
                if file_dir and not os.path.exists(file_dir):
                    os.makedirs(file_dir, exist_ok=True)
                
                # Checkout the file from the fix branch
                subprocess.run(["git", "checkout", fix_branch, "--", file], check=True)
            
            click.echo("✅ Changes applied successfully! Review the changes in your IDE before committing.")
        except subprocess.CalledProcessError as e:
            click.echo(f"❌ Failed to apply changes: {e}")
            return
        
        # Mock implementation of adding controls
        click.echo("\n✅ Updated app/agents/compliance_agent.py:")
        click.echo("  - Updated prompt templates to include PII detection")

        click.echo("\n✅ Updated .gitlab-ci.yml:")
        click.echo("  - Added privacy compliance check stage & tests")

        click.echo("\n✅ Added app/services/pii_masker.py:")
        click.echo("  - Implemented PII masking")

        click.echo("\n✅ Added app/data/compliance_docs/eu_ai_act_regulations.txt:")
        click.echo("  - Instructions for RAG")

        click.echo("\n✅ Added app/tests/validation/test_eu_ai_act_compliance.py:")
        click.echo("  - Test for EU AI Act Personal Data Management")
        
        click.echo("\n📝 All changes have been applied as uncommitted changes. Review them in your IDE and commit when ready.")
    else:
        click.echo("\nNo controls were added. You can add them manually later.")

@tavo.group()
def server():
    """Commands related to the OPA policy server."""
    pass

@server.command("start-dev")
@click.option("--pre-built", is_flag=True, help="Use prebuilt policies on startup")
@click.option("--db-filename", help="Path to the local database file")
@click.option("--use-mongodb", is_flag=True, help="Use MongoDB as the policy data store")
@click.option("--prebuilt-policies-file", help="Path to the prebuilt policies file")
def start_dev(pre_built, db_filename, use_mongodb, prebuilt_policies_file):
    """Start the server in development mode."""
    server_script = get_server_script_path()
    
    cmd = [sys.executable, server_script]
    
    if pre_built:
        cmd.append("--use-prebuilt-policies")
    
    if db_filename:
        cmd.extend(["--db-file", db_filename])
    
    if use_mongodb:
        cmd.append("--use-mongodb")
    
    if prebuilt_policies_file:
        cmd.extend(["--prebuilt-policies-file", prebuilt_policies_file])
    
    click.echo(f"Starting OPA policy server in development mode...")
    click.echo(f"Running command: {' '.join(cmd)}")
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        click.echo("\nServer stopped.")
    except Exception as e:
        click.echo(f"Error starting server: {e}", err=True)
        sys.exit(1)

if __name__ == "__main__":
    tavo() 