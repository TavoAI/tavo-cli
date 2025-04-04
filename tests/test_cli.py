import pytest
from click.testing import CliRunner
from src.cli import tavo

def test_cli_help():
    """Test that the CLI help command works"""
    runner = CliRunner()
    result = runner.invoke(tavo, ['--help'])
    assert result.exit_code == 0
    assert 'TAVO - Open Policy Agent Verification and Testing CLI tool' in result.output

def test_server_help():
    """Test that the server help command works"""
    runner = CliRunner()
    result = runner.invoke(tavo, ['server', '--help'])
    assert result.exit_code == 0
    assert 'Commands related to the OPA policy server' in result.output

def test_server_start_dev_help():
    """Test that the server start-dev help command works"""
    runner = CliRunner()
    result = runner.invoke(tavo, ['server', 'start-dev', '--help'])
    assert result.exit_code == 0
    assert 'Start the server in development mode' in result.output
    assert '--pre-built' in result.output
    assert '--db-filename' in result.output 