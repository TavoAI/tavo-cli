#!/bin/bash

# Exit on error
set -e

# Create a temporary virtual environment
echo "Creating a temporary virtual environment..."
python -m venv test_venv

# Activate the virtual environment
echo "Activating the virtual environment..."
source test_venv/bin/activate

# Install the package in development mode
echo "Installing the package in development mode..."
pip install -e .

# Test the CLI
echo "Testing the CLI..."
ovat --help
ovat server --help
ovat server start-dev --help

# Deactivate the virtual environment
echo "Deactivating the virtual environment..."
deactivate

# Remove the temporary virtual environment
echo "Removing the temporary virtual environment..."
rm -rf test_venv

echo "Installation test completed successfully!" 