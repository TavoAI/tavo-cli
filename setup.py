#!/usr/bin/env python3

from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="ovat-cli",
    version="0.1.0",
    packages=["src"],
    package_dir={"ovat_cli": "src"},
    py_modules=["src"],
    include_package_data=True,
    package_data={
        'src': ['server.py', 'policy_store.py', 'prebuilt_policies.json'],
    },
    install_requires=requirements,
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "ovat=src.cli:ovat",
        ],
    },
    description="OVAT - Open Policy Agent Verification and Testing CLI tool",
    author="OVAT Team",
    author_email="info@ovat.com",
    url="https://github.com/ovat-team/ovat-cli",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
) 