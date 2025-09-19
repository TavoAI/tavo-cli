"""Rule management system for Tavo.AI CLI."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class RuleSet:
    """Represents a collection of rules from a source."""
    id: str
    version: str
    rules: List[Dict[str, Any]]
    last_updated: datetime
    source: str  # "bundled", "api", "local"


@dataclass
class RuleManagerConfig:
    """Configuration for rule management."""
    cache_dir: Path
    cache_ttl_hours: int = 24
    api_endpoints: Optional[List[str]] = None

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = [
                "https://api.tavo.ai/rules/opengrep",
                "https://api.tavo.ai/rules/opa"
            ]


class RuleManager:
    """Manages rule sets for OpenGrep and OPA."""

    def __init__(self, config: RuleManagerConfig):
        self.config = config
        self.cache_dir = config.cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize with bundled rules
        self._load_bundled_rules()

    def _load_bundled_rules(self):
        """Load bundled rules that ship with the CLI."""
        bundled_path = Path(__file__).parent / "bundled_rules.json"
        if bundled_path.exists():
            with open(bundled_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.bundled_rules = {}
            for rule_type, categories in data.get("rules", {}).items():
                self.bundled_rules[rule_type] = {}
                for category, rule_data in categories.items():
                    last_updated_str = data["metadata"]["last_updated"]
                    # Handle both "rules" (OpenGrep) and "policies" (OPA) keys
                    rules_list = (rule_data.get("rules") or
                                  rule_data.get("policies", []))
                    self.bundled_rules[rule_type][category] = RuleSet(
                        id=f"{rule_type}_{category}",
                        version=rule_data.get("version", "1.0.0"),
                        rules=rules_list,
                        last_updated=datetime.fromisoformat(last_updated_str),
                        source="bundled"
                    )

    def get_opengrep_rules(self, category: str = "llm_security"
                           ) -> List[Dict[str, Any]]:
        """Get OpenGrep rules for a specific category."""
        if category in self.bundled_rules.get("opengrep", {}):
            return self.bundled_rules["opengrep"][category].rules
        return []

    def get_opa_policies(self, category: str = "financial"
                        ) -> List[Dict[str, Any]]:
        """Get OPA policies for a specific category."""
        if category in self.bundled_rules.get("opa", {}):
            return self.bundled_rules["opa"][category].rules
        return []

    def list_available_rules(self) -> Dict[str, List[str]]:
        """List all available rule categories."""
        result = {}
        for rule_type, categories in self.bundled_rules.items():
            result[rule_type] = list(categories.keys())
        return result

    def refresh_rules_from_api(self) -> bool:
        """Refresh rules from remote API endpoints."""
        # Placeholder for API integration
        logger.info("API rule refresh not yet implemented")
        return False

    def export_rules_to_file(self, rule_type: str, category: str,
                            output_path: Path):
        """Export rules to a file for use by OpenGrep or OPA."""
        if rule_type == "opengrep":
            rules = self.get_opengrep_rules(category)
            # Convert to OpenGrep YAML format
            yaml_content = self._convert_to_opengrep_yaml(rules)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
        elif rule_type == "opa":
            policies = self.get_opa_policies(category)
            # Export as JSON for OPA
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump({"policies": policies}, f, indent=2)

    def _convert_to_opengrep_yaml(self, rules: List[Dict[str, Any]]) -> str:
        """Convert rule list to OpenGrep YAML format."""
        yaml_lines = ["rules:"]

        for rule in rules:
            yaml_lines.extend([
                f"  - id: {rule['id']}",
                f"    message: {rule['message']}",
                "    languages: [python]",  # Default to Python
                "    patterns:",
                f"      - pattern: {rule['pattern']}",
                f"    severity: {rule['severity']}",
                ""
            ])

        return "\n".join(yaml_lines)
