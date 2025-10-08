"""Rule management system for Tavo AI CLI."""

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
                "https://api.tavoai.net/rules/opengrep",
                "https://api.tavoai.net/rules/opa",
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
            with open(bundled_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.bundled_rules = {}
            for rule_type, categories in data.get("rules", {}).items():
                self.bundled_rules[rule_type] = {}
                for category, rule_data in categories.items():
                    last_updated_str = data["metadata"]["last_updated"]
                    # Handle both "rules" (OpenGrep) and "policies" (OPA) keys
                    rules_list = rule_data.get("rules") or rule_data.get("policies", [])
                    self.bundled_rules[rule_type][category] = RuleSet(
                        id=f"{rule_type}_{category}",
                        version=rule_data.get("version", "1.0.0"),
                        rules=rules_list,
                        last_updated=datetime.fromisoformat(last_updated_str),
                        source="bundled",
                    )

        # Also load rules from tavo-rules repository if available
        self._load_tavo_rules_repository()

    def _load_tavo_rules_repository(self):
        """Load rules from the tavo-rules repository."""
        # Try to find tavo-rules repository relative to current location
        current_dir = Path.cwd()
        tavo_rules_path = None

        # Check if we're in the main workspace
        workspace_root = current_dir
        while workspace_root.parent != workspace_root:
            if (workspace_root / "tavo-rules").exists():
                tavo_rules_path = workspace_root / "tavo-rules"
                break
            workspace_root = workspace_root.parent

        if tavo_rules_path:
            logger.info(f"Loading rules from tavo-rules repository: {tavo_rules_path}")
            self._load_rules_from_directory(tavo_rules_path)
        else:
            logger.debug("tavo-rules repository not found, using only bundled rules")

    def _load_rules_from_directory(self, rules_dir: Path):
        """Load rules from a directory structure."""
        bundles_dir = rules_dir / "bundles"
        if bundles_dir.exists():
            # Load all bundle categories
            for bundle_dir in bundles_dir.iterdir():
                if bundle_dir.is_dir() and bundle_dir.name != ".git":
                    self._load_bundle_directory(bundle_dir)

    def _load_bundle_directory(self, bundle_dir: Path):
        """Load a specific bundle directory."""
        index_file = bundle_dir / "index.json"
        if index_file.exists():
            index_data = self._load_index_file(index_file)
            if index_data:
                self._process_rule_files(bundle_dir, index_data)

    def _load_index_file(self, index_file: Path) -> Optional[Dict[str, Any]]:
        """Load and parse the index.json file."""
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading index file {index_file}: {e}")
            return None

    def _process_rule_files(self, llm_security_dir: Path, index_data: Dict[str, Any]):
        """Process rule files based on index data."""
        rules_by_file = self._group_rules_by_file(index_data)

        for file_name, rule_infos in rules_by_file.items():
            yaml_file = llm_security_dir / file_name
            if yaml_file.exists():
                self._load_yaml_rule_file(yaml_file, file_name, rule_infos, index_data)

    def _group_rules_by_file(
        self, index_data: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group rules by their file name."""
        rules_by_file = {}
        for rule_info in index_data.get("rules", []):
            file_name = rule_info["file"]
            if file_name not in rules_by_file:
                rules_by_file[file_name] = []
            rules_by_file[file_name].append(rule_info)
        return rules_by_file

    def _load_yaml_rule_file(
        self,
        yaml_file: Path,
        file_name: str,
        rule_infos: List[Dict[str, Any]],
        index_data: Dict[str, Any],
    ):
        """Load a YAML rule file and add it to bundled rules."""
        try:
            import yaml

            with open(yaml_file, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)

            if isinstance(yaml_data, dict):
                self._add_rule_set_to_bundled(
                    yaml_data, file_name, rule_infos, index_data
                )

        except ImportError:
            logger.warning("PyYAML not available, skipping YAML rule loading")
        except Exception as e:
            logger.error(f"Error loading rules from {yaml_file}: {e}")

    def _add_rule_set_to_bundled(
        self,
        yaml_data: Dict[str, Any],
        file_name: str,
        rule_infos: List[Dict[str, Any]],
        index_data: Dict[str, Any],
    ):
        """Add a rule set to the bundled rules collection."""
        # Initialize opengrep rules if not exists
        if "opengrep" not in self.bundled_rules:
            self.bundled_rules["opengrep"] = {}

        # Extract category from first rule
        category = rule_infos[0]["category"] if rule_infos else "llm_security"

        # Create RuleSet for this file
        rule_set = RuleSet(
            id=f"opengrep_{category}_{file_name}",
            version=index_data.get("version", "1.0.0"),
            rules=yaml_data.get("rules", []),
            last_updated=datetime.fromisoformat(
                index_data.get("metadata", {}).get("last_updated", "2024-01-01")
            ),
            source="tavo-rules",
        )

        self.bundled_rules["opengrep"][category] = rule_set
        logger.info(f"Loaded {len(rule_set.rules)} rules from {file_name}")

    def get_opengrep_rules(
        self, category: str = "llm_security"
    ) -> List[Dict[str, Any]]:
        """Get OpenGrep rules for a specific category."""
        if category in self.bundled_rules.get("opengrep", {}):
            return self.bundled_rules["opengrep"][category].rules
        return []

    def get_opa_policies(self, category: str = "financial") -> List[Dict[str, Any]]:
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

    def export_rules_to_file(self, rule_type: str, category: str, output_path: Path):
        """Export rules to a file for use by OpenGrep or OPA."""
        if rule_type == "opengrep":
            rules = self.get_opengrep_rules(category)
            # Convert to OpenGrep YAML format
            yaml_content = self._convert_to_opengrep_yaml(rules)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(yaml_content)
        elif rule_type == "opa":
            policies = self.get_opa_policies(category)
            # Export as JSON for OPA
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump({"policies": policies}, f, indent=2)

    def _convert_to_opengrep_yaml(self, rules: List[Dict[str, Any]]) -> str:
        """Convert rule list to OpenGrep YAML format."""
        yaml_lines = ["rules:"]

        for rule in rules:
            yaml_lines.extend(
                [
                    f"  - id: {rule['id']}",
                    f"    message: {rule['message']}",
                    "    languages: [python]",  # Default to Python
                    "    patterns:",
                    f"      - pattern: {rule['pattern']}",
                    f"    severity: {rule['severity']}",
                    "",
                ]
            )

        return "\n".join(yaml_lines)
