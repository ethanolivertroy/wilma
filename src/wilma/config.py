"""
Configuration management for Wilma

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
from pathlib import Path
from typing import Any, List, Optional

import yaml

from wilma.enums import RiskLevel


class WilmaConfig:
    """Configuration manager for Wilma security checks."""

    # Default configuration values
    DEFAULT_CONFIG = {
        'required_tags': ['Environment', 'Owner', 'Project', 'DataClassification'],
        'thresholds': {
            'chunk_size_max': 1000,
            'chunk_overlap_max': 30,
            'log_retention_days': 90
        },
        'output': {
            'min_risk_level': 'LOW'
        },
        'checks': {
            'enabled': ['genai', 'iam', 'logging', 'network', 'tagging', 'knowledge_bases']
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Wilma configuration.

        Args:
            config_path: Optional path to config file. If None, searches default locations.
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config(config_path)

    def _load_config(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from file, with fallbacks.

        Priority order:
        1. Provided config_path argument
        2. ~/.wilma/config.yaml
        3. Default configuration
        """
        # Try provided path first
        if config_path:
            if os.path.exists(config_path):
                self._merge_config_file(config_path)
                print(f"[INFO] Loaded configuration from: {config_path}")
            else:
                print(f"[WARN] Config file not found: {config_path}")
                print("[INFO] Using default configuration")
            return

        # Try default location
        default_path = Path.home() / '.wilma' / 'config.yaml'
        if default_path.exists():
            self._merge_config_file(str(default_path))
            print(f"[INFO] Loaded configuration from: {default_path}")
        else:
            print("[INFO] No config file found, using default configuration")

    def _merge_config_file(self, file_path: str) -> None:
        """
        Load and merge configuration from YAML file.

        Args:
            file_path: Path to YAML configuration file
        """
        try:
            with open(file_path) as f:
                user_config = yaml.safe_load(f)

            if not user_config:
                return

            # Validate and merge configuration
            if not isinstance(user_config, dict):
                print(f"[ERROR] Invalid config file format: {file_path}")
                return

            # Merge top-level keys
            for key in ['required_tags', 'thresholds', 'output', 'checks']:
                if key in user_config:
                    if isinstance(user_config[key], dict):
                        self.config[key].update(user_config[key])
                    else:
                        self.config[key] = user_config[key]

            self._validate_config()

        except yaml.YAMLError as e:
            print(f"[ERROR] Failed to parse config file {file_path}: {str(e)}")
        except Exception as e:
            print(f"[ERROR] Failed to load config file {file_path}: {str(e)}")

    def _validate_config(self) -> None:
        """Validate loaded configuration values."""
        # Validate required_tags
        if not isinstance(self.config['required_tags'], list):
            print("[WARN] Invalid 'required_tags' configuration, using defaults")
            self.config['required_tags'] = self.DEFAULT_CONFIG['required_tags']

        # Validate thresholds
        thresholds = self.config['thresholds']
        if not isinstance(thresholds, dict):
            print("[WARN] Invalid 'thresholds' configuration, using defaults")
            self.config['thresholds'] = self.DEFAULT_CONFIG['thresholds']
        else:
            # Ensure numeric thresholds
            for key in ['chunk_size_max', 'chunk_overlap_max', 'log_retention_days']:
                if key in thresholds:
                    try:
                        thresholds[key] = int(thresholds[key])
                    except (ValueError, TypeError):
                        print(f"[WARN] Invalid threshold value for '{key}', using default")
                        thresholds[key] = self.DEFAULT_CONFIG['thresholds'][key]

        # Validate min_risk_level
        valid_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_risk = self.config['output'].get('min_risk_level', 'LOW').upper()
        if min_risk not in valid_levels:
            print(f"[WARN] Invalid min_risk_level '{min_risk}', using 'LOW'")
            self.config['output']['min_risk_level'] = 'LOW'
        else:
            self.config['output']['min_risk_level'] = min_risk

        # Validate enabled checks
        valid_checks = ['genai', 'iam', 'logging', 'network', 'tagging', 'knowledge_bases']
        enabled = self.config['checks'].get('enabled', [])
        if not isinstance(enabled, list):
            print("[WARN] Invalid 'enabled' checks configuration, using all checks")
            self.config['checks']['enabled'] = valid_checks
        else:
            # Filter out invalid check names
            invalid_checks = [c for c in enabled if c not in valid_checks]
            if invalid_checks:
                print(f"[WARN] Unknown checks ignored: {', '.join(invalid_checks)}")
            self.config['checks']['enabled'] = [c for c in enabled if c in valid_checks]

    # ========================================================================
    # Configuration Accessors
    # ========================================================================

    @property
    def required_tags(self) -> List[str]:
        """Get list of required tag keys for resources."""
        return self.config['required_tags']

    @property
    def chunk_size_max(self) -> int:
        """Get maximum recommended chunk size in tokens."""
        return self.config['thresholds']['chunk_size_max']

    @property
    def chunk_overlap_max(self) -> int:
        """Get maximum recommended chunk overlap percentage."""
        return self.config['thresholds']['chunk_overlap_max']

    @property
    def log_retention_days(self) -> int:
        """Get recommended log retention period in days."""
        return self.config['thresholds']['log_retention_days']

    @property
    def min_risk_level(self) -> RiskLevel:
        """Get minimum risk level for filtering findings."""
        level_str = self.config['output']['min_risk_level']
        return RiskLevel[level_str]

    @property
    def enabled_checks(self) -> List[str]:
        """Get list of enabled check modules."""
        return self.config['checks']['enabled']

    def is_check_enabled(self, check_name: str) -> bool:
        """
        Check if a specific check module is enabled.

        Args:
            check_name: Name of the check module (e.g., 'genai', 'iam')

        Returns:
            True if the check is enabled, False otherwise
        """
        return check_name in self.enabled_checks

    def should_include_finding(self, finding_risk_level: RiskLevel) -> bool:
        """
        Determine if a finding should be included based on risk level filter.

        Args:
            finding_risk_level: Risk level of the finding

        Returns:
            True if the finding meets the minimum risk level threshold
        """
        return finding_risk_level.score >= self.min_risk_level.score

    def get_custom_config(self, key: str, default: Any = None) -> Any:
        """
        Get a custom configuration value.

        Args:
            key: Configuration key (supports dot notation, e.g., 'thresholds.chunk_size_max')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    # ========================================================================
    # Configuration Display
    # ========================================================================

    def print_config(self) -> None:
        """Print current configuration for debugging."""
        print("\n[CONFIG] Wilma Configuration:")
        print(f"  Required Tags: {', '.join(self.required_tags)}")
        print(f"  Chunk Size Max: {self.chunk_size_max} tokens")
        print(f"  Chunk Overlap Max: {self.chunk_overlap_max}%")
        print(f"  Log Retention: {self.log_retention_days} days")
        print(f"  Min Risk Level: {self.min_risk_level.value}")
        print(f"  Enabled Checks: {', '.join(self.enabled_checks)}")
        print()

    def save_default_config(self, output_path: Optional[str] = None) -> str:
        """
        Save default configuration to a file.

        Args:
            output_path: Optional output path. If None, saves to ~/.wilma/config.yaml

        Returns:
            Path where config was saved
        """
        if output_path is None:
            config_dir = Path.home() / '.wilma'
            config_dir.mkdir(exist_ok=True)
            output_path = str(config_dir / 'config.yaml')

        with open(output_path, 'w') as f:
            yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)

        return output_path


# ============================================================================
# Configuration File Template
# ============================================================================

def create_example_config(output_path: str) -> None:
    """
    Create an example configuration file with comments.

    Args:
        output_path: Path where to save the example config
    """
    example_config = """# Wilma Security Checker Configuration
# This file allows you to customize Wilma's behavior and checks

# Required tags for governance and access control
# These tags will be validated on resources like Knowledge Bases, Models, etc.
required_tags:
  - Environment      # e.g., Development, Staging, Production
  - Owner            # Team or person responsible
  - Project          # Project or application name
  - DataClassification  # e.g., Public, Internal, Confidential, Restricted

# Security thresholds for various checks
thresholds:
  # Maximum recommended chunk size for Knowledge Base documents (in tokens)
  # Large chunks may include unintended context
  chunk_size_max: 1000

  # Maximum recommended chunk overlap percentage
  # High overlap may leak sensitive context across boundaries
  chunk_overlap_max: 30

  # Recommended log retention period (in days)
  # Adjust based on your compliance requirements
  log_retention_days: 90

# Output configuration
output:
  # Minimum risk level to include in reports
  # Options: LOW, MEDIUM, HIGH, CRITICAL
  # Use MEDIUM or HIGH in CI/CD to focus on critical issues
  min_risk_level: LOW

# Check module configuration
checks:
  # List of enabled check modules
  # Available: genai, iam, logging, network, tagging, knowledge_bases
  # Remove modules you don't want to run
  enabled:
    - genai
    - iam
    - logging
    - network
    - tagging
    - knowledge_bases

# Advanced: Custom check-specific configuration
# (Future expansion area for per-check settings)
"""

    with open(output_path, 'w') as f:
        f.write(example_config)

    print(f"[SUCCESS] Example configuration saved to: {output_path}")
