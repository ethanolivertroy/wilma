"""
Wilma - AWS Bedrock Security Configuration Checker

A comprehensive security auditing tool for AWS Bedrock that combines traditional
cloud security best practices with cutting-edge GenAI security capabilities.

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

__version__ = "1.0.0"
__author__ = "Ethan Troy"
__license__ = "GPL-3.0"

from wilma.checker import BedrockSecurityChecker
from wilma.enums import RiskLevel, SecurityMode

__all__ = ["BedrockSecurityChecker", "SecurityMode", "RiskLevel"]
