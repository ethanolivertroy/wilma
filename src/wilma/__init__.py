"""
Wilma - AWS Bedrock Security Posture Assessment

An AWS Bedrock security posture assessment tool that maps automated evidence to
Bedrock Security Indicators and external security frameworks.

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

__version__ = "0.2.0"
__author__ = "Ethan Troy"
__license__ = "GPL-3.0-or-later"

from wilma.checker import BedrockSecurityChecker
from wilma.enums import RiskLevel, SecurityMode

__all__ = ["BedrockSecurityChecker", "SecurityMode", "RiskLevel", "__version__"]
