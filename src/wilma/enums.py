"""
Enumerations for Wilma Security Modes and Risk Levels

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from enum import Enum


class SecurityMode(Enum):
    """Security check operational modes."""
    STANDARD = "standard"
    LEARN = "learn"


class RiskLevel(Enum):
    """Risk level classifications with scoring."""
    CRITICAL = (9, "[CRITICAL]", "CRITICAL")
    HIGH = (8, "[HIGH]", "HIGH")
    MEDIUM = (6, "[MEDIUM]", "MEDIUM")
    LOW = (3, "[LOW]", "LOW")
    INFO = (1, "[INFO]", "INFO")

    def __init__(self, score, symbol, label):
        self.score = score
        self.symbol = symbol
        self.label = label
