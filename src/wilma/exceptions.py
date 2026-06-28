"""Public exceptions for embedders of the Wilma library API."""


class WilmaError(Exception):
    """Base exception for Wilma library errors."""


class WilmaCredentialsError(WilmaError):
    """Raised when AWS credentials/session initialization fails."""
