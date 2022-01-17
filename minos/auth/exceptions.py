class AuthConfigException(Exception):
    """Base Api Gateway Exception."""


class NoTokenException(AuthConfigException):
    """Exception to be raised when token is not available."""


class ApiGatewayConfigException(AuthConfigException):
    """Base config exception."""
