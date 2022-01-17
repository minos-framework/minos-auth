from __future__ import (
    annotations,
)

import abc
import collections
import os
import typing as t
from distutils import (
    util,
)
from pathlib import (
    Path,
)

import yaml

from .exceptions import (
    AuthConfigException,
)

REST = collections.namedtuple("Rest", "host port")
USER_SERVICE = collections.namedtuple("UserService", "host port")
CREDENTIAL_SERVICE = collections.namedtuple("CredentialService", "host port path")
TOKEN_SERVICE = collections.namedtuple("TokenService", "host port path")

_ENVIRONMENT_MAPPER = {
    "rest.host": "AUTH_REST_HOST",
    "rest.port": "AUTH_REST_PORT",
    "user-service.host": "AUTH_USER_SERVICE_REST_HOST",
    "user-service.port": "AUTH_USER_SERVICE_REST_PORT",
    "credential-service.host": "AUTH_CREDENTIAL_SERVICE_REST_HOST",
    "credential-service.port": "AUTH_CREDENTIAL_SERVICE_REST_PORT",
    "credential-service.path": "AUTH_CREDENTIAL_SERVICE_REST_PATH",
    "token-service.host": "AUTH_TOKEN_SERVICE_REST_HOST",
    "token-service.port": "AUTH_TOKEN_SERVICE_REST_PORT",
    "token-service.path": "AUTH_TOKEN_SERVICE_REST_PATH",
}

_PARAMETERIZED_MAPPER = {
    "rest.host": "auth_rest_host",
    "rest.port": "auth_rest_port",
    "user-service.host": "auth_user_service_rest_host",
    "user-service.port": "auth_user_service_rest_port",
    "credential-service.host": "auth_credential_service_rest_host",
    "credential-service.port": "auth_credential_service_rest_port",
    "credential-service.path": "auth_credential_service_rest_path",
    "token-service.host": "auth_token_service_rest_host",
    "token-service.port": "auth_token_service_rest_port",
    "token-service.path": "auth_token_service_rest_path",
}


class AuthConfig(abc.ABC):
    """Api Gateway config class."""

    __slots__ = ("_services", "_path", "_data", "_with_environment", "_parameterized")

    def __init__(self, path: t.Union[Path, str], with_environment: bool = True, **kwargs):
        if isinstance(path, Path):
            path = str(path)
        self._services = {}
        self._path = path
        self._load(path)
        self._with_environment = with_environment
        self._parameterized = kwargs

    @staticmethod
    def _file_exit(path: str) -> bool:
        if os.path.isfile(path):
            return True
        return False

    def _load(self, path):
        if self._file_exit(path):
            with open(path) as f:
                self._data = yaml.load(f, Loader=yaml.FullLoader)
        else:
            raise AuthConfigException(f"Check if this path: {path} is correct")

    def _get(self, key: str, **kwargs: t.Any) -> t.Any:
        if key in _PARAMETERIZED_MAPPER and _PARAMETERIZED_MAPPER[key] in self._parameterized:
            return self._parameterized[_PARAMETERIZED_MAPPER[key]]

        if self._with_environment and key in _ENVIRONMENT_MAPPER and _ENVIRONMENT_MAPPER[key] in os.environ:
            if os.environ[_ENVIRONMENT_MAPPER[key]] in ["true", "True", "false", "False"]:
                return bool(util.strtobool(os.environ[_ENVIRONMENT_MAPPER[key]]))
            return os.environ[_ENVIRONMENT_MAPPER[key]]

        def _fn(k: str, data: dict[str, t.Any]) -> t.Any:
            current, _, following = k.partition(".")

            part = data[current]
            if not following:
                return part

            return _fn(following, part)

        return _fn(key, self._data)

    @property
    def rest(self) -> REST:
        """Get the rest config.

        :return: A ``REST`` NamedTuple instance.
        """
        return REST(host=self._get("rest.host"), port=int(self._get("rest.port")))

    @property
    def user_service(self) -> USER_SERVICE:
        """Get the rest config.

        :return: A ``REST`` NamedTuple instance.
        """
        return USER_SERVICE(host=self._get("user-service.host"), port=int(self._get("user-service.port")))

    @property
    def credential_service(self) -> CREDENTIAL_SERVICE:
        """Get the rest config.

        :return: A ``REST`` NamedTuple instance.
        """
        return CREDENTIAL_SERVICE(host=self._get("credential-service.host"),
                                  port=int(self._get("credential-service.port")),
                                  path=str(self._get("credential-service.path")))

    @property
    def token_service(self) -> TOKEN_SERVICE:
        """Get the rest config.

        :return: A ``REST`` NamedTuple instance.
        """
        return TOKEN_SERVICE(host=self._get("token-service.host"), port=int(self._get("token-service.port")),
                             path=str(self._get("token-service.path")))
