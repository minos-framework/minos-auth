"""
Copyright (C) 2021 Clariteia SL

This file is part of minos framework.

Minos framework can not be copied and/or distributed without the express permission of Clariteia SL.
"""
import os
import unittest
from unittest import (
    mock,
)

from minos.auth import (
    AuthConfig,
    AuthConfigException,
)
from tests.utils import (
    BASE_PATH,
)


class TestApiGatewayConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.config_file_path = BASE_PATH / "config.yml"

    def test_config_ini_fail(self):
        with self.assertRaises(AuthConfigException):
            AuthConfig(path=BASE_PATH / "test_fail_config.yaml")

    def test_config_rest(self):
        config = AuthConfig(path=self.config_file_path)
        rest = config.rest

        self.assertEqual("localhost", rest.host)
        self.assertEqual(55909, rest.port)

    @mock.patch.dict(os.environ, {"AUTH_REST_HOST": "::1"})
    def test_overwrite_with_environment_rest_host(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("::1", config.rest.host)

    @mock.patch.dict(os.environ, {"AUTH_REST_PORT": "4040"})
    def test_overwrite_with_environment_rest_port(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual(4040, config.rest.port)

    def test_config_user_service(self):
        config = AuthConfig(path=self.config_file_path)
        user_service = config.user_service

        self.assertEqual("localhost", user_service.host)
        self.assertEqual(5567, user_service.port)

    @mock.patch.dict(os.environ, {"AUTH_USER_SERVICE_REST_HOST": "::1"})
    def test_overwrite_with_environment_user_service_host(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("::1", config.user_service.host)

    @mock.patch.dict(os.environ, {"AUTH_USER_SERVICE_REST_PORT": "4040"})
    def test_overwrite_with_environment_user_service_port(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual(4040, config.user_service.port)

    def test_config_credential_service(self):
        config = AuthConfig(path=self.config_file_path)
        credential_service = config.credential_service

        self.assertEqual("localhost", credential_service.host)
        self.assertEqual(5568, credential_service.port)
        self.assertEqual("localhost", credential_service.host)
        self.assertEqual("/credentials", credential_service.path)

    @mock.patch.dict(os.environ, {"AUTH_CREDENTIAL_SERVICE_REST_HOST": "::1"})
    def test_overwrite_with_environment_credential_service_host(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("::1", config.credential_service.host)

    @mock.patch.dict(os.environ, {"AUTH_CREDENTIAL_SERVICE_REST_PORT": "4040"})
    def test_overwrite_with_environment_credential_service_port(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual(4040, config.credential_service.port)

    @mock.patch.dict(os.environ, {"AUTH_CREDENTIAL_SERVICE_REST_PATH": "/credential-test"})
    def test_overwrite_with_environment_credential_service_path(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("/credential-test", config.credential_service.path)

    def test_config_token_service(self):
        config = AuthConfig(path=self.config_file_path)
        token_service = config.token_service

        self.assertEqual("localhost", token_service.host)
        self.assertEqual(5569, token_service.port)
        self.assertEqual("/token", token_service.path)

    @mock.patch.dict(os.environ, {"AUTH_TOKEN_SERVICE_REST_HOST": "::1"})
    def test_overwrite_with_environment_token_service_host(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("::1", config.token_service.host)

    @mock.patch.dict(os.environ, {"AUTH_TOKEN_SERVICE_REST_PORT": "4040"})
    def test_overwrite_with_environment_token_service_port(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual(4040, config.token_service.port)

    @mock.patch.dict(os.environ, {"AUTH_TOKEN_SERVICE_REST_PATH": "/token-test"})
    def test_overwrite_with_environment_token_service_path(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("/token-test", config.token_service.path)


if __name__ == "__main__":
    unittest.main()
