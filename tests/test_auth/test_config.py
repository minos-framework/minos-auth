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

    def test_overwrite_with_parameter_rest_host(self):
        config = AuthConfig(path=self.config_file_path, auth_rest_host="::1")
        self.assertEqual("::1", config.rest.host)

    def test_overwrite_with_parameter_rest_port(self):
        config = AuthConfig(path=self.config_file_path, auth_rest_port=2233)
        self.assertEqual(2233, config.rest.port)

    def test_config_database(self):
        config = AuthConfig(path=self.config_file_path)
        database = config.database

        self.assertEqual("auth_db", database.dbname)
        self.assertEqual("minos", database.user)
        self.assertEqual("min0s", database.password)
        self.assertEqual(5432, database.port)

    def test_config_roles(self):
        config = AuthConfig(path=self.config_file_path)
        roles = config.roles

        self.assertIsInstance(roles.roles, list)
        self.assertEqual("3", roles.default)

    @mock.patch.dict(os.environ, {"AUTH_DATABASE_NAME": "db_test_name"})
    def test_overwrite_with_environment_database_name(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("db_test_name", config.database.dbname)

    @mock.patch.dict(os.environ, {"AUTH_DATABASE_USER": "test_user"})
    def test_overwrite_with_environment_database_user(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("test_user", config.database.user)

    @mock.patch.dict(os.environ, {"AUTH_DATABASE_PASSWORD": "some_pass"})
    def test_overwrite_with_environment_database_password(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("some_pass", config.database.password)

    @mock.patch.dict(os.environ, {"AUTH_DATABASE_HOST": "localhost.com"})
    def test_overwrite_with_environment_database_host(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual("localhost.com", config.database.host)

    @mock.patch.dict(os.environ, {"AUTH_DATABASE_PORT": "2020"})
    def test_overwrite_with_environment_database_port(self):
        config = AuthConfig(path=self.config_file_path)
        self.assertEqual(2020, config.database.port)

    def test_config_user_service(self):
        config = AuthConfig(path=self.config_file_path)
        user_service = config.user_service

        self.assertEqual("localhost", user_service.host)
        self.assertEqual(8090, user_service.port)

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
