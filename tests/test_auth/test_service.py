"""tests.test_api_gateway.test_rest.service module."""
import json
import unittest
from uuid import (
    uuid4,
)

import aiohttp
from aiohttp.test_utils import (
    AioHTTPTestCase,
)

from minos.auth import (
    AuthConfig,
    AuthRestService,
)
from tests.mock_servers.server import (
    MockServer,
)
from tests.utils import (
    BASE_PATH,
)

CONFIG_FILE_PATH = BASE_PATH / "config.yml"


class TestAuthRestService(AioHTTPTestCase):
    def setUp(self) -> None:
        self.config = AuthConfig(CONFIG_FILE_PATH)

        self.user = MockServer(host=self.config.user_service.host, port=self.config.user_service.port,)
        self.user.add_json_response(
            "/users", {"uuid": str(uuid4())}, methods=("POST",),
        )
        self.user.add_json_response(
            "/users/<uuid>", {"uuid": str(uuid4())}, methods=("GET",),
        )

        self.credentials = MockServer(
            host=self.config.credential_service.host, port=self.config.credential_service.port,
        )
        self.credentials.add_json_response(
            "/credentials", {"credential_uuid": "ioeiwoeweojkejk"}, methods=("POST",),
        )
        self.credentials.add_json_response(
            "/credentials/validate", {"credential_uuid": "ioeiwoeweojkejk"}, methods=("POST",),
        )

        self.token = MockServer(host=self.config.token_service.host, port=self.config.token_service.port,)
        self.token.add_json_response("/token", {"uuid": str(uuid4()), "token": "wenwmeodsaldkdñ"}, methods=("POST",))
        self.token.add_json_response("/token/validate", {"message": "Token valid."}, methods=("POST",))

        self.user.start()
        self.credentials.start()
        self.token.start()
        super().setUp()

    def tearDown(self) -> None:
        self.user.shutdown_server()
        self.credentials.shutdown_server()
        self.token.shutdown_server()
        super().tearDown()

    async def get_application(self):
        """
        Override the get_app method to return your application.
        """
        rest_service = AuthRestService(address=self.config.rest.host, port=self.config.rest.port, config=self.config)

        return await rest_service.create_application()

    async def test_create_credentials(self):
        url = "/auth/credentials"
        response = await self.client.request(
            "POST", url, data=json.dumps({"email": "test@gmail.com", "username": "test@gmail.com", "password": "1234"})
        )

        self.assertEqual(200, response.status)
        self.assertIn("uuid", await response.text())

    async def test_create_credentials_wrong_data(self):
        url = "/auth/credentials"
        response = await self.client.request("POST", url, data=json.dumps({"example": "none"}))

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Wrong data. Provide username and password."}, json.loads(await response.text()))

    async def test_create_credentials_no_data(self):
        url = "/auth/credentials"
        response = await self.client.request("POST", url,)

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Wrong data. Provide username and password."}, json.loads(await response.text()))

    async def test_get_user_from_credentials(self):

        url = "/auth/credentials"

        headers = {"Authorization": aiohttp.BasicAuth("test@gmail.com", "1234").encode()}

        response = await self.client.request("GET", url, headers=headers)

        self.assertEqual(200, response.status)
        self.assertIn("uuid", await response.text())

    async def test_login_credentials(self):
        url = "/auth/credentials/login"
        response = await self.client.request(
            "POST", url, data=json.dumps({"email": "test@gmail.com", "username": "test@gmail.com", "password": "1234"})
        )

        self.assertEqual(200, response.status)
        self.assertIn("token", await response.text())

    async def test_validate_token_no_data(self):
        url = "/auth/validate-token"
        response = await self.client.request("POST", url)

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Please provide Token."}, json.loads(await response.text()))

    async def test_validate_token_wrong_data(self):
        url = "/auth/validate-token"
        response = await self.client.request("POST", url, headers={"Authorization": "Bearer some-token"})

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Please provide correct Token."}, json.loads(await response.text()))

    async def test_validate_credentials_token(self):
        url = "/auth/credentials/login"
        resp = await self.client.request(
            "POST", url, data=json.dumps({"email": "test@gmail.com", "username": "test@gmail.com", "password": "1234"})
        )

        self.assertEqual(200, resp.status)
        self.assertIn("token", await resp.text())

        token = json.loads(await resp.text())["token"]
        url = "/auth/validate-token"
        response = await self.client.request("POST", url, headers={"Authorization": f"Bearer {token}"})

        self.assertEqual(200, response.status)
        self.assertIn("uuid", await response.text())

    async def test_create_token(self):
        url = "/auth/token"
        response = await self.client.request("POST", url, data=json.dumps({"email": "test@gmail.com"}))

        self.assertEqual(200, response.status)
        self.assertIn("token", await response.text())

    async def test_create_token_wrong_data(self):
        url = "/auth/token"
        response = await self.client.request("POST", url, data=json.dumps({"example": "test"}))

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Wrong data. Provide email."}, json.loads(await response.text()))

    async def test_create_token_no_data(self):
        url = "/auth/token"
        response = await self.client.request("POST", url,)

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Wrong data. Provide email."}, json.loads(await response.text()))

    async def test_get_user_from_token(self):

        url = "/auth/token"
        response = await self.client.request("GET", url, headers={"Authorization": "Bearer wenwmeodsaldkdñ"})

        self.assertEqual(200, response.status)
        self.assertIn("uuid", await response.text())

    async def test_get_user_from_token_wrong(self):

        url = "/auth/token"
        response = await self.client.request("GET", url)

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Please provide Token."}, json.loads(await response.text()))

    async def test_login_token(self):

        url = "/auth/token/login"
        response = await self.client.request("POST", url, headers={"Authorization": "Bearer wenwmeodsaldkdñ"})

        self.assertEqual(200, response.status)
        self.assertIn("token", await response.text())

    async def test_validate_token(self):
        url = "/auth/validate-token"
        response = await self.client.request("POST", url, headers={"Authorization": "Bearer wenwmeodsaldkdñ"})

        self.assertEqual(200, response.status)
        self.assertIn("uuid", await response.text())

    async def test_login_wrong_token(self):

        url = "/auth/token/login"
        response = await self.client.request("POST", url, headers={"Authorization": "Bearer nonexistingtoken"})

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Please provide correct Token."}, json.loads(await response.text()))

    async def test_login_without_token(self):

        url = "/auth/token/login"
        response = await self.client.request("POST", url)

        self.assertEqual(400, response.status)
        self.assertDictEqual({"error": "Please provide Token."}, json.loads(await response.text()))


class TestRolesRestService(AioHTTPTestCase):
    def setUp(self) -> None:
        self.config = AuthConfig(CONFIG_FILE_PATH)
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()

    async def get_application(self):
        """
        Override the get_app method to return your application.
        """
        rest_service = AuthRestService(address=self.config.rest.host, port=self.config.rest.port, config=self.config)

        return await rest_service.create_application()

    async def test_create_credentials(self):
        url = "/auth/roles"
        response = await self.client.request("GET", url,)

        self.assertEqual(200, response.status)


class TestAuthenticationRestService(AioHTTPTestCase):
    def setUp(self) -> None:
        self.config = AuthConfig(CONFIG_FILE_PATH)
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()

    async def get_application(self):
        """
        Override the get_app method to return your application.
        """
        rest_service = AuthRestService(address=self.config.rest.host, port=self.config.rest.port, config=self.config)

        return await rest_service.create_application()

    async def test_create_credentials(self):
        url = "/auth/all"
        response = await self.client.request("GET", url,)

        self.assertEqual(200, response.status)


if __name__ == "__main__":
    unittest.main()
