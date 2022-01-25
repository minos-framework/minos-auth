"""tests.test_api_gateway.test_rest.service module."""
import json
import unittest
from uuid import (
    uuid4,
)

import aiohttp
from aiohttp.test_utils import (
    AioHTTPTestCase,
    unittest_run_loop,
)
from werkzeug.exceptions import (
    abort,
)
from yarl import (
    URL,
)

from minos.auth import (
    AuthConfig,
    AuthRestService,
)
from minos.auth.handler import (
    service_call,
)
from tests.mock_servers.server import (
    MockServer,
)
from tests.utils import (
    BASE_PATH,
)


class TestAuthHandler(AioHTTPTestCase):
    CONFIG_FILE_PATH = BASE_PATH / "config.yml"

    def setUp(self) -> None:
        self.config = AuthConfig(self.CONFIG_FILE_PATH)

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
        resp = await service_call(method="GET", url=URL("http://localhost:1111/none"))

        self.assertEqual(503, resp.status)
        self.assertDictEqual({"error": "The requested endpoint is not available."}, json.loads(resp.text))


if __name__ == "__main__":
    unittest.main()
