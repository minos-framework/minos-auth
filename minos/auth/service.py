import logging

from aiohttp import (
    web,
)
from aiomisc.service.aiohttp import (
    AIOHTTPService,
)

from .config import (
    AuthConfig,
)
from .handler import (
    credentials,
    token,
)

logger = logging.getLogger(__name__)


class AuthRestService(AIOHTTPService):
    def __init__(self, address: str, port: int, config: AuthConfig):
        self.config = config
        super().__init__(address, port)

    async def create_application(self) -> web.Application:
        app = web.Application()

        app["config"] = self.config

        app.router.add_route("*", "/auth/{credentials:.*}", credentials)
        app.router.add_route("*", "/auth/{token:.*}", token)

        return app
