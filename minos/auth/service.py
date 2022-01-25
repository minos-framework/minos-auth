import logging

from aiohttp import (
    web,
)
from aiomisc.service.aiohttp import (
    AIOHTTPService,
)
from sqlalchemy import (
    create_engine,
)

from .config import (
    AuthConfig,
)
from .database.models import (
    Base,
)
from .handler import (
    credentials_login,
    get_user_from_credentials,
    get_user_from_token,
    register_credentials,
    register_token,
    token_login,
)

logger = logging.getLogger(__name__)


class AuthRestService(AIOHTTPService):
    def __init__(self, address: str, port: int, config: AuthConfig):
        self.config = config
        self.engine = None
        super().__init__(address, port)

    async def create_application(self) -> web.Application:
        app = web.Application()

        app["config"] = self.config
        self.engine = await self.create_engine()
        await self.create_database()

        app["db_engine"] = self.engine

        app.router.add_route("POST", "/auth/credentials", register_credentials)
        app.router.add_route("POST", "/auth/credentials/login", credentials_login)
        app.router.add_route("GET", "/auth/credentials", get_user_from_credentials)

        app.router.add_route("POST", "/auth/token", register_token)
        app.router.add_route("POST", "/auth/token/login", token_login)
        app.router.add_route("GET", "/auth/token", get_user_from_token)
        app.router.add_route("*", "/auth/validate-token", validate_token)

        return app

    async def create_engine(self):
        DATABASE_URI = (
            f"postgresql+psycopg2://{self.config.database.user}:{self.config.database.password}@"
            f"{self.config.database.host}:{self.config.database.port}/{self.config.database.dbname}"
        )

        return create_engine(DATABASE_URI)

    async def create_database(self):
        Base.metadata.create_all(self.engine)
