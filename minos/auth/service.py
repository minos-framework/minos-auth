import logging
from datetime import (
    datetime,
)

from aiohttp import (
    web,
)
from aiomisc.service.aiohttp import (
    AIOHTTPService,
)
from sqlalchemy import (
    create_engine,
)
from sqlalchemy.orm import (
    sessionmaker,
)

from .config import (
    AuthConfig,
)
from .database.models import (
    Base,
    Role,
)
from .handler import (
    AuthenticationRest,
    RoleRest,
    credentials_login,
    get_user_from_credentials,
    get_user_from_token,
    register_credentials,
    register_token,
    token_login,
    validate_token,
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
        await self.populate_database()

        app["db_engine"] = self.engine

        app.router.add_route("POST", "/auth/credentials", register_credentials)
        app.router.add_route("POST", "/auth/credentials/login", credentials_login)
        app.router.add_route("GET", "/auth/credentials", get_user_from_credentials)

        app.router.add_route("POST", "/auth/token", register_token)
        app.router.add_route("POST", "/auth/token/login", token_login)
        app.router.add_route("GET", "/auth/token", get_user_from_token)

        app.router.add_route("POST", "/auth/validate-token", validate_token)

        app.router.add_route("GET", "/auth/roles", RoleRest.get_roles)

        app.router.add_route("GET", "/auth/all", AuthenticationRest.get_all)

        return app

    async def create_engine(self):
        DATABASE_URI = (
            f"postgresql+psycopg2://{self.config.database.user}:{self.config.database.password}@"
            f"{self.config.database.host}:{self.config.database.port}/{self.config.database.dbname}"
        )

        return create_engine(DATABASE_URI)

    async def create_database(self):
        Base.metadata.create_all(self.engine)

    async def populate_database(self):
        session = sessionmaker(bind=self.engine)
        s = session()
        now = datetime.now()

        for role in self.config.roles.roles:
            instance = s.query(Role).filter(Role.code == role.code, Role.role_name == role.name).one_or_none()
            if instance is None:  # pragma: no cover
                r = Role(code=role.code, role_name=role.name, created_at=now, updated_at=now,)
                s.add(r)
        s.commit()
        s.close()
