import logging
from typing import (
    Any,
    Optional,
)

from aiohttp import (
    ClientConnectorError,
    ClientResponse,
    ClientSession,
    web,
)
from yarl import (
    URL,
)

from .exceptions import (
    NoTokenException,
)

logger = logging.getLogger(__name__)


async def credentials(request: web.Request) -> web.Response:
    """ Orchestrate discovery and microservice call """
    credential_host = request.app["config"].credential_service.host
    credential_port = request.app["config"].credential_service.port
    credential_path = request.app["config"].credential_service.path

    verb = request.method

    return web.json_response({})


async def token(request: web.Request) -> web.Response:
    """ Orchestrate discovery and microservice call """
    token_host = request.app["config"].token_service.host
    token_port = request.app["config"].token_service.port
    token_path = request.app["config"].token_service.path

    verb = request.method

    return web.json_response({})
