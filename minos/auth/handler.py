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

    credential_url = URL(
        f"http://{credential_host}:{credential_port}{credential_path}{request.path.replace('/auth/credentials', '')}"
    )

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(
                headers=headers, method=request.method, url=credential_url, data=data
            ) as response:
                return await _clone_response(response)
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def token(request: web.Request) -> web.Response:
    """ Orchestrate discovery and microservice call """
    token_host = request.app["config"].token_service.host
    token_port = request.app["config"].token_service.port
    token_path = request.app["config"].token_service.path

    verb = request.method

    return web.json_response({})


# noinspection PyMethodMayBeStatic
async def _clone_response(response: ClientResponse) -> web.Response:
    return web.Response(
        body=await response.read(), status=response.status, reason=response.reason, headers=response.headers,
    )
