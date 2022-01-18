import logging
from typing import (
    Any,
    Optional,
)
from datetime import (
    datetime,
)
from uuid import uuid4
import json
from aiohttp import (
    ClientConnectorError,
    ClientResponse,
    ClientSession,
    web,
)
from yarl import (
    URL,
)
from .database.models import (
    Authentication,
    AuthType,
)
from sqlalchemy.orm import (
    sessionmaker,
)
from sqlalchemy import (
    exc,
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
                resp = await _clone_response(response)

                if response.status == 200 and request.method == 'POST' and request.path == '/auth/credentials':
                    resp_json = json.loads(resp.text)
                    credential_uuid = resp_json["credential"]
                    auth_uuid = await create_authentication(request, credential_uuid, AuthType.CREDENTIAL.value)
                    return web.json_response({"authentication": str(auth_uuid)})

                return resp
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


async def create_authentication(request: web.Request, auth_uuid: str, auth_type: AuthType):
    Session = sessionmaker(bind=request.app["db_engine"])

    s = Session()

    now = datetime.now()
    uuid = uuid4()
    credential = Authentication(
        uuid=uuid,
        auth_type=auth_type,
        auth_uuid=auth_uuid,
        created_at=now,
        updated_at=now,
    )

    try:
        s.add(credential)
        s.commit()
    except exc.IntegrityError:
        return web.json_response(status=500, text="Username is already taken.")

    s.close()

    return uuid
