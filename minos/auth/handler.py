import logging
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
import secrets

logger = logging.getLogger(__name__)


async def register(request: web.Request) -> web.Response:
    """ Register User """
    try:
        content = await request.json()

        if "password" not in content:
            return web.HTTPBadRequest(text="Wrong data. Provide password.")
    except Exception:
        return web.HTTPBadRequest(text="Wrong data. Provide password.")

    user_host = request.app["config"].user_service.host
    user_port = request.app["config"].user_service.port
    user_path = request.app["config"].user_service.path

    user_url = URL(
        f"http://{user_host}:{user_port}{user_path}"
    )

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(
                headers=headers, method="POST", url=user_url, data=data
            ) as response:
                resp = await _clone_response(response)

                if response.status == 200:
                    resp_json = json.loads(resp.text)
                    user_uuid = resp_json["uuid"]
                    data = {"user_uuid": user_uuid, "username": content["email"], "password": content["password"]}
                    token = secrets.token_hex(20)
                    await create_credentials_call(content["email"], token, user_uuid, request, data)
                return resp

    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def login(request: web.Request) -> web.Response:
    """ Login User """
    return await validate_credentials(request)


async def validate_credentials(request: web.Request):
    """ Login User """
    credential_host = request.app["config"].credential_service.host
    credential_port = request.app["config"].credential_service.port
    credential_path = request.app["config"].credential_service.path

    credential_url = URL(
        f"http://{credential_host}:{credential_port}{credential_path}/validate"
    )

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(
                headers=headers, method=request.method, url=credential_url, data=data
            ) as response:
                resp = await _clone_response(response)

                if response.status == 200:
                    resp_json = json.loads(resp.text)
                    credential_uuid = resp_json["credential_uuid"]
                    token = await get_credential_token(request, credential_uuid)
                    return web.json_response({"token": token})

                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def get_credential_token(request: web.Request, credential_uuid: str):
    """ Get User by Session token """
    Session = sessionmaker(bind=request.app["db_engine"])

    s = Session()

    r = s.query(Authentication).filter(Authentication.auth_uuid == credential_uuid).first()
    s.close()

    return r.token


async def get_user_by_token(request: web.Request) -> web.Response:
    """ Get User by Session token """
    try:
        content = await request.json()

        if "token" not in content:
            return web.HTTPBadRequest(text="Please provide Token.")
    except Exception:
        return web.HTTPBadRequest(text="Please provide Token.")

    Session = sessionmaker(bind=request.app["db_engine"])

    s = Session()

    r = s.query(Authentication).filter(Authentication.token == content["token"]).first()
    s.close()

    if r is not None:
        return await get_user_call(request, r.user_uuid)
    return web.HTTPBadRequest(text="Please provide correct Token.")


async def get_user_call(request: web.Request, user_uuid: str) -> web.Response:
    """ Get User by Session token """
    user_host = request.app["config"].user_service.host
    user_port = request.app["config"].user_service.port
    user_path = request.app["config"].user_service.path

    credential_url = URL(
        f"http://{user_host}:{user_port}{user_path}/{user_uuid}"
    )

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(
                headers=headers, method="GET", url=credential_url, data=data
            ) as response:
                resp = await _clone_response(response)
                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


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
                    auth_uuid = await create_authentication(request, "", "", credential_uuid, AuthType.CREDENTIAL.value)
                    return web.json_response({"authentication": str(auth_uuid)})

                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def create_credentials_call(user_id: str, token: str, user_uuid: str, request: web.Request, data: dict, method: str = "POST"):
    credential_host = request.app["config"].credential_service.host
    credential_port = request.app["config"].credential_service.port
    credential_path = request.app["config"].credential_service.path

    credential_url = URL(
        f"http://{credential_host}:{credential_port}{credential_path}"
    )

    try:
        async with ClientSession() as session:
            async with session.request(
                method=method, url=credential_url, data=json.dumps(data)
            ) as response:
                resp = await _clone_response(response)

                if response.status == 200:
                    resp_json = json.loads(resp.text)
                    credential_uuid = resp_json["credential"]
                    auth_uuid = await create_authentication(request, token, user_id, user_uuid, credential_uuid, AuthType.CREDENTIAL.value)
                    return auth_uuid

                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def token(request: web.Request) -> web.Response:
    """ Orchestrate discovery and microservice call """
    token_host = request.app["config"].token_service.host
    token_port = request.app["config"].token_service.port
    token_path = request.app["config"].token_service.path

    credential_url = URL(
        f"http://{token_host}:{token_port}{token_path}{request.path.replace('/auth/token', '')}"
    )

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(
                headers=headers, method=request.method, url=credential_url, data=data
            ) as response:
                resp = await _clone_response(response)

                if response.status == 200 and request.method == 'POST' and request.path == '/auth/token':
                    resp_json = json.loads(resp.text)
                    credential_uuid = resp_json["token"]
                    auth_uuid = await create_authentication(request, credential_uuid, AuthType.TOKEN.value)
                    return web.json_response({"authentication": str(auth_uuid), "token": resp_json["token"]})

                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


# noinspection PyMethodMayBeStatic
async def _clone_response(response: ClientResponse) -> web.Response:
    return web.Response(
        body=await response.read(), status=response.status, reason=response.reason, headers=response.headers,
    )


async def create_authentication(request: web.Request, token: str, user_id: str, user_uuid: str, auth_uuid: str, auth_type: AuthType):
    Session = sessionmaker(bind=request.app["db_engine"])

    s = Session()

    now = datetime.now()
    uuid = uuid4()



    credential = Authentication(
        uuid=uuid,
        user_uuid=user_uuid,
        auth_uuid=auth_uuid,
        user_id=user_id,
        token=token,
        auth_type=auth_type,
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
