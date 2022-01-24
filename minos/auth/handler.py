import json
import logging
import secrets
from datetime import (
    datetime,
)
from uuid import (
    uuid4,
)

from aiohttp import (
    ClientConnectorError,
    ClientResponse,
    ClientSession,
    web,
)
from sqlalchemy import (
    desc,
    exc,
)
from sqlalchemy.orm import (
    sessionmaker,
)
from yarl import (
    URL,
)

from .database.models import (
    Authentication,
    AuthType,
)

logger = logging.getLogger(__name__)


async def register_credentials(request: web.Request) -> web.Response:
    """ Register User """
    try:
        content = await request.json()

        if "username" not in content or "password" not in content:
            return web.json_response({"error": "Wrong data. Provide username and password."}, status=400)
    except Exception:
        return web.json_response({"error": "Wrong data. Provide username and password."}, status=400)

    user_creation = await create_user_service_call(request)

    if user_creation.status == 200:
        resp_json = json.loads(user_creation.text)
        user_uuid = resp_json["uuid"]
        data = {"username": content["email"], "password": content["password"]}

        credentials_response = await create_credentials_call(request, data)

        if credentials_response.status == 200:
            resp_json_cred = json.loads(credentials_response.text)
            credential_uuid = resp_json_cred["credential_uuid"]
            token = secrets.token_hex(20)
            await create_authentication(
                request, token, content["email"], user_uuid, credential_uuid, AuthType.CREDENTIAL.value
            )
        else:
            return credentials_response

    return user_creation


async def register_token(request: web.Request) -> web.Response:
    """ Register User using token """
    try:
        content = await request.json()

        if "email" not in content:
            return web.HTTPBadRequest(text="Wrong data. Provide email.")
    except Exception:
        return web.HTTPBadRequest(text="Wrong data. Provide email.")

    user_creation = await create_user_service_call(request)

    if user_creation.status == 200:
        resp_json = json.loads(user_creation.text)
        user_uuid = resp_json["uuid"]

        token_response = await create_token_service_call(request)

        if token_response.status == 200:
            resp_json_cred = json.loads(token_response.text)
            await create_authentication(
                request,
                resp_json_cred["token"],
                content["email"],
                user_uuid,
                resp_json_cred["uuid"],
                AuthType.TOKEN.value,
            )
        return token_response

    return user_creation


async def create_user_service_call(request: web.Request) -> web.Response:
    """ Register User """
    user_host = request.app["config"].user_service.host
    user_port = request.app["config"].user_service.port
    user_path = request.app["config"].user_service.path

    user_url = URL(f"http://{user_host}:{user_port}{user_path}")

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(headers=headers, method="POST", url=user_url, data=data) as response:
                return await _clone_response(response)

    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def create_token_service_call(request: web.Request):
    """ Register User """
    token_host = request.app["config"].token_service.host
    token_port = request.app["config"].token_service.port
    token_path = request.app["config"].token_service.path

    credential_url = URL(f"http://{token_host}:{token_port}{token_path}")

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(
                headers=headers, method=request.method, url=credential_url, data=data
            ) as response:
                resp = await _clone_response(response)

                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def credentials_login(request: web.Request) -> web.Response:
    """ Login User """
    resp, token = await validate_credentials(request)
    return resp


async def token_login(request: web.Request) -> web.Response:
    """ Login User """
    try:
        token = await _get_authorization_token(request)
    except Exception:
        return web.json_response({"error": "Please provide Token."}, status=400)

    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

    r = s.query(Authentication).filter(Authentication.token == token).order_by(desc(Authentication.updated_at)).first()

    if r is not None:
        if r.auth_type == AuthType.TOKEN.value:
            token_response = await create_token_service_call(request)
            res = json.loads(token_response.text)
            r.token = res["token"]
            r.auth_uuid = res["uuid"]
            s.commit()
            return web.json_response({"token": res["token"]})

    s.close()

    return web.json_response({"error": "Please provide correct Token."}, status=400)


async def validate_credentials(request: web.Request):
    """ Login User """
    credential_host = request.app["config"].credential_service.host
    credential_port = request.app["config"].credential_service.port
    credential_path = request.app["config"].credential_service.path

    credential_url = URL(f"http://{credential_host}:{credential_port}{credential_path}/validate")

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(headers=headers, method="POST", url=credential_url, data=data) as response:
                resp = await _clone_response(response)

                if response.status == 200:
                    resp_json = json.loads(resp.text)
                    credential_uuid = resp_json["credential_uuid"]
                    token = await get_credential_token(request, credential_uuid)
                    return web.json_response({"token": token}), token

                return resp, None
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def validate_token(request: web.Request) -> web.Response:
    """ Get User by Session token """
    return await get_user_from_token(request, AuthType.TOKEN)


async def get_credential_token(request: web.Request, credential_uuid: str):
    """ Get User by Session token """
    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

    r = (
        s.query(Authentication)
        .filter(Authentication.auth_uuid == credential_uuid)
        .order_by(desc(Authentication.updated_at))
        .first()
    )
    s.close()

    return r.token


async def get_user_from_token(request: web.Request, auth_type: AuthType = AuthType.TOKEN) -> web.Response:
    """ Get User by Session token """
    try:
        token = await _get_authorization_token(request)
    except Exception:
        return web.json_response({"error": "Please provide Token."}, status=400)

    return await get_token_user(request, token, auth_type)


async def get_token_user(request: web.Request, token: str, auth_type: AuthType):
    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

    r = s.query(Authentication).filter(Authentication.token == token).order_by(desc(Authentication.updated_at)).first()
    s.close()

    if r is not None:
        if r.auth_type == auth_type.value:
            user_call_response = await get_user_call(request, r.user_uuid)
            return user_call_response

    return web.HTTPBadRequest(text="Please provide correct Token.")


async def get_user_from_credentials(request: web.Request) -> web.Response:
    resp, token = await validate_credentials(request)

    if resp.status == 200:
        return await get_token_user(request, token, AuthType.CREDENTIAL)
    return resp


async def token_service_call(request: web.Request, data: dict):
    token_host = request.app["config"].token_service.host
    token_port = request.app["config"].token_service.port
    token_path = request.app["config"].token_service.path

    token_url = URL(f"http://{token_host}:{token_port}{token_path}/validate")

    try:
        async with ClientSession() as session:
            async with session.request(method="POST", url=token_url, data=json.dumps(data)) as response:
                resp = await _clone_response(response)

                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def get_user_call(request: web.Request, user_uuid: str) -> web.Response:
    """ Get User by Session token """
    user_host = request.app["config"].user_service.host
    user_port = request.app["config"].user_service.port
    user_path = request.app["config"].user_service.path

    credential_url = URL(f"http://{user_host}:{user_port}{user_path}/{user_uuid}")

    headers = request.headers.copy()
    data = await request.read()

    try:
        async with ClientSession() as session:
            async with session.request(headers=headers, method="GET", url=credential_url, data=data) as response:
                resp = await _clone_response(response)
                return resp
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


async def create_credentials_call(request: web.Request, data: dict, method: str = "POST") -> web.Response:
    """ Orchestrate discovery and microservice call """
    credential_host = request.app["config"].credential_service.host
    credential_port = request.app["config"].credential_service.port
    credential_path = request.app["config"].credential_service.path

    credential_url = URL(f"http://{credential_host}:{credential_port}{credential_path}")

    try:
        async with ClientSession() as session:
            async with session.request(method=method, url=credential_url, data=json.dumps(data)) as response:
                return await _clone_response(response)
    except ClientConnectorError:
        raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")


# noinspection PyMethodMayBeStatic
async def _clone_response(response: ClientResponse) -> web.Response:
    return web.Response(
        body=await response.read(), status=response.status, reason=response.reason, headers=response.headers,
    )


async def create_authentication(
    request: web.Request, token: str, user_id: str, user_uuid: str, auth_uuid: str, auth_type: AuthType
):
    """ Orchestrate discovery and microservice call """
    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

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
    s.add(credential)
    s.commit()

    s.close()

    return uuid


async def _get_authorization_token(request: web.Request):
    headers = request.headers
    if "Authorization" in headers and "Bearer" in headers["Authorization"]:
        parts = headers["Authorization"].split()
        if len(parts) == 2:
            return parts[1]
