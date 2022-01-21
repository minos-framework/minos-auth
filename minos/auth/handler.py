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

        if "password" not in content:
            return web.HTTPBadRequest(text="Wrong data. Provide password.")
    except Exception:
        return web.HTTPBadRequest(text="Wrong data. Provide password.")

    user_creation = await create_user_service_call(request)

    if user_creation.status == 200:
        resp_json = json.loads(user_creation.text)
        user_uuid = resp_json["uuid"]
        data = {"user_uuid": user_uuid, "username": content["email"], "password": content["password"]}

        credentials_response = await create_credentials_call(request, data)

        if credentials_response.status == 200:
            resp_json_cred = json.loads(credentials_response.text)
            credential_uuid = resp_json_cred["credential"]
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

        if "password" not in content:
            return web.HTTPBadRequest(text="Wrong data. Provide password.")
    except Exception:
        return web.HTTPBadRequest(text="Wrong data. Provide password.")

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
                AuthType.CREDENTIAL.value,
            )
        else:
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


async def login(request: web.Request) -> web.Response:
    """ Login User """
    resp, token = await validate_credentials(request)
    return resp


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
            async with session.request(
                headers=headers, method=request.method, url=credential_url, data=data
            ) as response:
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
    return await get_user_by_token(request)


async def get_credential_token(request: web.Request, credential_uuid: str):
    """ Get User by Session token """
    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

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

    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

    r = s.query(Authentication).filter(Authentication.token == content["token"]).first()
    s.close()

    if r.auth_type == AuthType.TOKEN:
        token_response = await token_service_call(request)
        if token_response.status != 200:
            return token_response

    if r is not None:
        return await get_user_call(request, r.user_uuid)
    return web.HTTPBadRequest(text="Please provide correct Token.")


async def token_service_call(request: web.Request):
    token_host = request.app["config"].token_service.host
    token_port = request.app["config"].token_service.port
    token_path = request.app["config"].token_service.path

    credential_url = URL(f"http://{token_host}:{token_port}{token_path}/validate")

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

                if response.status == 200 and request.method == "POST" and request.path == "/auth/credentials":
                    resp_json = json.loads(resp.text)
                    credential_uuid = resp_json["credential"]
                    auth_uuid = await create_authentication(request, "", "", credential_uuid, AuthType.CREDENTIAL.value)
                    return web.json_response({"authentication": str(auth_uuid)})

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


async def create_token(request: web.Request) -> web.Response:
    """ Orchestrate discovery and microservice call """
    resp, token = await validate_credentials(request)

    if token is None:
        return resp

    session = sessionmaker(bind=request.app["db_engine"])

    s = session()

    r = s.query(Authentication).filter(Authentication.token == token).first()
    s.close()

    if r is not None:
        user_id = r.user_id
        user_uuid = r.user_uuid

        token_host = request.app["config"].token_service.host
        token_port = request.app["config"].token_service.port
        token_path = request.app["config"].token_service.path

        credential_url = URL(f"http://{token_host}:{token_port}{token_path}")

        headers = request.headers.copy()
        data = await request.read()

        try:
            async with ClientSession() as session:
                async with session.request(headers=headers, method="POST", url=credential_url, data=data) as response:
                    resp = await _clone_response(response)

                    if response.status == 200:
                        resp_json = json.loads(resp.text)

                        auth_uuid = await create_authentication(
                            request, resp_json["token"], user_id, user_uuid, resp_json["uuid"], AuthType.TOKEN.value
                        )
                        return web.json_response({"token": resp_json["token"]})

                    return resp
        except ClientConnectorError:
            raise web.HTTPServiceUnavailable(text="The requested endpoint is not available.")

    return web.json_response(status=500, text="Some error occurred.")


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

    try:
        s.add(credential)
        s.commit()
    except exc.IntegrityError:
        return web.json_response(status=500, text="Username is already taken.")

    s.close()

    return uuid
