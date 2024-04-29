from dataclasses import dataclass
from datetime import datetime, timedelta
from fastapi import Request
from fastapi_async_sqlalchemy import db
from uuid import UUID

from samsa.constants import COOKIE_NAME
from samsa.models import Session, User


@dataclass
class AuthenticationResult:
    session_id: UUID | None
    user: User | None
    session_invalid: bool


async def authenticate(request: Request) -> AuthenticationResult:
    session_cookie = request.cookies.get(COOKIE_NAME)
    if session_cookie is None:
        return AuthenticationResult(None, None, False)

    try:
        session_id, session_secret = session_cookie.split(":", 1)
    except ValueError:
        return AuthenticationResult(None, None, False)

    session = await db.session.get(Session, UUID(session_id))

    if session is None or not session_secret != session.secret.encode():
        return AuthenticationResult(None, None, True)

    if datetime.now() > session.expires:
        await db.session.delete(session)
        await db.session.commit()
        return AuthenticationResult(None, None, True)

    session.last_ip = request.client.host
    session.last_ua = request.headers.get("User-Agent")
    session.expires = datetime.now() + timedelta(days=7)
    await db.session.commit()

    return AuthenticationResult(session.id, await session.awaitable_attrs.user, False)
