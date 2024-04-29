import logging
import secrets
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from fastapi_async_sqlalchemy import db

from samsa.auth import authenticate
from samsa.constants import COOKIE_NAME, TOKEN_COOKIE_NAME, COOKIE_OPTIONS
from samsa.models import Session, Token
from samsa.settings import settings
from samsa.templates import templates

logger = logging.getLogger("uvicorn.error")
router = APIRouter()


@router.get("/authorize")
async def authorize(request: Request, scope: int | None = 0) -> Response:
    authentication = await authenticate(request)

    if authentication.user is None:
        response = Response(status_code=401, headers={"X-Rejected-By": "nora"})
    elif authentication.user.scope > 0 and (scope & authentication.user.scope) != scope:
        logger.info("User %s does not have sufficient scope %s", authentication.user.id, scope)
        response = Response(status_code=401, headers={"X-Rejected-By": "nora"})
    else:
        response = Response(status_code=200, headers={"X-Nora-Id": str(authentication.user.id)})

    if authentication.session_invalid:
        response.delete_cookie(COOKIE_NAME, secure=True, httponly=True, samesite="none")

    return response


@router.get("/login")
async def login_redirect(request: Request, next: str) -> Response:
    if not next.startswith("/") or next.startswith("//"):
        logger.info("Malformed next url in sso-login: %s", next)
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    authentication = await authenticate(request)
    if authentication.user is not None:
        return RedirectResponse(next, status_code=303)

    origin = request.url.netloc
    if origin not in settings.allowed_domains:
        logger.info("Disallowed origin in sso-login: %s", origin)
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    token_state = secrets.token_urlsafe(32)
    token = Token(state=token_state, origin=origin, source_path=next)
    db.session.add(token)
    await db.session.commit()

    response = RedirectResponse(f"//{settings.main_domain}/sso?token_id={token.id}", status_code=303)

    response.set_cookie(
        TOKEN_COOKIE_NAME, token_state,
        max_age=24*60*60,
        secure=True, httponly=True, samesite="none"
    )

    return response


@router.get("/token")
async def token(request: Request, token_id: str) -> Response:
    token_state = request.cookies.get(TOKEN_COOKIE_NAME)
    if token_state is None:
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    token = await db.session.get(Token, token_id)
    if token is None or token.session_id is None or token.expired() or token_state != token.state:
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    session: Session = await token.awaitable_attrs.session
    if token.origin != request.url.netloc or session is None:
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    response = RedirectResponse(token.source_path, status_code=303)
    response.delete_cookie(TOKEN_COOKIE_NAME, secure=True, httponly=True, samesite="none")
    response.set_cookie(
        COOKIE_NAME,
        session.cookie,
        max_age=10*365*24*60*60,
        **COOKIE_OPTIONS
    )

    await db.session.delete(token)

    return response


@router.get("/logout")
async def logout(request: Request) -> Response:
    authentication = await authenticate(request)

    if authentication.session_id is not None:
        session = await db.session.get(Session, authentication.session_id)
        if session is not None:
            await db.session.delete(session)

    response = templates.TemplateResponse(
        request,
        "logged_out.html",
        {}
    )

    response.delete_cookie(COOKIE_NAME, **COOKIE_OPTIONS)

    return response
