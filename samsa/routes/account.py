import logging
import secrets
import webauthn
from fastapi import APIRouter, HTTPException, Request, Response, Form
from fastapi.responses import RedirectResponse
from fastapi_async_sqlalchemy import db
from sqlalchemy import select
from typing import Annotated
from uuid import UUID, uuid4
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import (
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement
)

from samsa.auth import authenticate
from samsa.constants import CHALLENGE_COOKIE_NAME, CONFIRMATION_COOKIE_NAME, COOKIE_NAME, COOKIE_OPTIONS
from samsa.email import send_text
from samsa.models import Confirmation, Passkey, PasskeyChallenge, Session, Token, User
from samsa.settings import settings
from samsa.templates import templates

logger = logging.getLogger("uvicorn.error")
router = APIRouter()


def authorize(token: Token, session_id: UUID) -> Response:
    if token.origin not in settings.allowed_domains:
        logger.info("Disallowed origin while finalizing authorization: %s", token.origin)
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    token.session_id = session_id
    return RedirectResponse(f"//{token.origin}/.sso/token?token_id={token.id}", status_code=303)


@router.get("/")
async def sso_page(request: Request, token_id: str) -> Response:
    token = await db.session.get(Token, UUID(token_id))
    if token is None or token.expired():
        logger.info("Token %s does not exist or expired", token_id)
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    authentication = await authenticate(request)

    if authentication.session_id is not None:
        return authorize(token, authentication.session_id)

    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": next, "token_id": token_id}
    )


@router.post("/")
async def sso(token_id: str, email: Annotated[str, Form()]):
    token = await db.session.get(Token, UUID(token_id))
    if token is None or token.expired():
        logger.info("Token %s does not exist or expired", token_id)
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    user_query = select(User).where(User.email == email)
    user: User | None = await db.session.scalar(user_query)

    if user is not None:
        confirmation = Confirmation(
            token_id=token.id,
            user_id=user.id,
            code=secrets.token_urlsafe(32)
        )
        db.session.add(confirmation)
        await db.session.commit()

        confirmation_cookie = str(confirmation.id)

        await send_text(
            user.email,
            "САМСА [team Team]",
            f"""Добридень!

Системой автоматической меж-сервисной аутентификации команды [team Team] был
выпущен авторизационный токен для вашего аккаунта. Для прохождения авторизации
вам необходимо перейти по следующей ссылке:

https://{settings.main_domain}/sso/finish/{confirmation.code}

ПРЕДУПРЕЖДЕНИЕ О ПРАКТИКАХ РЫБНОЙ ЛОВЛИ

Не переходите по ссылке, если вы её не запрашивали: доступ в систему будет
предоставлен именно тому клиентскому устройству, из которого был инициирован
процесс аутентификации.

Такие дела.
""",
            send_from="sso@teamteam.dev"
        )
    else:
        # We don't want to disclose if chosen email is really registered,
        # so we fake the cookie.
        confirmation_cookie = uuid4()

    response = RedirectResponse("/sso/confirmation", status_code=303)

    response.set_cookie(
        CONFIRMATION_COOKIE_NAME, confirmation_cookie,
        max_age=24*60*60,
        **COOKIE_OPTIONS
    )

    return response


async def get_confirmation(code: str) -> Confirmation:
    confirmation_query = select(Confirmation).where(Confirmation.code == code)
    confirmation: Confirmation | None = await db.session.scalar(confirmation_query)

    if confirmation is None:
        raise HTTPException(400, "Некорректный код подтверждения.")

    if confirmation.expired():
        raise HTTPException(400, "Ссылка устарела. Запросите новую.")

    return confirmation


async def create_session(user_id: int) -> Session:
    session = Session(
        secret=secrets.token_urlsafe(32),
        user_id=user_id
    )
    db.session.add(session)
    await db.session.commit()

    return session


async def sso_finish(confirmation: Confirmation) -> Response:
    session = await create_session(confirmation.user_id)

    token = await confirmation.awaitable_attrs.token
    token.session_id = session.id

    await db.session.delete(confirmation)
    await db.session.commit()

    response = authorize(token, session.id)

    response.set_cookie(
        COOKIE_NAME,
        session.cookie,
        max_age=10*365*24*60*60,
        **COOKIE_OPTIONS
    )
    response.delete_cookie(CONFIRMATION_COOKIE_NAME, **COOKIE_OPTIONS)

    return response


@router.get("/finish/{code}")
async def sso_finish_get(request: Request, code: str) -> Response:
    confirmation = await get_confirmation(code)

    saved_confirmation_id = request.cookies.get(CONFIRMATION_COOKIE_NAME)

    if saved_confirmation_id is None or saved_confirmation_id != str(confirmation.id):
        return templates.TemplateResponse(
            request,
            "confirm_another_browser.html",
            {"code": code, "id": confirmation.id}
        )

    return await sso_finish(confirmation)


@router.post("/finish")
async def sso_finish_post(request: Request, confirmation_id: Annotated[str, Form()], code: Annotated[str, Form()]) -> Response:
    confirmation = await get_confirmation(code)

    if str(confirmation.id) != confirmation_id:
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    confirmation.confirmed = True
    await db.session.commit()

    return templates.TemplateResponse(
        request,
        "confirmed.html"
    )


@router.get("/confirmation")
async def confirmation_wait(request: Request) -> Response:
    saved_confirmation_id = request.cookies.get(CONFIRMATION_COOKIE_NAME)
    if saved_confirmation_id is None:
        logger.info("User did not provide confirmation cookie")
        raise HTTPException(400, "Ошибка авторизации. Попробуйте ещё раз.")

    confirmation = await db.session.get(Confirmation, UUID(saved_confirmation_id))

    if confirmation is not None and confirmation.confirmed:
        return await sso_finish(confirmation)

    if confirmation is not None and confirmation.expired():
        raise HTTPException(400, "Ссылка устарела. Запросите новую.")

    return templates.TemplateResponse(
        request,
        "check_email.html"
    )


@router.get("/passkey", response_model=PublicKeyCredentialRequestOptions)
async def start_verify_passkey():
    public_key = webauthn.generate_authentication_options(
        rp_id=settings.main_domain.split(":")[0],
        user_verification=UserVerificationRequirement.PREFERRED
    )

    challenge = PasskeyChallenge(
        challenge=public_key.challenge
    )
    db.session.add(challenge)
    await db.session.commit()

    response = Response(
        webauthn.options_to_json(public_key),
        headers={"Content-Type": "application/json"}
    )

    response.set_cookie(
        CHALLENGE_COOKIE_NAME, str(challenge.id),
        max_age=10*60,
        **COOKIE_OPTIONS
    )

    return response


@router.post("/passkey")
async def verify_passkey(request: Request):
    body = await request.json()

    challenge_id = request.cookies.get(CHALLENGE_COOKIE_NAME)
    if challenge_id is None:
        logger.info("Challenge ID is unknown")
        raise HTTPException(400, "Сессия недействительна. Попробуйте ещё раз.")

    challenge = await db.session.get(PasskeyChallenge, UUID(challenge_id))
    if challenge is None or challenge.user is not None or challenge.expired():
        logger.info("Challenge does not exist or expired, %s", challenge)
        raise HTTPException(400, "Сессия недействительна. Попробуйте ещё раз.")

    raw_id = webauthn.base64url_to_bytes(body["id"])
    passkey = await db.session.scalar(select(Passkey).where(Passkey.credential_id == raw_id))

    if passkey is None:
        logger.info("Credential %s does not exist or expired", body["id"])
        raise HTTPException(403, "Ключ не зарегистрирован. Войдите по почте и привяжите токен.")

    try:
        authentication = webauthn.verify_authentication_response(
            credential=body,
            expected_challenge=challenge.challenge,
            expected_rp_id=settings.main_domain.split(":")[0],
            expected_origin=f"{request.url.scheme}://{settings.main_domain}",
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count
        )
    except InvalidAuthenticationResponse as exc:
        logger.info("Could not verify token: %s", exc)
        raise HTTPException(400, "Не удалось верифицировать ключ.")


    passkey.sign_count = authentication.new_sign_count
    await db.session.delete(challenge)
    await db.session.commit()

    session = await create_session(passkey.user_id)

    response = Response(status_code=200)
    response.set_cookie(
        COOKIE_NAME,
        session.cookie,
        max_age=10*365*24*60*60,
        **COOKIE_OPTIONS
    )
    response.delete_cookie(CHALLENGE_COOKIE_NAME, **COOKIE_OPTIONS)

    return response
