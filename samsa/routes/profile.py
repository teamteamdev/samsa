import logging
import webauthn
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi_async_sqlalchemy import db
from typing import Sequence
from uuid import UUID
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    AttestationConveyancePreference,
    ResidentKeyRequirement,
    UserVerificationRequirement
)

from samsa.auth import authenticate
from samsa.constants import CHALLENGE_COOKIE_NAME
from samsa.models import Passkey, PasskeyChallenge
from samsa.settings import settings
from samsa.templates import templates

logger = logging.getLogger("uvicorn.error")
router = APIRouter()


@router.get("/passkey/enroll", response_model=PublicKeyCredentialCreationOptions)
async def start_enroll_passkey(request: Request):
    authentication = await authenticate(request)

    if authentication.user is None:
        raise HTTPException(403, "Вы не авторизованы")

    enrolled_passkeys: Sequence[Passkey] = await authentication.user.awaitable_attrs.passkeys

    public_key = webauthn.generate_registration_options(
        rp_id=settings.main_domain.split(":")[0],
        rp_name="[team Team] ИС САМСА",
        user_id=str(authentication.user.id).encode(),
        user_name=authentication.user.email,
        user_display_name=authentication.user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        attestation=AttestationConveyancePreference.DIRECT,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=passkey.credential_id)
            for passkey in enrolled_passkeys
        ]
    )

    challenge = PasskeyChallenge(
        user_id=authentication.user.id,
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
        secure=True, httponly=True, samesite="none"
    )

    return response


@router.post("/passkey/enroll")
async def enroll_passkey(request: Request):
    authentication = await authenticate(request)

    body = await request.json()

    if authentication.user is None:
        raise HTTPException(403, "Вы не авторизованы.")

    challenge_id = request.cookies.get(CHALLENGE_COOKIE_NAME)
    if challenge_id is None:
        logger.info("Challenge ID is unknown")
        raise HTTPException(400, "Сессия недействительна. Попробуйте ещё раз.")

    challenge = await db.session.get(PasskeyChallenge, UUID(challenge_id))
    if challenge is None or challenge.user_id != authentication.user.id or challenge.expired():
        logger.info("Challenge %s does not exist or foreign or expired", challenge_id)
        raise HTTPException(400, "Сессия недействительна. Попробуйте ещё раз.")

    try:
        registration = webauthn.verify_registration_response(
            credential=body,
            expected_challenge=challenge.challenge,
            expected_rp_id=settings.main_domain.split(":")[0],
            expected_origin=f"{request.url.scheme}://{settings.main_domain}"
        )
    except InvalidRegistrationResponse as exc:
        logger.info("Could not verify token: %s", exc)
        raise HTTPException(400, "Не удалось верифицировать ваш ключ.")

    passkey = Passkey(
        user_id=authentication.user.id,
        credential_id=registration.credential_id,
        public_key=registration.credential_public_key,
        sign_count=registration.sign_count,
        aaguid=registration.aaguid
    )
    db.session.add(passkey)
    await db.session.delete(challenge)
    await db.session.commit()

    response = Response(status_code=200)
    response.delete_cookie(
        CHALLENGE_COOKIE_NAME,
        secure=True, httponly=True, samesite="none"
    )

    return response


@router.get("/")
async def profile(request: Request) -> Response:
    authentication = await authenticate(request)

    if authentication.user is None:
        return RedirectResponse("/.sso/login?next=/", status_code=303)

    user = authentication.user

    await user.awaitable_attrs.sessions
    await user.awaitable_attrs.passkeys

    return templates.TemplateResponse(
        request,
        "user.html",
        {"user": user}
    )
