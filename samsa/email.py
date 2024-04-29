import aiosmtplib
import logging
from email.message import EmailMessage
from typing import Any

from samsa.settings import settings

logger = logging.getLogger("uvicorn.error")



def join_emails(value: list[str] | str) -> str:
    if isinstance(value, list):
        return ', '.join(value)

    return value


async def send_email(message: EmailMessage) -> None:
    if settings.smtp is None:
        logger.info("SMTP is disabled, email sent to stderr")
        for header in message.keys():
            logger.info("%s: %s", header, message[header])
        logger.info("%s", message.get_content())
        return

    kwargs: dict[str, Any] = {}

    if settings.smtp.login is not None:
        kwargs["username"] = settings.smtp.login
        kwargs["password"] = settings.smtp.password

    await aiosmtplib.send(
        message,
        hostname=settings.smtp.host,
        port=settings.smtp.port,
        use_tls=settings.smtp.tls,
        start_tls=settings.smtp.starttls,
        local_hostname="nora",
        **kwargs
    )


async def send_text(
    emails: str | list[str],
    subject: str,
    text: str,
    *,
    additional_headers: dict[str, str] = {},
    send_from: str | None = None
) -> None:
    message = EmailMessage()

    message["From"] = send_from or settings.smtp.default_from
    message["To"] = join_emails(emails)
    message["Subject"] = subject

    for key, value in additional_headers.items():
        message[key] = value

    message.set_content(text)

    return await send_email(message)
