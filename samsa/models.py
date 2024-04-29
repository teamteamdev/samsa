from datetime import datetime, timedelta, timezone
from sqlalchemy import ForeignKey
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func, text
from uuid import UUID

class Base(AsyncAttrs, DeclarativeBase):
    pass


class User(Base):
    """The user in system.

    scope - bitmask of provided scopes, 0 to disable any checks
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    scope: Mapped[int] = mapped_column(server_default="0")
    created: Mapped[datetime] = mapped_column(server_default=func.now())

    sessions: Mapped[list["Session"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    confirmations: Mapped[list["Confirmation"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    passkeys: Mapped[list["Passkey"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    passkey_challenges: Mapped[list["PasskeyChallenge"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    """Active authorization session."""
    __tablename__ = "sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.uuid_generate_v4())
    secret: Mapped[str]
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created: Mapped[datetime] = mapped_column(server_default=func.now())
    expires: Mapped[datetime] = mapped_column(server_default=text("now() + interval '7 days'"))
    last_ip: Mapped[str | None]
    last_ua: Mapped[str | None]

    user: Mapped["User"] = relationship(back_populates="sessions")
    tokens: Mapped[list["Token"]] = relationship(back_populates="session", cascade="all, delete-orphan")

    @property
    def cookie(self):
        return f"{self.id}:{self.secret}"


class Token(Base):
    """Temporary session to be replaced for [Session]. Lifetime is 24 hours."""
    __tablename__ = "tokens"

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.uuid_generate_v4())
    state: Mapped[str]
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"))
    origin: Mapped[str]
    source_path: Mapped[str]
    created: Mapped[datetime] = mapped_column(server_default=func.now())

    session: Mapped["Session | None"] = relationship(back_populates="tokens")
    confirmations: Mapped[list["Confirmation"]] = relationship(back_populates="token", cascade="all, delete-orphan")

    def expired(self) -> bool:
        return self.created.replace(tzinfo=timezone.utc) < datetime.now(tz=timezone.utc) - timedelta(days=1)


class Confirmation(Base):
    """E-mail confirmation code. Lifetime is 24 hours."""
    __tablename__ = "confirmations"

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.uuid_generate_v4())
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    token_id: Mapped[int] = mapped_column(ForeignKey("tokens.id"))
    code: Mapped[str]
    confirmed: Mapped[bool] = mapped_column(server_default=text("false"))
    created: Mapped[datetime] = mapped_column(server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="confirmations")
    token: Mapped["Token"] = relationship(back_populates="confirmations")

    def expired(self) -> bool:
        return self.created.replace(tzinfo=timezone.utc) < datetime.now(tz=timezone.utc) - timedelta(days=1)


class Passkey(Base):
    """Public key for passkey."""
    __tablename__ = "passkeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    aaguid: Mapped[UUID]
    credential_id: Mapped[bytes]
    public_key: Mapped[bytes]
    sign_count: Mapped[int]

    created: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="passkeys")


class PasskeyChallenge(Base):
    """Challenge for registration or authentication with passkey."""
    __tablename__ = "passkey_challenges"

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.uuid_generate_v4())
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    challenge: Mapped[bytes]
    created: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())

    user: Mapped["User | None"] = relationship(back_populates="passkey_challenges")

    def expired(self) -> bool:
        return self.created.replace(tzinfo=timezone.utc) < datetime.now(tz=timezone.utc) - timedelta(hours=1)
