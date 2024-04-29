from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class SMTPSettings(BaseModel):
    host: str = "localhost"
    port: int = 25
    login: str
    password: str | None = None
    default_from: str | None = None
    tls: bool = False
    starttls: bool = False


class Settings(BaseSettings):
    debug: bool = False
    database_url: str

    smtp: SMTPSettings | None = None

    main_domain: str
    allowed_domains: list[str]

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
