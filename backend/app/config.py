from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "TraceShield API"
    environment: str = "development"
    frontend_origin: str = "http://localhost:5173"
    mysql_url: str = ""
    secret_key: str = Field(default="trace-shield-super-secret-key-change-me", min_length=32)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
