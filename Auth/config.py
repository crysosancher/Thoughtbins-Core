"""Centralized configuration loaded from environment variables / .env file."""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Annotated, List

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Load .env once, at import time. Safe to call repeatedly.
load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- App ----
    app_name: str = "Auth API"
    app_env: str = "development"
    log_level: str = "INFO"
    # NoDecode keeps env values as raw strings; the validator below splits CSV.
    cors_origins: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["*"]
    )

    # ---- Database ----
    # NOTE: the '@' in the password is URL-encoded as %40 so the connection
    # parser doesn't split on it. Encode any other special chars too:
    #   : -> %3A,  / -> %2F,  # -> %23,  ? -> %3F,  % -> %25,  [ ] -> %5B %5D
    database_url: str = Field(
        default="postgresql://admin:ThoughtBins%402025@72.61.179.20:5432/ayurveda",
        description="SQLAlchemy connection string",
    )
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_echo: bool = False

    # ---- JWT ----
    jwt_secret_key: str = "change-me-access-secret"
    jwt_refresh_secret_key: str = "change-me-refresh-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # ---- Bcrypt ----
    bcrypt_rounds: int = 12

    # ---- Rate limiting ----
    rate_limit_default: str = "100/minute"
    rate_limit_register: str = "10/minute"
    rate_limit_login: str = "10/minute"
    rate_limit_verify: str = "60/minute"

    # ---- Trusted hosts ----
    trusted_hosts: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["*"]
    )
    
    # ---- CORS allowed methods ----
    cors_methods: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )

    @field_validator("cors_origins", "trusted_hosts", mode="before")
    @classmethod
    def _split_csv(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("bcrypt_rounds")
    @classmethod
    def _bcrypt_rounds_bounds(cls, v: int) -> int:
        if v < 4 or v > 16:
            raise ValueError("bcrypt_rounds must be between 4 and 16")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    # Quiet noisy libraries in production-ish environments.
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)