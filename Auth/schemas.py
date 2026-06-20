from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
import re


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _validate_password_strength(value: str) -> str:
    """Shared rule: 8-128 chars, must include at least one letter and one digit,
    no leading/trailing whitespace."""
    if value.strip() != value:
        raise ValueError("password must not start or end with whitespace")
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ValueError("password must contain at least one letter and one digit")
    return value


class RegisterRequest(BaseModel):
    """Payload accepted by POST /register."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=32,
        description="3-32 chars, letters/digits/._-",
    )
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="At least 8 characters, mix of letters and digits recommended",
    )
    full_name: Optional[str] = Field(default=None, max_length=255)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        if not USERNAME_RE.fullmatch(value):
            raise ValueError(
                "username must be 3-32 characters of letters, digits, '.', '_' or '-'"
            )
        return value

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: str) -> str:
        return _validate_password_strength(value)


class LoginRequest(BaseModel):
    """Payload accepted by POST /login."""

    username: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access_token expiry


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class RegisterResponse(BaseModel):
    user: UserPublic
    tokens: TokenResponse


class VerifyUserRequest(BaseModel):
    token: Optional[str] = Field(
        default=None,
        description="Optional access token; Authorization header is preferred",
    )


class VerifyUserResponse(BaseModel):
    valid: bool
    user: UserPublic
    expires_at: datetime


class UpdateUserRequest(BaseModel):
    """Payload accepted by PATCH /me. All fields optional — only provided
    fields are updated."""

    email: Optional[EmailStr] = Field(
        default=None, description="New email (must be unique across users)"
    )
    full_name: Optional[str] = Field(default=None, max_length=255)

    @field_validator("full_name")
    @classmethod
    def _strip_full_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("full_name must not be blank")
        return cleaned

    @model_validator(mode="after")
    def _at_least_one_field(self):
        if self.email is None and self.full_name is None:
            raise ValueError("Provide at least one of: email, full_name")
        return self


class ChangePasswordRequest(BaseModel):
    """Payload accepted by POST /change-password."""

    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="At least 8 characters, mix of letters and digits",
    )

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: str) -> str:
        return _validate_password_strength(value)

    @model_validator(mode="after")
    def _passwords_must_differ(self):
        if self.current_password == self.new_password:
            raise ValueError("new_password must differ from current_password")
        return self


class MessageResponse(BaseModel):
    message: str