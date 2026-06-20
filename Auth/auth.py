from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import User

# ---- Configuration -----------------------------------------------------------

JWT_SECRET_KEY = settings.jwt_secret_key
JWT_REFRESH_SECRET_KEY = settings.jwt_refresh_secret_key
JWT_ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = settings.refresh_token_expire_days
BCRYPT_ROUNDS = settings.bcrypt_rounds

bearer_scheme = HTTPBearer(auto_error=False)

# ---- Password hashing --------------------------------------------------------


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password with bcrypt (configurable cost factor)."""
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time bcrypt verification."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False

# ---- Token helpers -----------------------------------------------------------


def _build_token(
    subject: str,
    secret: str,
    expires_delta: timedelta,
    token_type: str,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> Tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": token_type,
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
    return token, expire


def create_access_token(
    user: User, extra_claims: Optional[Dict[str, Any]] = None
) -> Tuple[str, datetime]:
    return _build_token(
        subject=str(user.id),
        secret=JWT_SECRET_KEY,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
        extra_claims={
            "username": user.username,
            "email": user.email,
            "is_verified": user.is_verified,
            **(extra_claims or {}),
        },
    )


def create_refresh_token(user: User) -> Tuple[str, datetime]:
    return _build_token(
        subject=str(user.id),
        secret=JWT_REFRESH_SECRET_KEY,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )


def create_token_pair(user: User) -> Tuple[str, str, int]:
    """Return (access_token, refresh_token, access_expires_in_seconds)."""
    access_token, access_exp = create_access_token(user)
    refresh_token, _ = create_refresh_token(user)
    expires_in = max(int((access_exp - datetime.now(timezone.utc)).total_seconds()), 0)
    return access_token, refresh_token, expires_in


def decode_token(token: str, expected_type: str, secret: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token type mismatch",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# ---- Dependencies ------------------------------------------------------------


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency: extract bearer token, return the authenticated User."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials, "access", JWT_SECRET_KEY)

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        ) from exc

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    return user