import datetime as _dt
import logging
import time
import uuid

import jwt as _jwt
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from auth import (
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    create_token_pair,
    get_current_user,
    hash_password,
    verify_password,
)
from config import configure_logging, settings
from database import Base, engine, get_db
from models import User
from schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    UpdateUserRequest,
    UserPublic,
    VerifyUserRequest,
    VerifyUserResponse,
)

configure_logging()
logger = logging.getLogger("auth_api")

# ---- Rate limiter ------------------------------------------------------------
# In-memory storage is fine for single-instance dev. For multi-instance prod,
# point storage_uri at Redis (slowapi>=0.1.9 supports this).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit_default],
    # headers_enabled=False because slowapi's async wrapper requires every
    # rate-limited route to declare `response: Response` so it can attach
    # X-RateLimit-* headers, and it crashes with a hard exception otherwise.
    # The cost of disabling is no X-RateLimit-* headers on responses; rate
    # limiting itself still works and RateLimitExceeded still raises.
    headers_enabled=False,
)


# ---- App setup ---------------------------------------------------------------

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="JWT-based auth API with /register, /login and /verify-user.",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# NOTE: SlowAPIMiddleware is intentionally NOT added — it's a BaseHTTPMiddleware
# subclass and inherits the `response must be an instance of starlette.responses.Response`
# bug when routes raise into a custom Exception handler. The @limiter.limit
# decorators on each route do the actual limiting, and with headers_enabled=True
# the X-RateLimit-* headers are injected by the decorator itself.

# IMPORTANT: Add TrustedHostMiddleware FIRST so CORS runs first (middleware stack is reversed)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    max_age=86400,
)


# ---- Middleware: request id, timing, security headers -----------------------


SECURITY_HEADERS = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    (b"cache-control", b"no-store"),
)


class SecurityHeadersAndLoggingMiddleware:
    """
    Pure ASGI middleware — avoids the @app.middleware("http") decorator
    (BaseHTTPMiddleware) because that wrapper breaks when a route raises
    an exception that goes through a custom Exception handler, surfacing
    as `parameter 'response' must be an instance of starlette.responses.Response`.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Pick up an inbound request id, or mint one.
        request_id: str | None = None
        for name, value in scope.get("headers", []):
            if name == b"x-request-id":
                request_id = value.decode("latin-1", errors="replace")
                break
        if not request_id:
            request_id = uuid.uuid4().hex

        method = scope.get("method", "?")
        path = scope.get("path", "?")
        start = time.perf_counter()
        status_code = 500  # default until http.response.start arrives

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                # Merge security headers, preserving any the app already set.
                merged: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                seen: set[bytes] = {k.lower() for k, _ in merged}
                for k, v in SECURITY_HEADERS:
                    if k not in seen:
                        merged.append((k, v))
                merged.append((b"x-request-id", request_id.encode("latin-1")))
                message["headers"] = merged
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "%s %s -> %s in %.1fms rid=%s",
                method,
                path,
                status_code,
                elapsed_ms,
                request_id,
            )


app.add_middleware(SecurityHeadersAndLoggingMiddleware)


# ---- Exception handlers ------------------------------------------------------


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(_: Request, exc: SQLAlchemyError):
    logger.exception("Database error: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Database error",
            "type": exc.__class__.__name__,
            "message": str(exc.orig) if hasattr(exc, "orig") and exc.orig else str(exc),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Last-resort handler so the actual traceback always lands in the log
    # AND in the response body (so curl clients can see it too).
    if isinstance(exc, HTTPException):
        # Pass HTTPException through to FastAPI's built-in handler so 401,
        # 409, 422 etc. are never masked as 500s.
        return await http_exception_handler(request, exc)
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "type": exc.__class__.__name__,
            "message": str(exc),
        },
    )


# ---- Lifecycle ---------------------------------------------------------------


@app.on_event("startup")
def on_startup() -> None:
    # Sanity-check the connection string up front so typos fail loudly,
    # not as a cryptic psycopg2 host error from inside the DDL step.
    from urllib.parse import urlparse

    parsed = urlparse(settings.database_url)
    if not parsed.hostname:
        raise RuntimeError(
            f"DATABASE_URL is malformed (hostname is empty). "
            f"Got: {settings.database_url!r}"
        )
    logger.info(
        "Connecting to Postgres host=%s port=%s db=%s",
        parsed.hostname,
        parsed.port,
        parsed.path.lstrip("/"),
    )
    try:
        Base.metadata.create_all(bind=engine)
        logger.info(
            "Startup OK. env=%s db_pool=%s/%s",
            settings.app_env,
            settings.db_pool_size,
            settings.db_max_overflow,
        )
    except OperationalError as exc:
        logger.error("Cannot reach database on startup: %s", exc)
        raise


# ---- Helpers -----------------------------------------------------------------


def _user_to_public(user: User) -> UserPublic:
    return UserPublic.model_validate(user)


def _token_expiry(token: str) -> _dt.datetime:
    try:
        decoded = _jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except _jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc
    exp = decoded.get("exp")
    if not exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing exp claim",
        )
    return _dt.datetime.fromtimestamp(int(exp), tz=_dt.timezone.utc)


# ---- Routes ------------------------------------------------------------------


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Lightweight liveness probe. No rate limit, no DB call."""
    return {"status": "ok", "env": settings.app_env}


@app.options("/register")
async def register_options():
    """CORS preflight handler for register endpoint."""
    return JSONResponse(status_code=200)


@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
)
@limiter.limit(settings.rate_limit_register)
async def register(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    """Create a new user, hash their password, and return tokens."""
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already in use",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already in use",
        )

    db.refresh(user)
    logger.info("Registered user id=%s username=%s", user.id, user.username)

    access_token, refresh_token, expires_in = create_token_pair(user)
    return RegisterResponse(
        user=_user_to_public(user),
        tokens=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
        ),
    )


@app.options("/login")
async def login_options():
    """CORS preflight handler for login endpoint."""
    return JSONResponse(status_code=200)


@app.post(
    "/login",
    response_model=TokenResponse,
    tags=["auth"],
)
@limiter.limit(settings.rate_limit_login)
async def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate by username + password and return new tokens."""
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.hashed_password):
        # Same message in both branches prevents user-enumeration.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    access_token, refresh_token, expires_in = create_token_pair(user)
    logger.info("User id=%s username=%s logged in", user.id, user.username)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )


@app.options("/verify-user")
async def verify_user_options():
    """CORS preflight handler for verify-user endpoint."""
    return JSONResponse(status_code=200)


@app.post(
    "/verify-user",
    response_model=VerifyUserResponse,
    tags=["auth"],
)
@limiter.limit(settings.rate_limit_verify)
async def verify_user(
    request: Request,
    payload: Optional[VerifyUserRequest] = None,
    db: Session = Depends(get_db),
) -> VerifyUserResponse:
    """
    Validate a JWT and return the associated user.

    The token may be supplied either via the Authorization: Bearer header
    or in the JSON body (`token` field). Header takes precedence. The body
    is optional — sending no body at all is allowed.
    """
    payload = payload or VerifyUserRequest()
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    token: str | None = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token and payload.token:
        token = payload.token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from fastapi.security import HTTPAuthorizationCredentials

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    user = get_current_user(credentials=credentials, db=db)

    expires_at = _token_expiry(token)
    return VerifyUserResponse(valid=True, user=_user_to_public(user), expires_at=expires_at)


@app.options("/me")
async def update_me_options():
    """CORS preflight handler for /me endpoint."""
    return JSONResponse(status_code=200)


@app.patch(
    "/me",
    response_model=UserPublic,
    tags=["auth"],
)
@limiter.limit(settings.rate_limit_default)
async def update_me(
    request: Request,
    payload: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserPublic:
    """Update the authenticated user's own profile fields.

    All fields are optional; only the ones you send are updated. Username is
    intentionally NOT updatable here — it would invalidate any cached JWTs
    keyed on the old value. To rename, contact support / add a separate flow.
    """
    changed_fields: list[str] = []

    if payload.email is not None and payload.email != current_user.email:
        collision = (
            db.query(User)
            .filter(User.email == payload.email, User.id != current_user.id)
            .first()
        )
        if collision:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use",
            )
        current_user.email = payload.email
        changed_fields.append("email")

    if payload.full_name is not None and payload.full_name != current_user.full_name:
        current_user.full_name = payload.full_name
        changed_fields.append("full_name")

    if not changed_fields:
        # Nothing actually changed — return current state without a DB write.
        logger.info("update_me noop user_id=%s", current_user.id)
        return _user_to_public(current_user)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already in use",
        )

    db.refresh(current_user)
    logger.info(
        "update_me user_id=%s fields=%s", current_user.id, ",".join(changed_fields)
    )
    return _user_to_public(current_user)


@app.options("/change-password")
async def change_password_options():
    """CORS preflight handler for change-password endpoint."""
    return JSONResponse(status_code=200)


@app.post(
    "/change-password",
    response_model=MessageResponse,
    tags=["auth"],
)
@limiter.limit(settings.rate_limit_login)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Change the authenticated user's password.

    Requires the current password to prevent account takeover via a stolen
    device that still has a valid session token.
    """
    if not verify_password(payload.current_password, current_user.hashed_password):
        # Same generic message as /login to avoid disclosing account state.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    current_user.hashed_password = hash_password(payload.new_password)
    db.commit()
    logger.info("change_password user_id=%s ok", current_user.id)
    return MessageResponse(message="Password updated successfully")