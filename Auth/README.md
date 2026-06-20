# Auth API (FastAPI + JWT + PostgreSQL)

REST API with `/register`, `/login`, `/verify-user`, `/me` (update profile) and
`/change-password`. JWT-based auth, Pydantic validation, bcrypt password hashing,
and per-IP rate limiting.

## Project layout

```
Auth/
├── .env.example         # Copy to .env and fill in real secrets
├── .gitignore
├── requirements.txt
├── setup.sh             # One-shot venv + install + .env bootstrap
├── config.py            # Settings loaded from env via pydantic-settings
├── database.py          # SQLAlchemy engine + session + Base
├── models.py            # SQLAlchemy ORM models (User)
├── schemas.py           # Pydantic request/response models (validation)
├── auth.py              # bcrypt + JWT helpers + get_current_user dep
└── main.py              # FastAPI app, routes, rate limiting, middleware
```

## Setup

> **macOS / Homebrew Python note** — system Python is PEP 668 "externally managed",
> so `pip install` outside a virtualenv will fail. Always use a venv (or `pipx`).

### Option A — one-shot script

```bash
cd ThoughbinsCore/Auth
./setup.sh
```

This creates `.venv/`, installs deps, and copies `.env.example` to `.env`.

### Option B — manual

```bash
cd ThoughbinsCore/Auth
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Then generate real secrets and paste them into `.env`:

```bash
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "import secrets; print('JWT_REFRESH_SECRET_KEY=' + secrets.token_urlsafe(48))"
```

## Run

```bash
source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Interactive docs: <http://localhost:8000/docs> (disabled when `APP_ENV=production`).

## Endpoints

| Method | Path                | Auth   | Description                                       |
|--------|---------------------|--------|---------------------------------------------------|
| GET    | `/health`           | none   | Liveness check                                    |
| POST   | `/register`         | none   | Create user, returns access + refresh tokens      |
| POST   | `/login`            | none   | Returns access + refresh tokens                   |
| POST   | `/verify-user`      | Bearer | Validates a JWT and returns the user              |
| PATCH  | `/me`               | Bearer | Update the authenticated user's profile fields    |
| POST   | `/change-password`  | Bearer | Change the authenticated user's password          |

## Example usage

```bash
# Register
curl -X POST http://localhost:8000/register \
  -H 'Content-Type: application/json' \
  -d '{
        "username": "alice",
        "email": "alice@example.com",
        "password": "S3cretPass!",
        "full_name": "Alice Doe"
      }'

# Login
curl -X POST http://localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "S3cretPass!"}'

# Verify (using the access_token from login)
curl -X POST http://localhost:8000/verify-user \
  -H 'Authorization: Bearer <ACCESS_TOKEN>'

# Update profile (email and/or full_name; username is NOT changeable here)
curl -X PATCH http://localhost:8000/me \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@newdomain.com", "full_name": "Alice Doe-Pandey"}'

# Change password (requires current_password for confirmation)
curl -X POST http://localhost:8000/change-password \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"current_password": "S3cretPass!", "new_password": "N3werPass!"}'
```

## Security & standard practices

- **Password storage** — bcrypt with configurable cost (default 12).
- **Password rules** — 8–128 chars, must contain at least one letter and one digit,
  no leading/trailing whitespace.
- **JWTs** — HS256 with separate `access` (30 min) and `refresh` (7 d) secrets.
  Tokens carry `sub`, `iat`, `nbf`, `exp`, and a `type` claim to prevent confusion.
- **Validation** — every request/response body is a Pydantic model.
  Email is validated via `EmailStr`; usernames are regex-restricted.
- **Error messages** — login returns the same error for unknown-user and bad-password
  to prevent user enumeration.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `HSTS`, `Cache-Control: no-store`, plus per-request `X-Request-ID`.
- **CORS** — explicit allow-list from env (defaults to localhost dev origins).
- **Trusted hosts** — middleware rejects Host headers not in `TRUSTED_HOSTS`.
- **Rate limiting** — per-IP via slowapi; default 100/min, login/register 10/min,
  verify 60/min. Switch to Redis storage in production for multi-instance setups.
- **SQL** — SQLAlchemy ORM with `pool_pre_ping`; raw SQL never composed from input.
- **Logging** — structured access log with method, path, status, latency, request-id.
- **Production hardening** — set `APP_ENV=production`, swap in real secrets,
  front the app with HTTPS, and put Alembic in front of `Base.metadata.create_all`.

## Environment variables

See `.env.example` for the full list. Key ones:

| Variable                      | Default                          | Notes                          |
|-------------------------------|----------------------------------|--------------------------------|
| `DATABASE_URL`                | (provided)                       | Postgres connection string     |
| `JWT_SECRET_KEY`              | placeholder                      | **Must override**              |
| `JWT_REFRESH_SECRET_KEY`      | placeholder                      | **Must override**              |
| `JWT_ALGORITHM`               | `HS256`                          |                                |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30`                             |                                |
| `REFRESH_TOKEN_EXPIRE_DAYS`   | `7`                              |                                |
| `BCRYPT_ROUNDS`               | `12`                             | 4–16                           |
| `CORS_ORIGINS`                | `*` (override in prod)           | Comma-separated                |
| `RATE_LIMIT_LOGIN`            | `10/minute`                      | slowapi format                 |
| `RATE_LIMIT_REGISTER`         | `10/minute`                      |                                |