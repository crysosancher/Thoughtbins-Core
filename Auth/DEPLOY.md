# Auth Service Deployment Guide

This guide covers deploying the Auth Service to a Linux server using Docker.

## Prerequisites

- Docker installed on the server
- Docker Compose installed on the server
- PostgreSQL database accessible (connection string ready)

## Quick Start

### 1. Transfer Files to Server

```bash
# From your local machine
scp -r Auth/ user@your-server:/path/to/deploy/auth-service/
```

Or use Git to clone the repository on your server.

### 2. Configure Environment

```bash
cd /path/to/deploy/auth-service

# Copy the production template
cp .env.production .env

# Edit with your actual values
nano .env
```

**Required changes in `.env`:**
- `DATABASE_URL` - Your PostgreSQL connection string
- `JWT_SECRET_KEY` - Generate with: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `JWT_REFRESH_SECRET_KEY` - Generate with: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `CORS_ORIGINS` - Your frontend domain(s)
- `TRUSTED_HOSTS` - Your domain(s)

### 3. Build and Run

```bash
# Build the Docker image
docker build -t auth-api .

# Run with docker-compose
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 4. Verify Deployment

```bash
# Check health endpoint
curl http://localhost:8000/health

# Expected response: {"status":"ok","env":"production"}
```

## Production Deployment with Nginx (Recommended)

For production, use Nginx as a reverse proxy with SSL/TLS:

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name api.your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.your-domain.com;

    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Docker Commands Reference

```bash
# Start the service
docker-compose up -d

# Stop the service
docker-compose down

# Restart the service
docker-compose restart

# Rebuild after code changes
docker-compose up -d --build

# View logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f auth-api

# Stop and remove volumes (⚠️ removes data)
docker-compose down -v
```

## Health Monitoring

The service includes a built-in health check endpoint:

- **Endpoint:** `GET /health`
- **Returns:** `{"status": "ok", "env": "production"}`

Docker will automatically monitor this endpoint and restart the container if it fails.

## Updating the Service

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up -d --build
```

## Troubleshooting

### Container won't start

```bash
# Check logs for errors
docker-compose logs

# Verify environment variables
docker-compose config
```

### Database connection issues

```bash
# Test database connectivity from container
docker-compose exec auth-api python -c "
from urllib.parse import urlparse
from config import settings
parsed = urlparse(settings.database_url)
print(f'Host: {parsed.hostname}, Port: {parsed.port}, DB: {parsed.path}')
"
```

### View running processes inside container

```bash
docker-compose exec auth-api ps aux
```

## Security Checklist

- [ ] Changed default JWT secret keys
- [ ] Set strong database password
- [ ] Configured proper CORS origins
- [ ] Enabled SSL/TLS in production
- [ ] Set `APP_ENV=production`
- [ ] Restricted TRUSTED_HOSTS to your domains