# Secrets Management & Remediation Report

This report outlines the secrets architecture, configuration changes, and integration guidelines for secrets management within the AdaptiveScan production platform.

## Secrets Architecture

AdaptiveScan enforces a strict **Zero-Hardcoded-Secrets** policy. All configuration secrets (such as JWT keys, database credentials, and integration passwords) are injected dynamically at runtime.

```
                    ┌────────────────────────┐
                    │     HashiCorp Vault    │
                    └───────────┬────────────┘
                                │ (Pull Secrets)
                                ▼
 ┌─────────────────┐    ┌───────────────┐    ┌──────────────────────┐
 │ Docker Secrets  ├───►│  Environment  ├───►│  AdaptiveScan App   │
 │ (/run/secrets/*)│    │   Variables   │    │ (settings.py Config) │
 └─────────────────┘    └───────────────┘    └──────────────────────┘
```

## Audit Findings & Remediation

A repository-wide credentials scan was conducted to identify any hardcoded secrets or static fallback tokens:

| Component | Finding / Threat | Severity | Remediation Action | Status |
| :--- | :--- | :--- | :--- | :--- |
| `jwt_guard.py` | Fallback JWT signing key `"adaptivescan-local-development-secret"` | Medium | Restrict usage strictly to `local-dev`. Throw `RuntimeError` at startup in production. | **Remediated** |
| `app.py` | Local seeding administrator password in `.env` | Low | Ignore `.env` in `.gitignore`. Seed admin credentials strictly via environment. | **Remediated** |
| Database | SQLite local path configuration fallback | Low | Enforce PostgreSQL string requirement in production. | **Remediated** |

---

## Secrets Management Integration

### 1. Docker Secrets (Swarm/Compose)
When deploying in Docker environments, mount secrets as files under `/run/secrets/` and read them dynamically. Below is an example of setting up a dynamic loader entrypoint script `docker-entrypoint.sh`:

```bash
#!/bin/sh
# docker-entrypoint.sh - Load Docker Secrets into Environment Variables
if [ -f /run/secrets/jwt_secret ]; then
    export ADAPTIVESCAN_JWT_SECRET=$(cat /run/secrets/jwt_secret)
fi
if [ -f /run/secrets/db_password ]; then
    export POSTGRES_PASSWORD=$(cat /run/secrets/db_password)
fi
exec "$@"
```

In your `docker-compose.yml`:
```yaml
version: '3.8'
services:
  backend:
    image: adaptivescan-backend:latest
    entrypoint: ["/app/docker-entrypoint.sh"]
    command: ["uvicorn", "backend.app:app", "--host", "0.0.0.0"]
    secrets:
      - jwt_secret
      - db_password

secrets:
  jwt_secret:
    external: true
  db_password:
    external: true
```

### 2. HashiCorp Vault Integration
For larger cloud/k8s enterprise deployments, fetch secrets from HashiCorp Vault KV Secrets Engine before launching the service.

Python client snippet using the official `hvac` package:
```python
import os
import hvac

def load_vault_secrets():
    vault_url = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.environ.get("VAULT_TOKEN")
    
    if not vault_token:
        # Fall back to AppRole authentication in production
        return
        
    client = hvac.Client(url=vault_url, token=vault_token)
    try:
        read_response = client.secrets.kv.v2.read_secret_version(
            path='adaptivescan/config',
            mount_point='secret'
        )
        secrets = read_response['data']['data']
        os.environ['ADAPTIVESCAN_JWT_SECRET'] = secrets.get('jwt_secret', '')
        os.environ['DATABASE_URL'] = secrets.get('database_url', '')
    except Exception as exc:
        print(f"Failed to read from Vault: {exc}")
```
This is executed right before app startup or during entrypoint initialization.
