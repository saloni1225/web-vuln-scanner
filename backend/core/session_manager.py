import json
import re
from dataclasses import dataclass, field

import httpx


@dataclass(slots=True)
class SessionContext:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    csrf_token: dict[str, str] = field(default_factory=dict)
    login_performed: bool = False


class SessionManager:
    def __init__(self, auth: dict[str, object] | None = None) -> None:
        self.auth = auth or {}

    async def build(self, client: httpx.AsyncClient) -> SessionContext:
        context = SessionContext()
        for key, value in (self.auth.get("headers") or {}).items():
            if key and value:
                context.headers[str(key)] = str(value)
        for key, value in (self.auth.get("cookies") or {}).items():
            if key and value:
                context.cookies[str(key)] = str(value)

        jwt_token = str(self.auth.get("jwt_token") or "").strip()
        if jwt_token:
            context.headers.setdefault("Authorization", f"Bearer {jwt_token}")

        login_url = str(self.auth.get("login_url") or "").strip()
        username = str(self.auth.get("username") or "").strip()
        password = str(self.auth.get("password") or "").strip()
        if login_url and username and password:
            login_method = str(self.auth.get("login_method") or "post").lower()
            username_field = str(self.auth.get("username_field") or "email")
            password_field = str(self.auth.get("password_field") or "password")
            login_body = {username_field: username, password_field: password}
            extra_login_fields = self.auth.get("login_extra_fields") or {}
            if isinstance(extra_login_fields, dict):
                login_body.update({str(key): str(value) for key, value in extra_login_fields.items() if key})
            if login_method == "json":
                response = await client.post(login_url, json=login_body, headers=context.headers, cookies=context.cookies)
            else:
                response = await client.post(login_url, data=login_body, headers=context.headers, cookies=context.cookies)
            context.cookies.update({str(key): str(value) for key, value in response.cookies.items()})
            set_cookie = response.headers.get("set-cookie", "")
            if set_cookie and "=" in set_cookie:
                for raw_cookie in set_cookie.split(","):
                    primary = raw_cookie.split(";", 1)[0].strip()
                    if "=" not in primary:
                        continue
                    key, value = primary.split("=", 1)
                    if key and value:
                        context.cookies.setdefault(key.strip(), value.strip())
            try:
                payload = response.json()
            except json.JSONDecodeError:
                payload = {}
            if isinstance(payload, dict):
                token = (
                    payload.get("authentication")
                    or payload.get("token")
                    or payload.get("jwt")
                    or payload.get("accessToken")
                    or payload.get("access_token")
                )
                if token and "Authorization" not in context.headers:
                    context.headers["Authorization"] = f"Bearer {token}"
            
            # Extract CSRF token from HTML response
            if "html" in response.headers.get("content-type", "").lower():
                match = re.search(r'<input[^>]+name=[\'"]?(csrf[^>\'"]*|_token|authenticity_token)[\'"]?[^>]+value=[\'"]?([^\'">\s]+)', response.text, re.IGNORECASE)
                if not match:
                    match = re.search(r'<input[^>]+value=[\'"]?([^\'">\s]+)[\'"]?[^>]+name=[\'"]?(csrf[^>\'"]*|_token|authenticity_token)[\'"]?', response.text, re.IGNORECASE)
                    if match:
                        context.csrf_token[match.group(2)] = match.group(1)
                else:
                    context.csrf_token[match.group(1)] = match.group(2)

            context.login_performed = response.status_code < 400

        return context
