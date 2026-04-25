import json
from dataclasses import dataclass, field

import httpx


@dataclass(slots=True)
class SessionContext:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
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
            try:
                payload = response.json()
            except json.JSONDecodeError:
                payload = {}
            if isinstance(payload, dict):
                token = payload.get("authentication") or payload.get("token") or payload.get("jwt")
                if token and "Authorization" not in context.headers:
                    context.headers["Authorization"] = f"Bearer {token}"
            context.login_performed = response.status_code < 400

        return context
