from dataclasses import dataclass
import asyncio
import time

import httpx

from backend.config.settings import settings
from backend.core.session_manager import SessionManager


@dataclass(slots=True)
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float


class RequestHandler:
    def __init__(self, auth: dict[str, object] | None = None) -> None:
        self._session_manager = SessionManager(auth)
        self._initialized = False
        self._last_request_started = 0.0
        auth = auth or {}
        configured_rate_limit = float(auth.get("rate_limit_per_second") or settings.default_rate_limit_per_second)
        self._rate_limit_per_second = max(settings.minimum_rate_limit_per_second, configured_rate_limit)
        self._client = httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
        )

    async def _initialize(self) -> None:
        if self._initialized:
            return
        context = await self._session_manager.build(self._client)
        self._client.headers.update(context.headers)
        self._client.cookies.update(context.cookies)
        self._initialized = True

    async def _throttle(self) -> None:
        await self._initialize()
        delay = 1 / max(self._rate_limit_per_second, settings.minimum_rate_limit_per_second)
        elapsed = time.perf_counter() - self._last_request_started
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        self._last_request_started = time.perf_counter()

    async def get(self, url: str) -> HttpResponse:
        await self._throttle()
        response = await self._client.get(url)
        return self._to_http_response(response)

    async def head(self, url: str) -> HttpResponse:
        await self._throttle()
        response = await self._client.head(url)
        return self._to_http_response(response)

    async def options(self, url: str) -> HttpResponse:
        await self._throttle()
        response = await self._client.options(url)
        return self._to_http_response(response)

    async def post(self, url: str, data: dict[str, str]) -> HttpResponse:
        await self._throttle()
        response = await self._client.post(url, data=data)
        return self._to_http_response(response)

    async def post_json(self, url: str, data: dict[str, str]) -> HttpResponse:
        await self._throttle()
        response = await self._client.post(url, json=data)
        return self._to_http_response(response)

    async def request_json(self, method: str, url: str, data: dict[str, str]) -> HttpResponse:
        await self._throttle()
        response = await self._client.request(method.upper(), url, json=data)
        return self._to_http_response(response)

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _to_http_response(response: httpx.Response) -> HttpResponse:
        return HttpResponse(
            url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            elapsed_ms=response.elapsed.total_seconds() * 1000,
        )
