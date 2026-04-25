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
        self._retry_attempts = max(0, int(auth.get("retry_attempts") or settings.retry_attempts))
        self._retry_backoff_ms = max(0, int(auth.get("retry_backoff_ms") or settings.retry_backoff_ms))
        self._client = httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
        )
        self.session_context = None

    async def _initialize(self) -> None:
        if self._initialized:
            return
        context = await self._session_manager.build(self._client)
        self.session_context = context
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
        return await self._send("GET", url)

    async def head(self, url: str) -> HttpResponse:
        return await self._send("HEAD", url)

    async def options(self, url: str) -> HttpResponse:
        return await self._send("OPTIONS", url)

    async def post(self, url: str, data: dict[str, str]) -> HttpResponse:
        return await self._send("POST", url, data=data)

    async def post_json(self, url: str, data: dict[str, str]) -> HttpResponse:
        return await self._send("POST", url, json=data)

    async def request_json(self, method: str, url: str, data: dict[str, str]) -> HttpResponse:
        return await self._send(method.upper(), url, json=data)

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

    async def _send(self, method: str, url: str, **kwargs) -> HttpResponse:
        last_error: Exception | None = None
        for attempt in range(self._retry_attempts + 1):
            try:
                await self._throttle()
                response = await self._client.request(method, url, **kwargs)
                if response.status_code in {429, 502, 503, 504} and attempt < self._retry_attempts:
                    await asyncio.sleep((self._retry_backoff_ms / 1000) * (attempt + 1))
                    continue
                return self._to_http_response(response)
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                last_error = exc
                if attempt >= self._retry_attempts:
                    raise
                await asyncio.sleep((self._retry_backoff_ms / 1000) * (attempt + 1))
        assert last_error is not None
        raise last_error
