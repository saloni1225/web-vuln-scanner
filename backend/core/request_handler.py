from dataclasses import dataclass

import httpx

from backend.config.settings import settings


@dataclass(slots=True)
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float


class RequestHandler:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
        )

    async def get(self, url: str) -> HttpResponse:
        response = await self._client.get(url)
        return self._to_http_response(response)

    async def head(self, url: str) -> HttpResponse:
        response = await self._client.head(url)
        return self._to_http_response(response)

    async def post(self, url: str, data: dict[str, str]) -> HttpResponse:
        response = await self._client.post(url, data=data)
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
