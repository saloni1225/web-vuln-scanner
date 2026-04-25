import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar


T = TypeVar("T")


class RateLimiter:
    def __init__(self, concurrency: int) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)

    async def run(self, task: Callable[[], Awaitable[T]]) -> T:
        async with self._semaphore:
            return await task()

