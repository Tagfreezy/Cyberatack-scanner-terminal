"""Async client for the Worker's JSON API (/api/feed, /api/stats, /api/sensors)."""

from __future__ import annotations

from typing import Any

import httpx

from . import __version__


class ApiError(Exception):
    pass


class ApiClient:
    def __init__(self, base_url: str, token: str, timeout: float = 20.0) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}", "User-Agent": f"cyberwatch-tui/{__version__}"},
            timeout=timeout,
        )

    async def _request(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        try:
            r = await self._client.request(method, path, **kw)
        except httpx.HTTPError as e:
            raise ApiError(f"network error: {e.__class__.__name__}") from e
        if r.status_code == 401:
            raise ApiError("401 unauthorized: check CYBERWATCH_API_TOKEN")
        if r.status_code >= 400:
            raise ApiError(f"HTTP {r.status_code} on {path}")
        try:
            return r.json()
        except ValueError as e:
            raise ApiError(f"invalid JSON from {path}") from e

    async def feed(self, since: int = 0, limit: int = 200) -> dict[str, Any]:
        return await self._request("GET", "/api/feed", params={"since": since, "limit": limit})

    async def stats(self) -> dict[str, Any]:
        return await self._request("GET", "/api/stats")

    async def sensors(self) -> dict[str, Any]:
        return await self._request("GET", "/api/sensors")

    async def explain(self, incident_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/api/incident/{incident_id}/explain", timeout=60.0)

    async def aclose(self) -> None:
        await self._client.aclose()
