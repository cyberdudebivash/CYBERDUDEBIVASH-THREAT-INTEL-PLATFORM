"""
SENTINEL APEX — Database Client
Supabase REST API client with connection pooling
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("sentinel.db")
settings = get_settings()

# Persistent HTTP client for Supabase REST calls
_client: Optional[httpx.AsyncClient] = None


def _headers(service: bool = False) -> dict[str, str]:
    """Build Supabase REST API headers."""
    key = settings.SUPABASE_SERVICE_KEY if service else settings.SUPABASE_ANON_KEY
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=f"{settings.SUPABASE_URL}/rest/v1",
            headers=_headers(service=True),
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
    return _client


async def close_client():
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None


class SupabaseDB:
    """Thin async wrapper over Supabase REST API (PostgREST)."""

    @staticmethod
    async def query(
        table: str,
        select: str = "*",
        filters: Optional[dict[str, str]] = None,
        order: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        single: bool = False,
        count: bool = False,
    ) -> dict[str, Any]:
        """Execute a SELECT query via PostgREST."""
        client = await get_client()
        params: dict[str, str] = {"select": select}
        headers = dict(client.headers)

        if filters:
            params.update(filters)
        if order:
            params["order"] = order
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        if single:
            headers["Accept"] = "application/vnd.pgrst.object+json"
        if count:
            headers["Prefer"] = "count=exact"
            headers["Range-Unit"] = "items"

        resp = await client.get(f"/{table}", params=params, headers=headers)
        resp.raise_for_status()

        result = {"data": resp.json()}
        if count and "content-range" in resp.headers:
            cr = resp.headers["content-range"]
            total = cr.split("/")[-1] if "/" in cr else "0"
            result["count"] = int(total) if total != "*" else 0
        return result

    @staticmethod
    async def insert(
        table: str,
        data: dict[str, Any] | list[dict[str, Any]],
        upsert: bool = False,
        on_conflict: Optional[str] = None,
    ) -> dict[str, Any]:
        """INSERT or UPSERT rows."""
        client = await get_client()
        headers = dict(client.headers)
        headers["Prefer"] = "return=representation"
        if upsert:
            headers["Prefer"] += ",resolution=merge-duplicates"
            if on_conflict:
                headers["Prefer"] += f",on_conflict={on_conflict}"

        resp = await client.post(f"/{table}", json=data, headers=headers)
        resp.raise_for_status()
        return {"data": resp.json()}

    @staticmethod
    async def update(
        table: str,
        data: dict[str, Any],
        filters: dict[str, str],
    ) -> dict[str, Any]:
        """UPDATE rows matching filters."""
        client = await get_client()
        headers = dict(client.headers)
        headers["Prefer"] = "return=representation"

        resp = await client.patch(f"/{table}", params=filters, json=data, headers=headers)
        resp.raise_for_status()
        return {"data": resp.json()}

    @staticmethod
    async def delete(table: str, filters: dict[str, str]) -> dict[str, Any]:
        """DELETE rows matching filters."""
        client = await get_client()
        headers = dict(client.headers)
        headers["Prefer"] = "return=representation"

        resp = await client.delete(f"/{table}", params=filters, headers=headers)
        resp.raise_for_status()
        return {"data": resp.json()}

    @staticmethod
    async def rpc(function: str, params: Optional[dict[str, Any]] = None) -> Any:
        """Call a Supabase/Postgres RPC function."""
        client = await get_client()
        resp = await client.post(f"/rpc/{function}", json=params or {})
        resp.raise_for_status()
        return resp.json()


# Supabase Auth client (separate from PostgREST)
class SupabaseAuth:
    """Supabase GoTrue auth API client."""

    @staticmethod
    async def sign_up(email: str, password: str, metadata: Optional[dict] = None) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/signup",
                headers={
                    "apikey": settings.SUPABASE_ANON_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "email": email,
                    "password": password,
                    "data": metadata or {},
                },
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def sign_in(email: str, password: str) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/token?grant_type=password",
                headers={
                    "apikey": settings.SUPABASE_ANON_KEY,
                    "Content-Type": "application/json",
                },
                json={"email": email, "password": password},
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def refresh_session(refresh_token: str) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
                headers={
                    "apikey": settings.SUPABASE_ANON_KEY,
                    "Content-Type": "application/json",
                },
                json={"refresh_token": refresh_token},
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def get_user(access_token: str) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{settings.SUPABASE_URL}/auth/v1/user",
                headers={
                    "apikey": settings.SUPABASE_ANON_KEY,
                    "Authorization": f"Bearer {access_token}",
                },
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def sign_in_with_oauth(provider: str, redirect_to: str) -> dict:
        """Get OAuth URL for provider (google, github, etc.)."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{settings.SUPABASE_URL}/auth/v1/authorize",
                params={"provider": provider, "redirect_to": redirect_to},
                headers={"apikey": settings.SUPABASE_ANON_KEY},
                follow_redirects=False,
            )
            return {"url": str(resp.headers.get("location", "")), "provider": provider}
