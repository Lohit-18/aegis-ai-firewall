"""OpenAI-compatible upstream adapter.

Deliberately thin. The whole value of the OpenAI chat-completions shape is that
one adapter reaches OpenAI, Groq, Together, Fireworks, vLLM, LM Studio and
Ollama. The seam exists so a second provider (Anthropic's Messages API, say)
can be added without touching the proxy or the detection engine.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from ..config import settings


class UpstreamError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"upstream returned {status}")
        self.status = status
        self.body = body


class OpenAICompatProvider:
    name = "openai-compatible"

    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        self.base_url = (base_url or settings.upstream_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.upstream_api_key
        self._client: httpx.AsyncClient | None = None

    async def startup(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                settings.upstream_timeout_s,
                connect=settings.upstream_connect_timeout_s,
            ),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    async def shutdown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("provider not started")
        return self._client

    def _headers(self, inbound: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        # Prefer the caller's own key when they supply one - Aegis is a proxy,
        # not a credential broker. Falling back to a configured key is a dev
        # convenience.
        caller_auth = (inbound or {}).get("authorization")
        if caller_auth:
            headers["authorization"] = caller_auth
        elif self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        return headers

    # ---- system prompt handling -----------------------------------------

    @staticmethod
    def get_system_prompt(payload: dict[str, Any]) -> str | None:
        for msg in payload.get("messages", []):
            if isinstance(msg, dict) and msg.get("role") in ("system", "developer"):
                content = msg.get("content")
                if isinstance(content, str):
                    return content
        return None

    @staticmethod
    def set_system_prompt(payload: dict[str, Any], prompt: str) -> dict[str, Any]:
        messages = list(payload.get("messages", []))
        for i, msg in enumerate(messages):
            if isinstance(msg, dict) and msg.get("role") in ("system", "developer"):
                messages[i] = {**msg, "content": prompt}
                payload["messages"] = messages
                return payload
        payload["messages"] = [{"role": "system", "content": prompt}, *messages]
        return payload

    # ---- calls ------------------------------------------------------------

    async def chat(self, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        resp = await self.client.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=self._headers(headers),
        )
        if resp.status_code >= 400:
            raise UpstreamError(resp.status_code, resp.text)
        return resp.json()

    async def chat_stream(
        self, payload: dict[str, Any], headers: dict[str, str] | None = None
    ) -> AsyncIterator[str]:
        """Yield raw SSE lines from upstream."""
        async with self.client.stream(
            "POST",
            f"{self.base_url}/chat/completions",
            json={**payload, "stream": True},
            headers=self._headers(headers),
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise UpstreamError(resp.status_code, body.decode("utf-8", "replace"))
            async for line in resp.aiter_lines():
                yield line

    async def models(self, headers: dict[str, str] | None = None) -> dict[str, Any]:
        resp = await self.client.get(f"{self.base_url}/models", headers=self._headers(headers))
        if resp.status_code >= 400:
            raise UpstreamError(resp.status_code, resp.text)
        return resp.json()


# ---- SSE helpers ---------------------------------------------------------

def parse_sse_delta(line: str) -> str | None:
    """Extract assistant text from one `data:` line of an OpenAI SSE stream."""
    if not line.startswith("data:"):
        return None
    data = line[5:].strip()
    if not data or data == "[DONE]":
        return None
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return None
    try:
        choices = obj.get("choices") or []
        if not choices:
            return None
        delta = choices[0].get("delta") or {}
        content = delta.get("content")
        return content if isinstance(content, str) else None
    except (AttributeError, IndexError, TypeError):
        return None


def make_sse_chunk(text: str, model: str = "aegis", chunk_id: str = "aegis-rewrite") -> str:
    """Build a synthetic SSE data line carrying `text` as assistant content."""
    payload = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def make_sse_stop(model: str = "aegis", reason: str = "stop") -> str:
    payload = {
        "id": "aegis-rewrite",
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\ndata: [DONE]\n\n"
