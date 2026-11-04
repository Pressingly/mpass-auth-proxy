"""Bounded request-body reading and strict JSON decoding for the adapter's POST routes."""

import json

from starlette.requests import Request


class RequestTooLarge(Exception):
    """The body is, or declares itself, larger than the route accepts."""


def _declared_length(request: Request) -> int | None:
    raw = request.headers.get("content-length", "")
    return int(raw) if raw.isdigit() else None


async def read_body_within(request: Request, limit: int) -> bytes:
    """The whole body, never buffering more than `limit` bytes. Raises
    RequestTooLarge on a declared Content-Length above the limit before reading
    anything, and as soon as a streamed or chunked body passes it."""
    declared = _declared_length(request)
    if declared is not None and declared > limit:
        raise RequestTooLarge()
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise RequestTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def strict_json_loads(raw: bytes | str):
    """json.loads that refuses duplicate object keys, so no two readers of the
    same bytes can disagree on a value, and bytes that are not UTF-8 (json.loads
    would otherwise sniff UTF-16 and UTF-32). Raises ValueError, also for
    nesting deep enough to exhaust the parser's recursion limit."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    try:
        return json.loads(text, object_pairs_hook=_without_duplicate_keys)
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc


def _without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key in JSON object")
    return dict(pairs)
