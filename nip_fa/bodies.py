"""Bounded request-body reading for the adapter's unauthenticated POST routes."""

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
