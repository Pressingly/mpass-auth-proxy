"""Response builders. Every adapter response carries `Cache-Control: no-store`."""

from fastapi.responses import JSONResponse, RedirectResponse

NO_STORE = {"Cache-Control": "no-store"}


def adapter_json(body: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=body, status_code=status_code, headers=NO_STORE)


def denial(status_code: int, error: str) -> JSONResponse:
    return adapter_json({"error": error}, status_code)


def invalid_request() -> JSONResponse:
    return denial(400, "invalid_request")


def session_required() -> JSONResponse:
    return denial(401, "session_required")


def session_expired() -> JSONResponse:
    return denial(401, "session_expired")


def request_too_large() -> JSONResponse:
    return denial(413, "request_too_large")


def adapter_redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=302, headers=NO_STORE)
