FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN adduser --system --no-create-home appuser && chown -R appuser /app
USER appuser

ENV LOG_LEVEL=info
# --no-access-log: silences uvicorn's per-request access lines. Those leaked
# bearer tokens for /mpass-callback (id_token / access_token / refresh_token
# travel as query params and were echoed in full into container logs) plus
# client IPs. Application-level events (login mutex 409, callback success/
# failure, PKCE failures) are logged via main.py's logger and remain visible.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8000 --log-level ${LOG_LEVEL} --no-access-log"]
