from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class SlidingWindowRateLimiter(BaseHTTPMiddleware):
    """Small in-process limiter for sensitive write endpoints.

    This protects a single development/API process. A shared store such as
    Redis is required when the service runs behind multiple workers.
    """

    limits = {
        ("POST", "/api/auth/login"): (5, 60),
        ("POST", "/api/auth/register"): (5, 60),
        ("POST", "/api/incidents"): (10, 60),
    }

    def __init__(self, app) -> None:
        super().__init__(app)
        self._requests: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next):
        limit_config = self.limits.get((request.method, request.url.path))
        if limit_config is None:
            return await call_next(request)

        max_requests, window_seconds = limit_config
        client_host = request.client.host if request.client else "unknown"
        key = (client_host, request.method + ":" + request.url.path)
        now = monotonic()
        with self._lock:
            timestamps = self._requests[key]
            while timestamps and now - timestamps[0] >= window_seconds:
                timestamps.popleft()
            if len(timestamps) >= max_requests:
                retry_after = max(1, int(window_seconds - (now - timestamps[0])))
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again later."},
                    headers={"Retry-After": str(retry_after)},
                )
            timestamps.append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        )
        return response
