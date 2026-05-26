"""TraceZ Backend — Rate Limiting Middleware."""

import time
from collections import defaultdict
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from app.config import settings

class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    In-memory, sliding-window per-IP rate limiter middleware.
    Supports path-specific limits for auth, scanning, and admin operations.
    """
    
    def __init__(self, app):
        super().__init__(app)
        # Store requests as: { client_ip: { category: [timestamp_float, ...] } }
        self.history = defaultdict(lambda: defaultdict(list))
        
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Bypass rate limiting for health check
        if request.url.path == "/api/health":
            return await call_next(request)
            
        client_ip = request.client.host if request.client else "unknown_ip"
        path = request.url.path
        
        # Determine rate limit configuration
        category = "default"
        limit = settings.RATE_LIMIT_PER_MINUTE
        
        if path.startswith("/api/auth"):
            category = "auth"
            limit = settings.AUTH_RATE_LIMIT
        elif path.startswith("/api/scan"):
            category = "scan"
            limit = settings.SCAN_RATE_LIMIT
        elif path.startswith("/api/admin"):
            category = "admin"
            limit = 20  # Strict rate limit for admin operations
            
        now = time.time()
        window_start = now - 60.0  # 1-minute window
        
        # Get history for this IP and category, clean up expired timestamps
        timestamps = self.history[client_ip][category]
        timestamps = [t for t in timestamps if t > window_start]
        self.history[client_ip][category] = timestamps
        
        # Check if rate limit is exceeded
        if len(timestamps) >= limit:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "retry_after": int(60 - (now - timestamps[0])) if timestamps else 60
                }
            )
            
        # Record this request
        self.history[client_ip][category].append(now)
        
        return await call_next(request)
