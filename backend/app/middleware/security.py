"""TraceZ Backend — Security Headers Middleware."""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that injects security headers into all responses."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        
        # Prevent browsers from MIME-sniffing a response away from the declared content-type
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking attacks by forbidding page framing
        response.headers["X-Frame-Options"] = "DENY"
        
        # Enable browser-native cross-site scripting (XSS) filter
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Enforce Content Security Policy (strict CSP for API endpoints, permissive for dashboard/static assets)
        if request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "sandbox; "
                "base-uri 'none'; "
                "form-action 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://unpkg.com; "
                "style-src 'self' 'unsafe-inline' https://unpkg.com; "
                "img-src 'self' data: https://unpkg.com https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com; "
                "connect-src 'self' http://127.0.0.1:8000 http://localhost:8000 ws://127.0.0.1:8000 ws://localhost:8000; "
                "frame-src 'none'; "
                "object-src 'none';"
            )
        
        # Enforce HTTPS on clients if not local development
        # We check settings inside the actual application config or assume HSTS in production
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Control referrer information
        response.headers["Referrer-Policy"] = "no-referrer"
        
        return response
