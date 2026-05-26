"""TraceZ Backend — FastAPI Main Entrypoint."""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.rate_limiter import RateLimiterMiddleware
from app.routes import health, auth, scan, admin, threat_intel, monolithic


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tracez")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI application lifecycle context."""
    logger.info("[*] Starting TraceZ security backend...")
    # Initialize DB (creates tables, seeds admin user)
    init_db()
    yield
    logger.info("[*] Shutting down TraceZ security backend...")

# Initialize FastAPI App
app = FastAPI(
    title="TraceZ Safe Browsing Shield API",
    description="Intelligent browser security and phishing detection backend.",
    version="1.0.0",
    lifespan=lifespan
)

# 1. CORS Middleware (Restricted to chrome extension and local dashboard origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# 2. Custom Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# 3. Rate Limiter Middleware
app.add_middleware(RateLimiterMiddleware)

# --- Static files & Landing Dashboard routes ---
static_dir = Path(__file__).resolve().parent / "static"
if not static_dir.exists():
    static_dir.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/")
def serve_dashboard():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "TraceZ Backend Server is Running."}

@app.get("/api/extension/download")
def download_extension_zip():
    zip_path = static_dir / "tracez-extension.zip"
    if zip_path.exists():
        return FileResponse(
            str(zip_path), 
            media_type="application/zip", 
            filename="tracez-extension.zip"
        )
    raise HTTPException(
        status_code=404, 
        detail="Extension build file not found. Please run 'npm run build:extension' first."
    )

# --- Register Routers ---
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(admin.router)
app.include_router(threat_intel.router)
app.include_router(monolithic.router)

# --- Global Exception Handlers (Mitigate info disclosure) ---

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Intercept all uncaught server errors, returning a generic sanitized response."""
    logger.error(f"[!] Unhandled error on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please contact the administrator."}
    )
