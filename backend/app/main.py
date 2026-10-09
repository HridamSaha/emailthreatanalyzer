from __future__ import annotations

from collections import defaultdict, deque
from contextlib import asynccontextmanager
from time import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.v1.analyses import router as analyses_router
from app.api.v1.analyze import router as analyze_router
from app.api.v1.rules import router as rules_router
from app.api.v1.stats import router as stats_router
from app.core.bootstrap import init_db
from app.core.config import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Static email threat analysis, URL inspection, attachment metadata review, and explainable scoring.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Admin-Token"],
)
app.state.analyze_hits = defaultdict(deque)


@app.exception_handler(HTTPException)
def http_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
    return JSONResponse(status_code=exc.status_code, content={"error": "request_error", "detail": detail})


@app.exception_handler(Exception)
def unhandled_handler(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "An unexpected error occurred while processing the request."},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/health")
def health_meta() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "app": settings.app_name}


app.include_router(analyze_router)
app.include_router(analyses_router)
app.include_router(rules_router)
app.include_router(stats_router)


@app.middleware("http")
async def analyze_rate_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path.startswith("/api/v1/analyze"):
        key = request.client.host if request.client else "local"
        window: deque = app.state.analyze_hits[key]
        now = time()
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= settings.rate_limit_analyze_per_minute:
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "detail": "Too many analysis requests."},
            )
        window.append(now)
    return await call_next(request)
