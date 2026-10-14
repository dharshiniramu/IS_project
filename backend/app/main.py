from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import auth, incidents
from .config import get_settings
from .database import check_database_connection, engine, init_db
from .middleware import SecurityHeadersMiddleware, SlidingWindowRateLimiter

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SlidingWindowRateLimiter)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(incidents.router)


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


@app.get("/api/health/database")
def database_health_check() -> dict[str, str]:
    if engine is None:
        return {"status": "not_configured", "database": "mysql"}
    if not check_database_connection():
        return {"status": "unavailable", "database": "mysql"}
    return {"status": "ok", "database": "mysql"}
