"""
ASL V6 - Microservices Entrypoints
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import time
from fastapi import Request

from app.core.config import settings
from app.main import lifespan, global_exception_handler
from app.api.v1.endpoints import (
    auth, users, organizations, projects, repositories, 
    scans, findings, reports, rules, billing, 
    webhooks, github, ai, benchmarks
)

def create_service(title: str, routers: list) -> FastAPI:
    app = FastAPI(
        title=title,
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        redirect_slashes=False,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "https://app.adityasecuritylabs.tech",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response

    app.add_exception_handler(Exception, global_exception_handler)

    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "service": title,
            "version": settings.app_version,
            "environment": settings.environment,
        }
        
    @app.get("/")
    async def root():
        return {
            "service": title,
            "docs": "/docs" if settings.debug else "Contact support for API documentation",
        }

    for router, prefix, tags in routers:
        app.include_router(router, prefix=f"{settings.api_prefix}{prefix}", tags=tags)

    return app

# 1. Authentication Service
auth_app = create_service("ASL V6 - Authentication Service", [
    (auth.router, "/auth", ["Authentication"]),
    (users.router, "/users", ["Users"]),
    (organizations.router, "/organizations", ["Organizations"]),
])

# 2. Scan Service
scan_app = create_service("ASL V6 - Scan Service", [
    (scans.router, "/scans", ["Scans"]),
    (findings.router, "/findings", ["Findings"]),
    (benchmarks.router, "/benchmarks", ["Benchmarks"]),
    (rules.router, "/rules", ["Rules"]),
])

# 3. Repository Service
repository_app = create_service("ASL V6 - Repository Service", [
    (repositories.router, "/repositories", ["Repositories"]),
    (github.router, "/github", ["GitHub"]),
])

# 4. Report Service
report_app = create_service("ASL V6 - Report Service", [
    (reports.router, "/reports", ["Reports"]),
])

# 5. AI Review Service
ai_app = create_service("ASL V6 - AI Review Service", [
    (ai.router, "/ai", ["AI"]),
])

# 6. Deployment Service
deployment_app = create_service("ASL V6 - Deployment Service", [
    (webhooks.router, "/webhooks", ["Webhooks"]),
    (projects.router, "/projects", ["Projects"]),
    (billing.router, "/billing", ["Billing"]),
])
