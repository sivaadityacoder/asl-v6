"""
ASL V6 SaaS Backend - API v1 Router
"""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    users,
    organizations,
    projects,
    repositories,
    scans,
    findings,
    reports,
    rules,
    billing,
    webhooks,
    github,
    ai,
    benchmarks,
)

api_router = APIRouter()

# Auth routes
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# User routes
api_router.include_router(users.router, prefix="/users", tags=["Users"])

# Organization routes
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])

# Project routes
api_router.include_router(projects.router, prefix="/projects", tags=["Projects"])

# Repository routes
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"])

# Scan routes
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])

# Finding routes
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])

# Report routes
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])

# Rules routes
api_router.include_router(rules.router, prefix="/rules", tags=["Rules"])

# Billing routes
api_router.include_router(billing.router, prefix="/billing", tags=["Billing"])

# Webhook routes
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])

# GitHub routes
api_router.include_router(github.router, prefix="/github", tags=["GitHub"])

# AI routes
api_router.include_router(ai.router, prefix="/ai", tags=["AI"])

# Benchmarks routes
api_router.include_router(benchmarks.router, prefix="/benchmarks", tags=["Benchmarks"])