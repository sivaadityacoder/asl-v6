"""
ASL V6 - Scan Worker (Celery Task)
Background task that runs the 10-layer scan pipeline for a given repository.
Results are stored in Supabase and streamed via Redis pub/sub.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
import structlog

try:
    from celery import Celery
    from celery.utils.log import get_task_logger
    _celery_available = True
except ImportError:
    _celery_available = False

logger = structlog.get_logger(__name__)


def create_celery_app() -> Any:
    """Create Celery app — returns None if Celery not configured."""
    if not _celery_available:
        return None

    try:
        from app.core.config import settings
        app = Celery(
            "asl_v6",
            broker=settings.celery_broker_url,
            backend=settings.celery_result_backend,
        )
        app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            task_track_started=True,
            task_soft_time_limit=3300,  # 55 min
            task_time_limit=3600,       # 60 min
            worker_prefetch_multiplier=1,
        )
        return app
    except Exception as e:
        logger.warning("Could not create Celery app", error=str(e))
        return None


celery_app = create_celery_app()


def run_scan_task(scan_id: str, repo_url: str, nvidia_api_key: str | None = None) -> dict[str, Any]:
    """
    Main scan task — runs the full 10-layer pipeline.
    Called by Celery worker or directly for testing.
    """
    async def _run():
        from app.scan.pipeline import ScanPipeline
        pipeline = ScanPipeline(nvidia_api_key=nvidia_api_key)
        result = await pipeline.scan(repo_url=repo_url, scan_id=scan_id)
        return result.to_dict()

    return asyncio.run(_run())


if celery_app:
    @celery_app.task(
        bind=True,
        name="asl_v6.scan",
        max_retries=2,
        soft_time_limit=3300,
        time_limit=3600,
    )
    def run_scan(self, scan_id: str, repo_url: str, nvidia_api_key: str | None = None):
        """Celery task wrapper for the scan pipeline."""
        try:
            logger.info("Starting scan task", scan_id=scan_id, repo_url=repo_url)
            result = run_scan_task(scan_id, repo_url, nvidia_api_key)
            logger.info("Scan task complete", scan_id=scan_id, verified=result.get("verified_finding_count"))
            return result
        except Exception as exc:
            logger.error("Scan task failed", scan_id=scan_id, error=str(exc))
            raise self.retry(exc=exc, countdown=30)