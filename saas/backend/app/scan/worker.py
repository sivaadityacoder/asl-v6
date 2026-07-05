import asyncio
import structlog
from datetime import datetime
from app.core.database import get_supabase
from app.core.config import settings
from app.scan.pipeline import ScanPipeline, ScanStatus

logger = structlog.get_logger(__name__)

async def run_scan_background(scan_id: str, repo_url: str):
    logger.info("Starting background scan", scan_id=scan_id, repo_url=repo_url)
    supabase = get_supabase()
    try:
        pipeline = ScanPipeline(
            nvidia_api_key=settings.nvidia_api_key,
            nvidia_base_url=settings.nvidia_base_url
        )
        
        supabase.table("scans").update({
            "status": ScanStatus.CLONING.value,
            "started_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()
        
        result = await pipeline.scan(repo_url=repo_url, scan_id=scan_id)
        
        update_data = {
            "status": result.status.value,
            "completed_at": datetime.utcnow().isoformat(),
            "findings_count": result.verified_finding_count,
            "error_message": result.error,
        }
        
        supabase.table("scans").update(update_data).eq("id", scan_id).execute()
        logger.info("Background scan finished", scan_id=scan_id, status=result.status)
        
    except Exception as e:
        logger.error("Background scan failed", scan_id=scan_id, error=str(e))
        supabase.table("scans").update({
            "status": ScanStatus.FAILED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "error_message": str(e)
        }).eq("id", scan_id).execute()
