"""
ASL V6 SaaS Backend - Scans Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from supabase import Client

router = APIRouter()


class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    CLONING = "cloning"
    DISCOVERY = "discovery"
    STATIC_ANALYSIS = "static_analysis"
    SECRETS_SCAN = "secrets_scan"
    REACHABILITY = "reachability"
    CONTEXT_ANALYSIS = "context_analysis"
    OWASP_LLM = "owasp_llm"
    MITRE_ATLAS = "mitre_atlas"
    DYNAMIC_VALIDATION = "dynamic_validation"
    AI_REVIEW = "ai_review"
    EVIDENCE_COLLECTION = "evidence_collection"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanCreate(BaseModel):
    repository_id: str
    commit_sha: str
    branch: str = "main"
    scan_config: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    id: str
    repository_id: str
    project_id: str
    organization_id: str
    initiated_by: str
    commit_sha: str
    branch: str
    status: ScanStatus
    progress: int
    current_layer: int
    total_layers: int
    layer_status: Dict[str, str]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    error_message: Optional[str] = None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    scan_config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanLayerResponse(BaseModel):
    id: str
    scan_id: str
    layer_number: int
    name: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    findings_count: int
    error: Optional[str] = None
    metadata: Dict[str, Any]


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
):
    """Create and queue a new scan"""
    supabase: Client = get_supabase()
    
    # Check repository access
    repo = supabase.table("repositories").select("*, projects(*)").eq("id", scan_data.repository_id).single().execute()
    if not repo.data:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    project = repo.data["projects"]
    member = supabase.table("organization_members").select("role").eq("organization_id", project["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check if there's already a running scan for this repo
    running_scan = supabase.table("scans").select("id").eq("repository_id", scan_data.repository_id).in_("status", ["pending", "queued", "cloning", "discovery", "static_analysis", "secrets_scan", "reachability", "context_analysis", "owasp_llm", "mitre_atlas", "dynamic_validation", "ai_review", "evidence_collection", "report_generation"]).execute()
    if running_scan.data:
        raise HTTPException(status_code=409, detail="A scan is already running for this repository")
    
    # Create scan record
    scan = {
        "repository_id": scan_data.repository_id,
        "project_id": project["id"],
        "organization_id": project["organization_id"],
        "initiated_by": current_user.user_id,
        "commit_sha": scan_data.commit_sha,
        "branch": scan_data.branch,
        "status": ScanStatus.QUEUED,
        "progress": 0,
        "current_layer": 0,
        "total_layers": 10,
        "layer_status": {},
        "scan_config": scan_data.scan_config or {},
    }
    
    result = supabase.table("scans").insert(scan).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create scan")
    
    scan_id = result.data[0]["id"]
    
    # Create scan layers
    layers = [
        {"scan_id": scan_id, "layer_number": 1, "name": "Repository Discovery"},
        {"scan_id": scan_id, "layer_number": 2, "name": "Static Analysis"},
        {"scan_id": scan_id, "layer_number": 3, "name": "Secrets Scanning"},
        {"scan_id": scan_id, "layer_number": 4, "name": "Reachability Analysis"},
        {"scan_id": scan_id, "layer_number": 5, "name": "Context Analysis"},
        {"scan_id": scan_id, "layer_number": 6, "name": "OWASP LLM Top 10"},
        {"scan_id": scan_id, "layer_number": 7, "name": "MITRE ATLAS"},
        {"scan_id": scan_id, "layer_number": 8, "name": "Dynamic Validation"},
        {"scan_id": scan_id, "layer_number": 9, "name": "AI Review"},
        {"scan_id": scan_id, "layer_number": 10, "name": "Evidence Collection"},
    ]
    
    supabase.table("scan_layers").insert(layers).execute()
    
    # Queue the scan task (Celery)
    # background_tasks.add_task(queue_scan_task, scan_id)
    # For now, just return the scan
    
    return ScanResponse(**result.data[0])


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    project_id: Optional[str] = Query(None, alias="project_id"),
    repository_id: Optional[str] = Query(None, alias="repository_id"),
    status: Optional[ScanStatus] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List scans"""
    supabase: Client = get_supabase()
    
    # Build query based on user's organization membership
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if not org_ids:
        return ScanListResponse(scans=[], total=0, page=page, page_size=page_size)
    
    query = supabase.table("scans").select("*", count="exact").in_("organization_id", org_ids)
    
    if project_id:
        query = query.eq("project_id", project_id)
    if repository_id:
        query = query.eq("repository_id", repository_id)
    if status:
        query = query.eq("status", status.value)
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True)
    
    result = query.execute()
    
    return ScanListResponse(
        scans=[ScanResponse(**s) for s in result.data],
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get scan by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check access
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if result.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return ScanResponse(**result.data)


@router.get("/{scan_id}/layers", response_model=List[ScanLayerResponse])
async def get_scan_layers(scan_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get scan layers with progress"""
    supabase: Client = get_supabase()
    
    # Check scan access
    scan = supabase.table("scans").select("organization_id").eq("id", scan_id).single().execute()
    if not scan.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if scan.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    result = supabase.table("scan_layers").select("*").eq("scan_id", scan_id).order("layer_number").execute()
    
    return [ScanLayerResponse(**l) for l in result.data]


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, current_user: TokenData = Depends(get_current_user)):
    """Cancel a running scan"""
    supabase: Client = get_supabase()
    
    scan = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    if not scan.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check authorization (owner/admin or scan initiator)
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    org_roles = {o["organization_id"]: o["role"] for o in orgs.data}
    
    if scan.data["organization_id"] not in org_roles:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if org_roles[scan.data["organization_id"]] not in ["owner", "admin"] and scan.data["initiated_by"] != current_user.user_id:
        raise HTTPException(status_code=403, detail="Not authorized to cancel this scan")
    
    # Only cancel if not already completed/failed
    if scan.data["status"] in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Scan already finished")
    
    supabase.table("scans").update({
        "status": ScanStatus.CANCELLED,
        "completed_at": datetime.utcnow().isoformat(),
        "error_message": "Cancelled by user",
    }).eq("id", scan_id).execute()
    
    # Update layers
    supabase.table("scan_layers").update({
        "status": "cancelled",
        "completed_at": datetime.utcnow().isoformat(),
    }).eq("scan_id", scan_id).in_("status", ["pending", "running"]).execute()
    
    return {"message": "Scan cancelled successfully"}


@router.get("/{scan_id}/live")
async def get_live_scan_progress(scan_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get live scan progress for websocket/polling"""
    supabase: Client = get_supabase()
    
    scan = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    if not scan.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if scan.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    layers = supabase.table("scan_layers").select("*").eq("scan_id", scan_id).order("layer_number").execute()
    
    return {
        "scan": ScanResponse(**scan.data),
        "layers": [ScanLayerResponse(**l) for l in layers.data],
    }