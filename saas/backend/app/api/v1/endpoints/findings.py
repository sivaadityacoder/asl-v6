"""
ASL V6 SaaS Backend - Findings Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from supabase import Client

router = APIRouter()


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    ACCEPTED_RISK = "accepted_risk"


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    assigned_to: Optional[str] = None
    suppression_reason: Optional[str] = None


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    repository_id: str
    project_id: str
    organization_id: str
    layer: int
    layer_name: str
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_llm_id: Optional[str] = None
    mitre_atlas_id: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: dict
    remediation: Optional[str] = None
    references: List[str]
    tags: List[str]
    confidence: Optional[float] = None
    assigned_to: Optional[str] = None
    triaged_by: Optional[str] = None
    triaged_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    is_suppressed: bool
    suppression_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class FindingListResponse(BaseModel):
    findings: List[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingStatsResponse(BaseModel):
    total: int
    by_severity: dict
    by_status: dict
    by_layer: dict
    by_category: dict


@router.get("/", response_model=FindingListResponse)
async def list_findings(
    scan_id: Optional[str] = Query(None, alias="scan_id"),
    project_id: Optional[str] = Query(None, alias="project_id"),
    repository_id: Optional[str] = Query(None, alias="repository_id"),
    severity: Optional[FindingSeverity] = None,
    status: Optional[FindingStatus] = None,
    layer: Optional[int] = None,
    rule_id: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List findings with filters"""
    supabase: Client = get_supabase()
    
    # Get user's organizations
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if not org_ids:
        return FindingListResponse(findings=[], total=0, page=page, page_size=page_size)
    
    query = supabase.table("findings").select("*", count="exact").in_("organization_id", org_ids)
    
    if scan_id:
        query = query.eq("scan_id", scan_id)
    if project_id:
        query = query.eq("project_id", project_id)
    if repository_id:
        query = query.eq("repository_id", repository_id)
    if severity:
        query = query.eq("severity", severity.value)
    if status:
        query = query.eq("status", status.value)
    if layer:
        query = query.eq("layer", layer)
    if rule_id:
        query = query.eq("rule_id", rule_id)
    if search:
        query = query.or_(f"title.ilike.%{search}%,description.ilike.%{search}%,file_path.ilike.%{search}%")
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True)
    
    result = query.execute()
    
    return FindingListResponse(
        findings=[FindingResponse(**f) for f in result.data],
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=FindingStatsResponse)
async def get_finding_stats(
    scan_id: Optional[str] = Query(None, alias="scan_id"),
    project_id: Optional[str] = Query(None, alias="project_id"),
    repository_id: Optional[str] = Query(None, alias="repository_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Get finding statistics"""
    supabase: Client = get_supabase()
    
    # Get user's organizations
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if not org_ids:
        return FindingStatsResponse(total=0, by_severity={}, by_status={}, by_layer={}, by_category={})
    
    query = supabase.table("findings").select("*").in_("organization_id", org_ids)
    
    if scan_id:
        query = query.eq("scan_id", scan_id)
    if project_id:
        query = query.eq("project_id", project_id)
    if repository_id:
        query = query.eq("repository_id", repository_id)
    
    result = query.execute()
    
    findings = result.data
    
    by_severity = {}
    by_status = {}
    by_layer = {}
    by_category = {}
    
    for f in findings:
        # Severity
        sev = f.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # Status
        st = f.get("status", "unknown")
        by_status[st] = by_status.get(st, 0) + 1
        
        # Layer
        lyr = f.get("layer", 0)
        by_layer[lyr] = by_layer.get(lyr, 0) + 1
        
        # Category (from rule_id or owasp_llm_id)
        cat = f.get("owasp_llm_id") or f.get("mitre_atlas_id") or f.get("rule_id", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
    
    return FindingStatsResponse(
        total=len(findings),
        by_severity=by_severity,
        by_status=by_status,
        by_layer=by_layer,
        by_category=by_category,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get finding by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("findings").select("*").eq("id", finding_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Check access
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if result.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return FindingResponse(**result.data)


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    finding_data: FindingUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Update finding (status, assignment, suppression)"""
    supabase: Client = get_supabase()
    
    result = supabase.table("findings").select("*").eq("id", finding_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Check access
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    org_roles = {o["organization_id"]: o["role"] for o in orgs.data}
    
    if result.data["organization_id"] not in org_roles:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = finding_data.model_dump(exclude_unset=True)
    
    # Handle status changes
    if "status" in update_data:
        new_status = update_data["status"]
        if new_status in ["fixed", "false_positive", "wont_fix", "accepted_risk"]:
            update_data["triaged_by"] = current_user.user_id
            update_data["triaged_at"] = datetime.utcnow().isoformat()
            if new_status == "fixed":
                update_data["fixed_at"] = datetime.utcnow().isoformat()
        
        if new_status == "accepted_risk" and not finding_data.suppression_reason:
            raise HTTPException(status_code=400, detail="Suppression reason required for accepted risk")
    
    if update_data:
        supabase.table("findings").update(update_data).eq("id", finding_id).execute()
    
    # Return updated finding
    updated = supabase.table("findings").select("*").eq("id", finding_id).single().execute()
    return FindingResponse(**updated.data)


@router.post("/bulk-update")
async def bulk_update_findings(
    finding_ids: List[str],
    finding_data: FindingUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Bulk update multiple findings"""
    supabase: Client = get_supabase()
    
    # Check access for all findings
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    org_roles = {o["organization_id"]: o["role"] for o in orgs.data}
    
    for finding_id in finding_ids:
        result = supabase.table("findings").select("organization_id").eq("id", finding_id).single().execute()
        if not result.data or result.data["organization_id"] not in org_roles:
            raise HTTPException(status_code=403, detail=f"Not authorized for finding {finding_id}")
    
    update_data = finding_data.model_dump(exclude_unset=True)
    
    if "status" in update_data:
        new_status = update_data["status"]
        if new_status in ["fixed", "false_positive", "wont_fix", "accepted_risk"]:
            update_data["triaged_by"] = current_user.user_id
            update_data["triaged_at"] = datetime.utcnow().isoformat()
            if new_status == "fixed":
                update_data["fixed_at"] = datetime.utcnow().isoformat()
    
    if update_data:
        supabase.table("findings").update(update_data).in_("id", finding_ids).execute()
    
    return {"message": f"Updated {len(finding_ids)} findings", "updated": len(finding_ids)}