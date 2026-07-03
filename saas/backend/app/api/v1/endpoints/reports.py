"""
ASL V6 SaaS Backend - Reports Endpoints
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


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"


class ReportCreate(BaseModel):
    scan_id: str
    title: str
    format: ReportFormat


class ReportResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    organization_id: str
    title: str
    format: ReportFormat
    status: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    download_url: Optional[str] = None
    expires_at: Optional[datetime] = None
    generated_at: Optional[datetime] = None
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ReportListResponse(BaseModel):
    reports: List[ReportResponse]
    total: int
    page: int
    page_size: int


@router.post("/", response_model=ReportResponse, status_code=201)
async def create_report(
    report_data: ReportCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Generate a report for a scan"""
    supabase: Client = get_supabase()
    
    # Check scan access
    scan = supabase.table("scans").select("*").eq("id", report_data.scan_id).single().execute()
    if not scan.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    org_roles = {o["organization_id"]: o["role"] for o in orgs.data}
    
    if scan.data["organization_id"] not in org_roles:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Create report record
    report = {
        "scan_id": report_data.scan_id,
        "project_id": scan.data["project_id"],
        "organization_id": scan.data["organization_id"],
        "title": report_data.title,
        "format": report_data.format.value,
        "status": "generating",
    }
    
    result = supabase.table("reports").insert(report).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create report")
    
    # TODO: Queue report generation task
    # background_tasks.add_task(generate_report_task, result.data[0]["id"])
    
    return ReportResponse(**result.data[0])


@router.get("/", response_model=ReportListResponse)
async def list_reports(
    scan_id: Optional[str] = Query(None, alias="scan_id"),
    project_id: Optional[str] = Query(None, alias="project_id"),
    format: Optional[ReportFormat] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List reports"""
    supabase: Client = get_supabase()
    
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if not org_ids:
        return ReportListResponse(reports=[], total=0, page=page, page_size=page_size)
    
    query = supabase.table("reports").select("*", count="exact").in_("organization_id", org_ids)
    
    if scan_id:
        query = query.eq("scan_id", scan_id)
    if project_id:
        query = query.eq("project_id", project_id)
    if format:
        query = query.eq("format", format.value)
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True)
    
    result = query.execute()
    
    return ReportListResponse(
        reports=[ReportResponse(**r) for r in result.data],
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get report by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("reports").select("*").eq("id", report_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Report not found")
    
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if result.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return ReportResponse(**result.data)


@router.get("/{report_id}/download")
async def download_report(report_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get download URL for report"""
    supabase: Client = get_supabase()
    
    result = supabase.table("reports").select("*").eq("id", report_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Report not found")
    
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    
    if result.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if result.data["status"] != "completed":
        raise HTTPException(status_code=400, detail="Report not ready")
    
    if not result.data["file_path"]:
        raise HTTPException(status_code=404, detail="Report file not found")
    
    # Generate signed URL
    signed_url = supabase.storage.from_("reports").create_signed_url(
        result.data["file_path"], 3600  # 1 hour
    )
    
    if "signedURL" not in signed_url:
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    
    return {"download_url": signed_url["signedURL"], "expires_in": 3600}


@router.delete("/{report_id}")
async def delete_report(report_id: str, current_user: TokenData = Depends(get_current_user)):
    """Delete report"""
    supabase: Client = get_supabase()
    
    result = supabase.table("reports").select("*").eq("id", report_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Report not found")
    
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    org_roles = {o["organization_id"]: o["role"] for o in orgs.data}
    
    if result.data["organization_id"] not in org_roles or org_roles[result.data["organization_id"]] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Delete from storage
    if result.data["file_path"]:
        supabase.storage.from_("reports").remove([result.data["file_path"]])
    
    # Delete from database
    supabase.table("reports").delete().eq("id", report_id).execute()
    
    return {"message": "Report deleted successfully"}