"""
ASL V6 SaaS Backend - Projects Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from supabase import Client

router = APIRouter()


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=100, pattern="^[a-z0-9-]+$")
    description: Optional[str] = None
    avatar_url: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    slug: Optional[str] = Field(None, min_length=1, max_length=100, pattern="^[a-z0-9-]+$")
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: Optional[bool] = None
    settings: Optional[dict] = None


class ProjectResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    settings: dict
    is_active: bool
    created_at: datetime
    updated_at: datetime
    repository_count: int = 0
    scan_count: int = 0


class ProjectListResponse(BaseModel):
    projects: List[ProjectResponse]
    total: int
    page: int
    page_size: int


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(
    project_data: ProjectCreate,
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Create a new project"""
    supabase: Client = get_supabase()
    
    # Check if user is member of organization
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    
    if not member.data:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    # Check if slug is unique within organization
    existing = supabase.table("projects").select("id").eq("organization_id", org_id).eq("slug", project_data.slug).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Project slug already exists in this organization")
    
    # Create project
    project = {
        "organization_id": org_id,
        "name": project_data.name,
        "slug": project_data.slug,
        "description": project_data.description,
        "avatar_url": project_data.avatar_url,
        "settings": {},
        "is_active": True,
    }
    
    result = supabase.table("projects").insert(project).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create project")
    
    return ProjectResponse(**result.data[0])


@router.get("/", response_model=ProjectListResponse)
async def list_projects(
    org_id: str = Query(..., alias="organization_id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """List projects in an organization"""
    supabase: Client = get_supabase()
    
    # Check membership
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    query = supabase.table("projects").select("*", count="exact").eq("organization_id", org_id)
    
    if search:
        query = query.or_(f"name.ilike.%{search}%,description.ilike.%{search}%")
    if is_active is not None:
        query = query.eq("is_active", is_active)
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True)
    
    result = query.execute()
    
    # Get repository and scan counts for each project
    projects = []
    for p in result.data:
        repo_count = supabase.table("repositories").select("id", count="exact").eq("project_id", p["id"]).execute()
        scan_count = supabase.table("scans").select("id", count="exact").eq("project_id", p["id"]).execute()
        
        projects.append(ProjectResponse(
            **p,
            repository_count=repo_count.count or 0,
            scan_count=scan_count.count or 0,
        ))
    
    return ProjectListResponse(
        projects=projects,
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get project by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check membership
    member = supabase.table("organization_members").select("role").eq("organization_id", result.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get counts
    repo_count = supabase.table("repositories").select("id", count="exact").eq("project_id", project_id).execute()
    scan_count = supabase.table("scans").select("id", count="exact").eq("project_id", project_id).execute()
    
    return ProjectResponse(
        **result.data,
        repository_count=repo_count.count or 0,
        scan_count=scan_count.count or 0,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_data: ProjectUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Update project"""
    supabase: Client = get_supabase()
    
    # Get project
    project = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    if not project.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if user is admin/owner of organization
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check slug uniqueness if changed
    if project_data.slug and project_data.slug != project.data["slug"]:
        existing = supabase.table("projects").select("id").eq("organization_id", project.data["organization_id"]).eq("slug", project_data.slug).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Project slug already exists in this organization")
    
    update_data = project_data.model_dump(exclude_unset=True)
    if update_data:
        result = supabase.table("projects").update(update_data).eq("id", project_id).execute()
        return ProjectResponse(**result.data[0])
    
    return await get_project(project_id, current_user)


@router.delete("/{project_id}")
async def delete_project(project_id: str, current_user: TokenData = Depends(get_current_user)):
    """Delete project (soft delete)"""
    supabase: Client = get_supabase()
    
    project = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    if not project.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if user is admin/owner
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    supabase.table("projects").update({"is_active": False}).eq("id", project_id).execute()
    
    return {"message": "Project deleted successfully"}


@router.get("/{project_id}/stats")
async def get_project_stats(project_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get project statistics"""
    supabase: Client = get_supabase()
    
    project = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    if not project.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check membership
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get stats
    repo_count = supabase.table("repositories").select("id", count="exact").eq("project_id", project_id).execute()
    scan_count = supabase.table("scans").select("id", count="exact").eq("project_id", project_id).execute()
    
    # Get recent scans
    recent_scans = supabase.table("scans").select("*").eq("project_id", project_id).order("created_at", desc=True).limit(5).execute()
    
    # Get finding counts by severity
    findings = supabase.table("findings").select("severity", count="exact").eq("project_id", project_id).execute()
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings.data:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
    
    return {
        "repository_count": repo_count.count or 0,
        "scan_count": scan_count.count or 0,
        "recent_scans": recent_scans.data,
        "findings_by_severity": severity_counts,
    }