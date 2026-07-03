"""
ASL V6 SaaS Backend - Repositories Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from supabase import Client

router = APIRouter()


class RepositoryConnect(BaseModel):
    github_repo_id: str
    owner: str
    name: str
    full_name: str
    url: str
    clone_url: str
    default_branch: str = "main"
    description: Optional[str] = None
    language: Optional[str] = None
    stars: int = 0
    forks: int = 0
    size_kb: int = 0
    is_private: bool = True
    is_archived: bool = False
    is_fork: bool = False


class RepositoryResponse(BaseModel):
    id: str
    project_id: str
    provider: str
    provider_repo_id: str
    owner: str
    name: str
    full_name: str
    url: str
    clone_url: str
    default_branch: str
    description: Optional[str] = None
    language: Optional[str] = None
    stars: int
    forks: int
    size_kb: int
    is_private: bool
    is_archived: bool
    is_fork: bool
    webhook_id: Optional[int] = None
    last_synced_at: Optional[datetime] = None
    settings: dict
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0
    last_scan_status: Optional[str] = None


class RepositoryListResponse(BaseModel):
    repositories: List[RepositoryResponse]
    total: int
    page: int
    page_size: int


@router.post("/connect", response_model=RepositoryResponse, status_code=201)
async def connect_repository(
    repo_data: RepositoryConnect,
    project_id: str = Query(..., alias="project_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Connect a GitHub repository to a project"""
    supabase: Client = get_supabase()
    
    # Check project access
    project = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    if not project.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin", "member"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check if repo already connected
    existing = supabase.table("repositories").select("id").eq("project_id", project_id).eq("provider_repo_id", repo_data.github_repo_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Repository already connected to this project")
    
    # Create repository record
    repo = {
        "project_id": project_id,
        "provider": "github",
        "provider_repo_id": repo_data.github_repo_id,
        "owner": repo_data.owner,
        "name": repo_data.name,
        "full_name": repo_data.full_name,
        "url": repo_data.url,
        "clone_url": repo_data.clone_url,
        "default_branch": repo_data.default_branch,
        "description": repo_data.description,
        "language": repo_data.language,
        "stars": repo_data.stars,
        "forks": repo_data.forks,
        "size_kb": repo_data.size_kb,
        "is_private": repo_data.is_private,
        "is_archived": repo_data.is_archived,
        "is_fork": repo_data.is_fork,
        "settings": {},
    }
    
    result = supabase.table("repositories").insert(repo).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to connect repository")
    
    return RepositoryResponse(**result.data[0], scan_count=0)


@router.get("/", response_model=RepositoryListResponse)
async def list_repositories(
    project_id: str = Query(..., alias="project_id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """List repositories in a project"""
    supabase: Client = get_supabase()
    
    # Check project access
    project = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    if not project.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    query = supabase.table("repositories").select("*", count="exact").eq("project_id", project_id)
    
    if search:
        query = query.or_(f"name.ilike.%{search}%,full_name.ilike.%{search}%")
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True)
    
    result = query.execute()
    
    # Get scan counts for each repo
    repos = []
    for r in result.data:
        scan_count = supabase.table("scans").select("id", count="exact").eq("repository_id", r["id"]).execute()
        last_scan = supabase.table("scans").select("status").eq("repository_id", r["id"]).order("created_at", desc=True).limit(1).execute()
        
        repos.append(RepositoryResponse(
            **r,
            scan_count=scan_count.count or 0,
            last_scan_status=last_scan.data[0]["status"] if last_scan.data else None,
        ))
    
    return RepositoryListResponse(
        repositories=repos,
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{repo_id}", response_model=RepositoryResponse)
async def get_repository(repo_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get repository by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("repositories").select("*").eq("id", repo_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    # Check access
    project = supabase.table("projects").select("*").eq("id", result.data["project_id"]).single().execute()
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    scan_count = supabase.table("scans").select("id", count="exact").eq("repository_id", repo_id).execute()
    last_scan = supabase.table("scans").select("status").eq("repository_id", repo_id).order("created_at", desc=True).limit(1).execute()
    
    return RepositoryResponse(
        **result.data,
        scan_count=scan_count.count or 0,
        last_scan_status=last_scan.data[0]["status"] if last_scan.data else None,
    )


@router.delete("/{repo_id}")
async def disconnect_repository(repo_id: str, current_user: TokenData = Depends(get_current_user)):
    """Disconnect repository from project"""
    supabase: Client = get_supabase()
    
    result = supabase.table("repositories").select("*").eq("id", repo_id).single().execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    project = supabase.table("projects").select("*").eq("id", result.data["project_id"]).single().execute()
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    supabase.table("repositories").delete().eq("id", repo_id).execute()
    
    return {"message": "Repository disconnected successfully"}


@router.post("/{repo_id}/sync")
async def sync_repository(repo_id: str, current_user: TokenData = Depends(get_current_user)):
    """Sync repository metadata from GitHub"""
    supabase: Client = get_supabase()
    
    result = supabase.table("repositories").select("*").eq("id", repo_id).single().execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    project = supabase.table("projects").select("*").eq("id", result.data["project_id"]).single().execute()
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # TODO: Implement GitHub API sync
    # This would fetch latest repo info from GitHub API
    
    supabase.table("repositories").update({"last_synced_at": datetime.utcnow().isoformat()}).eq("id", repo_id).execute()
    
    return {"message": "Repository synced successfully"}