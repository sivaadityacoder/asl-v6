"""
ASL V6 SaaS Backend - Organizations Endpoints
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


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=100, pattern="^[a-z0-9-]+$")
    description: Optional[str] = None


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    slug: Optional[str] = Field(None, min_length=1, max_length=100, pattern="^[a-z0-9-]+$")
    description: Optional[str] = None
    logo_url: Optional[str] = None
    settings: Optional[dict] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    logo_url: Optional[str] = None
    owner_id: str
    plan_tier: str
    settings: dict
    created_at: datetime
    updated_at: datetime
    member_count: int = 0
    project_count: int = 0


class OrganizationListResponse(BaseModel):
    organizations: List[OrganizationResponse]
    total: int
    page: int
    page_size: int


class MemberInvite(BaseModel):
    email: str
    role: str = "member"


class MemberResponse(BaseModel):
    id: str
    organization_id: str
    user_id: str
    role: str
    invited_by: Optional[str] = None
    invited_at: datetime
    joined_at: Optional[datetime] = None
    user: dict


@router.post("/", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    org_data: OrganizationCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Create a new organization"""
    supabase: Client = get_supabase()
    
    # Check if slug is unique
    existing = supabase.table("organizations").select("id").eq("slug", org_data.slug).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Organization slug already exists")
    
    # Create organization
    org = {
        "name": org_data.name,
        "slug": org_data.slug,
        "description": org_data.description,
        "owner_id": current_user.user_id,
        "plan_tier": "starter",
        "settings": {},
    }
    
    result = supabase.table("organizations").insert(org).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create organization")
    
    org_id = result.data[0]["id"]
    
    # Add creator as owner
    supabase.table("organization_members").insert({
        "organization_id": org_id,
        "user_id": current_user.user_id,
        "role": "owner",
        "joined_at": datetime.utcnow().isoformat(),
    }).execute()
    
    return OrganizationResponse(**result.data[0], member_count=1, project_count=0)


@router.get("/", response_model=OrganizationListResponse)
async def list_organizations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List organizations user belongs to"""
    supabase: Client = get_supabase()
    
    # Get user's organizations
    memberships = supabase.table("organization_members").select("organization_id, role").eq("user_id", current_user.user_id).execute()
    
    if not memberships.data:
        return OrganizationListResponse(organizations=[], total=0, page=page, page_size=page_size)
    
    org_ids = [m["organization_id"] for m in memberships.data]
    
    # Get organization details
    orgs = supabase.table("organizations").select("*").in_("id", org_ids).range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True).execute()
    
    # Get counts for each org
    organizations = []
    for org in orgs.data:
        member_count = supabase.table("organization_members").select("id", count="exact").eq("organization_id", org["id"]).execute()
        project_count = supabase.table("projects").select("id", count="exact").eq("organization_id", org["id"]).execute()
        
        organizations.append(OrganizationResponse(
            **org,
            member_count=member_count.count or 0,
            project_count=project_count.count or 0,
        ))
    
    return OrganizationListResponse(
        organizations=organizations,
        total=len(org_ids),
        page=page,
        page_size=page_size,
    )


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(org_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get organization by ID"""
    supabase: Client = get_supabase()
    
    # Check membership
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    result = supabase.table("organizations").select("*").eq("id", org_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    member_count = supabase.table("organization_members").select("id", count="exact").eq("organization_id", org_id).execute()
    project_count = supabase.table("projects").select("id", count="exact").eq("organization_id", org_id).execute()
    
    return OrganizationResponse(
        **result.data,
        member_count=member_count.count or 0,
        project_count=project_count.count or 0,
    )


@router.put("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str,
    org_data: OrganizationUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Update organization"""
    supabase: Client = get_supabase()
    
    # Check if user is admin/owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can update organization")
    
    # Check slug uniqueness if changed
    if org_data.slug:
        existing = supabase.table("organizations").select("id").eq("slug", org_data.slug).neq("id", org_id).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Organization slug already exists")
    
    update_data = org_data.model_dump(exclude_unset=True)
    if update_data:
        result = supabase.table("organizations").update(update_data).eq("id", org_id).execute()
        return OrganizationResponse(**result.data[0])
    
    return await get_organization(org_id, current_user)


@router.delete("/{org_id}")
async def delete_organization(org_id: str, current_user: TokenData = Depends(get_current_user)):
    """Delete organization (owner only)"""
    supabase: Client = get_supabase()
    
    # Check if user is owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] != "owner":
        raise HTTPException(status_code=403, detail="Only organization owner can delete organization")
    
    # Soft delete - mark as inactive (or actually delete with cascade)
    supabase.table("organizations").delete().eq("id", org_id).execute()
    
    return {"message": "Organization deleted successfully"}


@router.get("/{org_id}/members", response_model=List[MemberResponse])
async def list_members(
    org_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """List organization members"""
    supabase: Client = get_supabase()
    
    # Check membership
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    result = supabase.table("organization_members").select("*, users(*)").eq("organization_id", org_id).execute()
    
    members = []
    for m in result.data:
        user_data = m.pop("users", {})
        members.append(MemberResponse(**m, user=user_data))
    
    return members


@router.post("/{org_id}/members/invite", response_model=MemberResponse, status_code=201)
async def invite_member(
    org_id: str,
    invite: MemberInvite,
    current_user: TokenData = Depends(get_current_user),
):
    """Invite a user to organization"""
    supabase: Client = get_supabase()
    
    # Check if user is admin/owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can invite members")
    
    # Find user by email
    user = supabase.table("users").select("id").eq("email", invite.email).execute()
    
    if not user.data:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user.data[0]["id"]
    
    # Check if already a member
    existing = supabase.table("organization_members").select("id").eq("organization_id", org_id).eq("user_id", user_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="User is already a member")
    
    # Create membership
    membership = {
        "organization_id": org_id,
        "user_id": user_id,
        "role": invite.role,
        "invited_by": current_user.user_id,
        "invited_at": datetime.utcnow().isoformat(),
    }
    
    result = supabase.table("organization_members").insert(membership).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to invite member")
    
    return MemberResponse(**result.data[0], user=user.data[0])


@router.put("/{org_id}/members/{user_id}")
async def update_member_role(
    org_id: str,
    user_id: str,
    role: str = Query(..., pattern="^(owner|admin|member|viewer)$"),
    current_user: TokenData = Depends(get_current_user),
):
    """Update member role"""
    supabase: Client = get_supabase()
    
    # Check if current user is owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] != "owner":
        raise HTTPException(status_code=403, detail="Only organization owner can change roles")
    
    # Can't change own role
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    
    # Update role
    supabase.table("organization_members").update({"role": role}).eq("organization_id", org_id).eq("user_id", user_id).execute()
    
    return {"message": "Role updated successfully"}


@router.delete("/{org_id}/members/{user_id}")
async def remove_member(
    org_id: str,
    user_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """Remove member from organization"""
    supabase: Client = get_supabase()
    
    # Check if current user is admin/owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can remove members")
    
    # Can't remove self
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")
    
    # Can't remove owner
    target = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", user_id).execute()
    if target.data and target.data[0]["role"] == "owner":
        raise HTTPException(status_code=400, detail="Cannot remove organization owner")
    
    supabase.table("organization_members").delete().eq("organization_id", org_id).eq("user_id", user_id).execute()
    
    return {"message": "Member removed successfully"}