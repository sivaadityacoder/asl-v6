"""
ASL V6 SaaS Backend - Users Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from supabase import Client

router = APIRouter()


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    github_username: Optional[str] = None
    role: str
    plan_tier: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    page_size: int


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """List users (admin only)"""
    # Check if user is admin
    supabase: Client = get_supabase()
    user = supabase.table("users").select("role").eq("id", current_user.user_id).single().execute()
    
    if not user.data or user.data.get("role") not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    query = supabase.table("users").select("*", count="exact")
    
    if search:
        query = query.or_(f"email.ilike.%{search}%,full_name.ilike.%{search}%")
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True)
    
    result = query.execute()
    
    return UserListResponse(
        users=[UserResponse(**u) for u in result.data],
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get user by ID"""
    supabase: Client = get_supabase()
    
    # Users can only view their own profile unless admin
    if current_user.user_id != user_id:
        user = supabase.table("users").select("role").eq("id", current_user.user_id).single().execute()
        if not user.data or user.data.get("role") not in ["owner", "admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    result = supabase.table("users").select("*").eq("id", user_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(**result.data)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Update user"""
    supabase: Client = get_supabase()
    
    # Users can only update their own profile unless admin
    if current_user.user_id != user_id:
        user = supabase.table("users").select("role").eq("id", current_user.user_id).single().execute()
        if not user.data or user.data.get("role") not in ["owner", "admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = user_data.model_dump(exclude_unset=True)
    if update_data:
        result = supabase.table("users").update(update_data).eq("id", user_id).execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="User not found")
        return UserResponse(**result.data[0])
    
    return await get_user(user_id, current_user)


@router.delete("/{user_id}")
async def delete_user(user_id: str, current_user: TokenData = Depends(get_current_user)):
    """Delete user (admin only)"""
    supabase: Client = get_supabase()
    
    # Check admin
    user = supabase.table("users").select("role").eq("id", current_user.user_id).single().execute()
    if not user.data or user.data.get("role") not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Soft delete
    supabase.table("users").update({"is_active": False}).eq("id", user_id).execute()
    
    return {"message": "User deleted successfully"}


@router.get("/{user_id}/organizations")
async def get_user_organizations(user_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get organizations user belongs to"""
    if current_user.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    supabase: Client = get_supabase()
    
    result = supabase.table("organization_members").select(
        "*, organizations(*)"
    ).eq("user_id", user_id).execute()
    
    return result.data