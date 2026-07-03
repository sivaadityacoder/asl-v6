"""
ASL V6 SaaS Backend - Rules Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
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


class RuleCreate(BaseModel):
    rule_id: str = Field(..., pattern="^[A-Z0-9-]+$")
    name: str
    description: str
    category: str
    severity: FindingSeverity
    layer: int = Field(..., ge=1, le=10)
    language: Optional[str] = None
    pattern: Optional[str] = None
    ast_pattern: Optional[Dict[str, Any]] = None
    is_custom: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[FindingSeverity] = None
    layer: Optional[int] = Field(None, ge=1, le=10)
    language: Optional[str] = None
    pattern: Optional[str] = None
    ast_pattern: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class RuleResponse(BaseModel):
    id: str
    rule_id: str
    name: str
    description: str
    category: str
    severity: FindingSeverity
    layer: int
    language: Optional[str] = None
    pattern: Optional[str] = None
    ast_pattern: Optional[Dict[str, Any]] = None
    is_active: bool
    is_custom: bool
    created_by: Optional[str] = None
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RuleListResponse(BaseModel):
    rules: List[RuleResponse]
    total: int
    page: int
    page_size: int


@router.post("/", response_model=RuleResponse, status_code=201)
async def create_rule(
    rule_data: RuleCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Create a custom rule"""
    supabase: Client = get_supabase()
    
    # Check if user is admin in any organization
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    is_admin = any(o["role"] in ["owner", "admin"] for o in orgs.data)
    
    if not is_admin:
        raise HTTPException(status_code=403, detail="Only organization admins can create custom rules")
    
    # Check if rule_id already exists
    existing = supabase.table("rules").select("id").eq("rule_id", rule_data.rule_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Rule ID already exists")
    
    rule = {
        "rule_id": rule_data.rule_id,
        "name": rule_data.name,
        "description": rule_data.description,
        "category": rule_data.category,
        "severity": rule_data.severity.value,
        "layer": rule_data.layer,
        "language": rule_data.language,
        "pattern": rule_data.pattern,
        "ast_pattern": rule_data.ast_pattern,
        "is_active": True,
        "is_custom": True,
        "created_by": current_user.user_id,
        "metadata": {},
    }
    
    result = supabase.table("rules").insert(rule).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create rule")
    
    return RuleResponse(**result.data[0])


@router.get("/", response_model=RuleListResponse)
async def list_rules(
    category: Optional[str] = None,
    layer: Optional[int] = Query(None, ge=1, le=10),
    severity: Optional[FindingSeverity] = None,
    language: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_custom: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List rules"""
    supabase: Client = get_supabase()
    
    query = supabase.table("rules").select("*", count="exact")
    
    if category:
        query = query.eq("category", category)
    if layer:
        query = query.eq("layer", layer)
    if severity:
        query = query.eq("severity", severity.value)
    if language:
        query = query.eq("language", language)
    if is_active is not None:
        query = query.eq("is_active", is_active)
    if is_custom is not None:
        query = query.eq("is_custom", is_custom)
    
    query = query.range((page - 1) * page_size, page * page_size - 1).order("layer").order("category").order("rule_id")
    
    result = query.execute()
    
    return RuleListResponse(
        rules=[RuleResponse(**r) for r in result.data],
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/categories")
async def get_rule_categories(current_user: TokenData = Depends(get_current_user)):
    """Get unique rule categories"""
    supabase: Client = get_supabase()
    
    result = supabase.table("rules").select("category").execute()
    
    categories = list(set(r["category"] for r in result.data if r.get("category")))
    categories.sort()
    
    return {"categories": categories}


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get rule by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("rules").select("*").eq("rule_id", rule_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return RuleResponse(**result.data)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    rule_data: RuleUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Update a custom rule"""
    supabase: Client = get_supabase()
    
    result = supabase.table("rules").select("*").eq("rule_id", rule_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    if not result.data.get("is_custom"):
        raise HTTPException(status_code=400, detail="Cannot update built-in rules")
    
    # Check if user is admin
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    is_admin = any(o["role"] in ["owner", "admin"] for o in orgs.data)
    
    if not is_admin:
        raise HTTPException(status_code=403, detail="Only organization admins can update custom rules")
    
    update_data = rule_data.model_dump(exclude_unset=True)
    if update_data:
        supabase.table("rules").update(update_data).eq("rule_id", rule_id).execute()
    
    updated = supabase.table("rules").select("*").eq("rule_id", rule_id).single().execute()
    return RuleResponse(**updated.data)


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, current_user: TokenData = Depends(get_current_user)):
    """Delete a custom rule"""
    supabase: Client = get_supabase()
    
    result = supabase.table("rules").select("*").eq("rule_id", rule_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    if not result.data.get("is_custom"):
        raise HTTPException(status_code=400, detail="Cannot delete built-in rules")
    
    # Check if user is admin
    orgs = supabase.table("organization_members").select("role, organization_id").eq("user_id", current_user.user_id).execute()
    is_admin = any(o["role"] in ["owner", "admin"] for o in orgs.data)
    
    if not is_admin:
        raise HTTPException(status_code=403, detail="Only organization admins can delete custom rules")
    
    supabase.table("rules").delete().eq("rule_id", rule_id).execute()
    
    return {"message": "Rule deleted successfully"}