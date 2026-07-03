"""
ASL V6 SaaS Backend - Webhooks Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import hmac
import hashlib
import json

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from app.core.config import settings
from supabase import Client

router = APIRouter()


class WebhookCreate(BaseModel):
    url: str
    events: List[str]
    secret: Optional[str] = None


class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    events: Optional[List[str]] = None
    is_active: Optional[bool] = None


class WebhookResponse(BaseModel):
    id: str
    organization_id: str
    url: str
    events: List[str]
    is_active: bool
    last_triggered_at: Optional[datetime] = None
    failure_count: int
    created_at: datetime
    updated_at: datetime


class WebhookListResponse(BaseModel):
    webhooks: List[WebhookResponse]
    total: int
    page: int
    page_size: int


class WebhookDeliveryResponse(BaseModel):
    id: str
    webhook_id: str
    event_type: str
    payload: dict
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    attempt: int
    max_attempts: int
    next_retry_at: Optional[datetime] = None
    succeeded_at: Optional[datetime] = None
    error: Optional[str] = None
    created_at: datetime


# Supported webhook events
WEBHOOK_EVENTS = [
    "scan.created",
    "scan.started",
    "scan.layer_started",
    "scan.layer_completed",
    "scan.completed",
    "scan.failed",
    "scan.cancelled",
    "finding.created",
    "finding.updated",
    "report.generated",
    "repository.connected",
    "repository.disconnected",
]


@router.post("/", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    webhook_data: WebhookCreate,
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Create a webhook"""
    supabase: Client = get_supabase()
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can manage webhooks")
    
    # Validate events
    invalid_events = [e for e in webhook_data.events if e not in WEBHOOK_EVENTS]
    if invalid_events:
        raise HTTPException(status_code=400, detail=f"Invalid events: {invalid_events}")
    
    # Generate secret if not provided
    secret = webhook_data.secret or hashlib.sha256(f"{org_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:32]
    
    webhook = {
        "organization_id": org_id,
        "url": webhook_data.url,
        "secret": secret,
        "events": webhook_data.events,
        "is_active": True,
        "failure_count": 0,
    }
    
    result = supabase.table("webhooks").insert(webhook).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create webhook")
    
    return WebhookResponse(**result.data[0])


@router.get("/", response_model=WebhookListResponse)
async def list_webhooks(
    org_id: str = Query(..., alias="organization_id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List webhooks"""
    supabase: Client = get_supabase()
    
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can view webhooks")
    
    result = supabase.table("webhooks").select("*", count="exact").eq("organization_id", org_id).range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True).execute()
    
    return WebhookListResponse(
        webhooks=[WebhookResponse(**w) for w in result.data],
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/events")
async def list_webhook_events(current_user: TokenData = Depends(get_current_user)):
    """Get list of supported webhook events"""
    return {"events": WEBHOOK_EVENTS}


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(webhook_id: str, current_user: TokenData = Depends(get_current_user)):
    """Get webhook by ID"""
    supabase: Client = get_supabase()
    
    result = supabase.table("webhooks").select("*").eq("id", webhook_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", result.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return WebhookResponse(**result.data)


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    webhook_data: WebhookUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    """Update webhook"""
    supabase: Client = get_supabase()
    
    result = supabase.table("webhooks").select("*").eq("id", webhook_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", result.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Validate events if provided
    if webhook_data.events:
        invalid_events = [e for e in webhook_data.events if e not in WEBHOOK_EVENTS]
        if invalid_events:
            raise HTTPException(status_code=400, detail=f"Invalid events: {invalid_events}")
    
    update_data = webhook_data.model_dump(exclude_unset=True)
    if update_data:
        supabase.table("webhooks").update(update_data).eq("id", webhook_id).execute()
    
    updated = supabase.table("webhooks").select("*").eq("id", webhook_id).single().execute()
    return WebhookResponse(**updated.data)


@router.delete("/{webhook_id}")
async def delete_webhook(webhook_id: str, current_user: TokenData = Depends(get_current_user)):
    """Delete webhook"""
    supabase: Client = get_supabase()
    
    result = supabase.table("webhooks").select("*").eq("id", webhook_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", result.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    supabase.table("webhooks").delete().eq("id", webhook_id).execute()
    
    return {"message": "Webhook deleted successfully"}


@router.get("/{webhook_id}/deliveries", response_model=List[WebhookDeliveryResponse])
async def list_webhook_deliveries(
    webhook_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List webhook delivery attempts"""
    supabase: Client = get_supabase()
    
    result = supabase.table("webhooks").select("organization_id").eq("id", webhook_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", result.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    deliveries = supabase.table("webhook_deliveries").select("*").eq("webhook_id", webhook_id).range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True).execute()
    
    return [WebhookDeliveryResponse(**d) for d in deliveries.data]


@router.post("/{webhook_id}/test")
async def test_webhook(webhook_id: str, current_user: TokenData = Depends(get_current_user)):
    """Send a test webhook"""
    supabase: Client = get_supabase()
    
    result = supabase.table("webhooks").select("*").eq("id", webhook_id).single().execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", result.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Send test payload
    test_payload = {
        "event": "webhook.test",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {"message": "This is a test webhook from ASL V6"},
    }
    
    await _deliver_webhook(result.data, test_payload)
    
    return {"message": "Test webhook sent"}


async def _deliver_webhook(webhook: dict, payload: dict):
    """Deliver webhook with retries"""
    import httpx
    
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Create signature
                secret = webhook["secret"].encode()
                payload_bytes = json.dumps(payload).encode()
                signature = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
                
                headers = {
                    "Content-Type": "application/json",
                    "X-ASL-Signature": f"sha256={signature}",
                    "X-ASL-Event": payload.get("event", "unknown"),
                    "X-ASL-Delivery": webhook["id"],
                }
                
                response = await client.post(webhook["url"], json=payload, headers=headers)
                
                if 200 <= response.status_code < 300:
                    # Success
                    supabase = get_supabase()
                    supabase.table("webhook_deliveries").insert({
                        "webhook_id": webhook["id"],
                        "event_type": payload.get("event", "unknown"),
                        "payload": payload,
                        "response_status": response.status_code,
                        "response_body": response.text[:1000] if response.text else None,
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "succeeded_at": datetime.utcnow().isoformat(),
                    }).execute()
                    
                    supabase.table("webhooks").update({
                        "last_triggered_at": datetime.utcnow().isoformat(),
                        "failure_count": 0,
                    }).eq("id", webhook["id"]).execute()
                    
                    return
                else:
                    raise Exception(f"HTTP {response.status_code}: {response.text}")
                    
        except Exception as e:
            if attempt == max_attempts:
                # Final failure
                supabase = get_supabase()
                supabase.table("webhook_deliveries").insert({
                    "webhook_id": webhook["id"],
                    "event_type": payload.get("event", "unknown"),
                    "payload": payload,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "error": str(e),
                }).execute()
                
                supabase.table("webhooks").update({
                    "failure_count": webhook.get("failure_count", 0) + 1,
                }).eq("id", webhook["id"]).execute()
            else:
                # Wait before retry (exponential backoff)
                import asyncio
                await asyncio.sleep(2 ** attempt)


# Internal function to trigger webhooks (called from other services)
async def trigger_webhook(event_type: str, organization_id: str, payload: dict):
    """Trigger webhooks for an event"""
    supabase: Client = get_supabase()
    
    webhooks = supabase.table("webhooks").select("*").eq("organization_id", organization_id).eq("is_active", True).contains("events", [event_type]).execute()
    
    for webhook in webhooks.data:
        await _deliver_webhook(webhook, payload)