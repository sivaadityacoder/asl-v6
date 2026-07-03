"""
ASL V6 SaaS Backend - Billing Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import stripe
import os

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from app.core.config import settings
from supabase import Client

router = APIRouter()

# Initialize Stripe
if settings.stripe_secret_key:
    stripe.api_key = settings.stripe_secret_key


class CheckoutSessionRequest(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str


class CheckoutSessionResponse(BaseModel):
    session_id: str
    url: str


class SubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    stripe_subscription_id: str
    plan_tier: str
    status: str
    current_period_start: datetime
    current_period_end: datetime
    cancel_at_period_end: bool
    canceled_at: Optional[datetime] = None


class InvoiceResponse(BaseModel):
    id: str
    organization_id: str
    stripe_invoice_id: str
    amount: int
    currency: str
    status: str
    invoice_url: Optional[str] = None
    invoice_pdf: Optional[str] = None
    period_start: datetime
    period_end: datetime
    paid_at: Optional[datetime] = None


class BillingPortalResponse(BaseModel):
    url: str


@router.post("/checkout", response_model=CheckoutSessionResponse)
async def create_checkout_session(
    request: CheckoutSessionRequest,
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Create Stripe checkout session for subscription"""
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Billing not configured")
    
    supabase: Client = get_supabase()
    
    # Check if user is admin/owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can manage billing")
    
    # Get or create Stripe customer
    org = supabase.table("organizations").select("stripe_customer_id").eq("id", org_id).single().execute()
    
    customer_id = org.data.get("stripe_customer_id") if org.data else None
    
    if not customer_id:
        # Create Stripe customer
        user = supabase.table("users").select("email, full_name").eq("id", current_user.user_id).single().execute()
        customer = stripe.Customer.create(
            email=user.data["email"],
            name=user.data.get("full_name"),
            metadata={"organization_id": org_id},
        )
        customer_id = customer.id
        supabase.table("organizations").update({"stripe_customer_id": customer_id}).eq("id", org_id).execute()
    
    # Create checkout session
    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": request.price_id, "quantity": 1}],
        mode="subscription",
        success_url=request.success_url,
        cancel_url=request.cancel_url,
        metadata={"organization_id": org_id},
    )
    
    return CheckoutSessionResponse(session_id=session.id, url=session.url)


@router.post("/portal", response_model=BillingPortalResponse)
async def create_billing_portal(
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Create Stripe billing portal session"""
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Billing not configured")
    
    supabase: Client = get_supabase()
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can manage billing")
    
    org = supabase.table("organizations").select("stripe_customer_id").eq("id", org_id).single().execute()
    
    if not org.data or not org.data.get("stripe_customer_id"):
        raise HTTPException(status_code=400, detail="No billing account found")
    
    session = stripe.billing_portal.Session.create(
        customer=org.data["stripe_customer_id"],
        return_url=f"{settings.frontend_url}/org/{org_id}/settings/billing",
    )
    
    return BillingPortalResponse(url=session.url)


@router.get("/subscription", response_model=Optional[SubscriptionResponse])
async def get_subscription(
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Get current subscription"""
    supabase: Client = get_supabase()
    
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    result = supabase.table("subscriptions").select("*").eq("organization_id", org_id).order("created_at", desc=True).limit(1).execute()
    
    if not result.data:
        return None
    
    return SubscriptionResponse(**result.data[0])


@router.get("/invoices", response_model=List[InvoiceResponse])
async def list_invoices(
    org_id: str = Query(..., alias="organization_id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
):
    """List invoices"""
    supabase: Client = get_supabase()
    
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can view invoices")
    
    result = supabase.table("invoices").select("*").eq("organization_id", org_id).range((page - 1) * page_size, page * page_size - 1).order("created_at", desc=True).execute()
    
    return [InvoiceResponse(**i) for i in result.data]


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhooks"""
    if not settings.stripe_secret_key or not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Billing not configured")
    
    supabase: Client = get_supabase()
    
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.stripe_webhook_secret)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Handle event
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        org_id = session.get("metadata", {}).get("organization_id")
        if org_id:
            # Subscription will be created via subscription.created event
            pass
    
    elif event["type"] == "customer.subscription.created":
        sub = event["data"]["object"]
        org_id = sub.get("metadata", {}).get("organization_id")
        if org_id:
            # Determine plan tier from price
            price_id = sub["items"]["data"][0]["price"]["id"]
            plan_tier = _get_plan_tier_from_price(price_id)
            
            supabase.table("subscriptions").upsert({
                "organization_id": org_id,
                "stripe_subscription_id": sub["id"],
                "stripe_customer_id": sub["customer"],
                "plan_tier": plan_tier,
                "status": sub["status"],
                "current_period_start": datetime.fromtimestamp(sub["current_period_start"]).isoformat(),
                "current_period_end": datetime.fromtimestamp(sub["current_period_end"]).isoformat(),
                "cancel_at_period_end": sub["cancel_at_period_end"],
            }).execute()
            
            # Update organization plan tier
            supabase.table("organizations").update({"plan_tier": plan_tier}).eq("id", org_id).execute()
    
    elif event["type"] == "customer.subscription.updated":
        sub = event["data"]["object"]
        price_id = sub["items"]["data"][0]["price"]["id"]
        plan_tier = _get_plan_tier_from_price(price_id)
        
        supabase.table("subscriptions").update({
            "plan_tier": plan_tier,
            "status": sub["status"],
            "current_period_start": datetime.fromtimestamp(sub["current_period_start"]).isoformat(),
            "current_period_end": datetime.fromtimestamp(sub["current_period_end"]).isoformat(),
            "cancel_at_period_end": sub["cancel_at_period_end"],
            "canceled_at": datetime.fromtimestamp(sub["canceled_at"]).isoformat() if sub.get("canceled_at") else None,
        }).eq("stripe_subscription_id", sub["id"]).execute()
        
        supabase.table("organizations").update({"plan_tier": plan_tier}).eq("stripe_customer_id", sub["customer"]).execute()
    
    elif event["type"] == "customer.subscription.deleted":
        sub = event["data"]["object"]
        supabase.table("subscriptions").update({
            "status": "canceled",
            "canceled_at": datetime.utcnow().isoformat(),
        }).eq("stripe_subscription_id", sub["id"]).execute()
        
        supabase.table("organizations").update({"plan_tier": "starter"}).eq("stripe_customer_id", sub["customer"]).execute()
    
    elif event["type"] == "invoice.payment_succeeded":
        invoice = event["data"]["object"]
        supabase.table("invoices").upsert({
            "organization_id": invoice.get("metadata", {}).get("organization_id"),
            "stripe_invoice_id": invoice["id"],
            "amount": invoice["amount_paid"],
            "currency": invoice["currency"],
            "status": invoice["status"],
            "invoice_url": invoice.get("hosted_invoice_url"),
            "invoice_pdf": invoice.get("invoice_pdf"),
            "period_start": datetime.fromtimestamp(invoice["period_start"]).isoformat(),
            "period_end": datetime.fromtimestamp(invoice["period_end"]).isoformat(),
            "paid_at": datetime.utcnow().isoformat(),
        }).execute()
    
    return {"received": True}


def _get_plan_tier_from_price(price_id: str) -> str:
    """Map Stripe price ID to plan tier"""
    price_map = {
        settings.stripe_price_starter: "starter",
        settings.stripe_price_pro: "pro",
        settings.stripe_price_team: "team",
        settings.stripe_price_enterprise: "enterprise",
    }
    return price_map.get(price_id, "starter")