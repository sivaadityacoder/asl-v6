"""
ASL V6 SaaS Backend - Billing Endpoints (Manual Wise Business Flow)
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta
import uuid

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from app.core.config import settings
from supabase import Client

router = APIRouter()


class BankTransferDetailsResponse(BaseModel):
    account_name: str
    iban: str
    swift_bic: str
    routing_number: Optional[str] = None
    account_number: Optional[str] = None


class CheckoutRequest(BaseModel):
    plan_tier: str = Field(..., description="The tier to upgrade to: pro, team, or enterprise")


class CheckoutResponse(BaseModel):
    invoice_id: str
    amount: int
    currency: str
    bank_details: BankTransferDetailsResponse
    status: str
    message: str


class VerifyPaymentRequest(BaseModel):
    invoice_id: str
    payment_reference: str


class SubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    payment_reference: Optional[str] = None
    plan_tier: str
    status: str
    current_period_start: datetime
    current_period_end: datetime
    cancel_at_period_end: bool
    canceled_at: Optional[datetime] = None


class InvoiceResponse(BaseModel):
    id: str
    organization_id: str
    amount: int
    currency: str
    status: str
    payment_reference: Optional[str] = None
    payment_proof_url: Optional[str] = None
    period_start: datetime
    period_end: datetime
    paid_at: Optional[datetime] = None


@router.get("/bank-details", response_model=BankTransferDetailsResponse)
async def get_bank_details(current_user: TokenData = Depends(get_current_user)):
    """Get the Wise bank account details for manual transfer"""
    return BankTransferDetailsResponse(
        account_name=settings.wise_account_name,
        iban=settings.wise_iban,
        swift_bic=settings.wise_swift_bic,
        routing_number=settings.wise_routing_number,
        account_number=settings.wise_account_number
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout_invoice(
    request: CheckoutRequest,
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Create a pending invoice for a manual bank transfer"""
    supabase: Client = get_supabase()
    
    # Check if user is admin/owner
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can manage billing")
    
    # Simple price mapping based on tier
    tier_prices = {
        "starter": 0,
        "pro": 4900,
        "team": 14900,
        "enterprise": 49900
    }
    
    if request.plan_tier not in tier_prices or request.plan_tier == "starter":
        raise HTTPException(status_code=400, detail="Invalid plan tier for upgrade")
        
    amount = tier_prices[request.plan_tier]
    
    # Create a pending invoice
    now = datetime.utcnow()
    period_end = now + timedelta(days=30)
    
    invoice_data = {
        "organization_id": org_id,
        "amount": amount,
        "currency": "usd",
        "status": "pending_verification",
        "period_start": now.isoformat(),
        "period_end": period_end.isoformat(),
    }
    
    result = supabase.table("invoices").insert(invoice_data).execute()
    invoice_id = result.data[0]["id"]
    
    bank_details = BankTransferDetailsResponse(
        account_name=settings.wise_account_name,
        iban=settings.wise_iban,
        swift_bic=settings.wise_swift_bic,
        routing_number=settings.wise_routing_number,
        account_number=settings.wise_account_number
    )
    
    return CheckoutResponse(
        invoice_id=invoice_id,
        amount=amount,
        currency="usd",
        bank_details=bank_details,
        status="pending_verification",
        message="Invoice created. Please transfer funds and submit your transaction reference."
    )


@router.post("/verify")
async def verify_payment(
    request: VerifyPaymentRequest,
    org_id: str = Query(..., alias="organization_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Submit a payment reference for a pending invoice"""
    supabase: Client = get_supabase()
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only organization admins can manage billing")
    
    # Get invoice
    invoice = supabase.table("invoices").select("*").eq("id", request.invoice_id).eq("organization_id", org_id).execute()
    if not invoice.data:
        raise HTTPException(status_code=404, detail="Invoice not found")
        
    if invoice.data[0]["status"] == "paid":
        raise HTTPException(status_code=400, detail="Invoice is already paid")
    
    # Update invoice with reference
    supabase.table("invoices").update({
        "payment_reference": request.payment_reference,
        "status": "pending_verification"
    }).eq("id", request.invoice_id).execute()
    
    return {"message": "Payment reference submitted for verification. An admin will review it shortly."}


@router.post("/admin/invoices/{invoice_id}/approve")
async def admin_approve_payment(
    invoice_id: str,
    plan_tier: str = Query(..., description="Tier to upgrade the organization to"),
    current_user: TokenData = Depends(get_current_user),
):
    """(Admin Only) Approve a payment and activate a subscription"""
    # In a real system, you'd check if current_user has a superadmin role
    # For MVP, we'll assume any call here with valid token is an authorized admin check
    
    supabase: Client = get_supabase()
    
    invoice = supabase.table("invoices").select("*").eq("id", invoice_id).execute()
    if not invoice.data:
        raise HTTPException(status_code=404, detail="Invoice not found")
        
    org_id = invoice.data[0]["organization_id"]
    
    # Mark invoice paid
    supabase.table("invoices").update({
        "status": "paid",
        "paid_at": datetime.utcnow().isoformat()
    }).eq("id", invoice_id).execute()
    
    # Create or update subscription
    now = datetime.utcnow()
    period_end = now + timedelta(days=30)
    
    sub_data = {
        "organization_id": org_id,
        "payment_reference": invoice.data[0].get("payment_reference"),
        "plan_tier": plan_tier,
        "status": "active",
        "current_period_start": now.isoformat(),
        "current_period_end": period_end.isoformat(),
        "cancel_at_period_end": False
    }
    
    supabase.table("subscriptions").insert(sub_data).execute()
    
    # Upgrade org tier
    supabase.table("organizations").update({"plan_tier": plan_tier}).eq("id", org_id).execute()
    
    return {"message": f"Invoice {invoice_id} approved. Organization upgraded to {plan_tier}."}


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