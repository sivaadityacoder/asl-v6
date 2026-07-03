"""
ASL V6 SaaS Backend - Auth Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
import httpx
import jwt
from datetime import datetime, timedelta
import uuid

from app.core.config import settings
from app.core.database import get_supabase
from supabase import Client

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


# Pydantic models
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class GitHubAuthRequest(BaseModel):
    code: str
    redirect_uri: str


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    github_username: Optional[str] = None
    role: str
    plan_tier: str
    is_active: bool


class AuthResponse(BaseModel):
    user: UserResponse
    access_token: str
    refresh_token: str


# Helper functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def verify_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        token_type: str = payload.get("type")
        if user_id is None or token_type != "access":
            raise HTTPException(status_code=401, detail="Invalid token")
        return TokenData(user_id=user_id, email=email)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    return verify_token(token)


async def get_current_user_from_supabase(token: str = Depends(oauth2_scheme)):
    """Get user from Supabase Auth"""
    supabase: Client = get_supabase()
    try:
        user = supabase.auth.get_user(token)
        return user.user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# Auth endpoints
@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Register a new user with email/password"""
    supabase: Client = get_supabase()
    
    try:
        # Create user in Supabase Auth
        auth_response = supabase.auth.admin.create_user({
            "email": user_data.email,
            "password": user_data.password,
            "email_confirm": True,
            "user_metadata": {"full_name": user_data.full_name}
        })
        
        if not auth_response.user:
            raise HTTPException(status_code=400, detail="Failed to create user")
        
        # Create user profile in database
        user_profile = {
            "id": auth_response.user.id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "role": "member",
            "plan_tier": "starter",
            "is_active": True,
        }
        
        supabase.table("users").insert(user_profile).execute()
        
        # Generate tokens
        access_token = create_access_token({"sub": auth_response.user.id, "email": user_data.email})
        refresh_token = create_refresh_token({"sub": auth_response.user.id, "email": user_data.email})
        
        return AuthResponse(
            user=UserResponse(
                id=auth_response.user.id,
                email=user_data.email,
                full_name=user_data.full_name,
                role="member",
                plan_tier="starter",
                is_active=True,
            ),
            access_token=access_token,
            refresh_token=refresh_token,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=AuthResponse)
async def login(user_data: UserLogin):
    """Login with email/password"""
    supabase: Client = get_supabase()
    
    try:
        auth_response = supabase.auth.sign_in_with_password({
            "email": user_data.email,
            "password": user_data.password,
        })
        
        if not auth_response.user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get user profile
        profile = supabase.table("users").select("*").eq("id", auth_response.user.id).single().execute()
        
        access_token = create_access_token({"sub": auth_response.user.id, "email": user_data.email})
        refresh_token = create_refresh_token({"sub": auth_response.user.id, "email": user_data.email})
        
        return AuthResponse(
            user=UserResponse(
                id=auth_response.user.id,
                email=auth_response.user.email,
                full_name=profile.data.get("full_name") if profile.data else None,
                avatar_url=profile.data.get("avatar_url") if profile.data else None,
                github_username=profile.data.get("github_username") if profile.data else None,
                role=profile.data.get("role", "member") if profile.data else "member",
                plan_tier=profile.data.get("plan_tier", "starter") if profile.data else "starter",
                is_active=profile.data.get("is_active", True) if profile.data else True,
            ),
            access_token=access_token,
            refresh_token=refresh_token,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@router.post("/github", response_model=AuthResponse)
async def github_auth(auth_data: GitHubAuthRequest):
    """Authenticate with GitHub OAuth"""
    supabase: Client = get_supabase()
    
    try:
        # Exchange code for GitHub access token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": auth_data.code,
                    "redirect_uri": auth_data.redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
            token_data = token_response.json()
            
            if "error" in token_data:
                raise HTTPException(status_code=400, detail=token_data.get("error_description", "GitHub auth failed"))
            
            github_token = token_data["access_token"]
            
            # Get GitHub user info
            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {github_token}"},
            )
            github_user = user_response.json()
            
            # Get user emails
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {github_token}"},
            )
            emails = emails_response.json()
            primary_email = next((e["email"] for e in emails if e["primary"]), None)
        
        if not primary_email:
            raise HTTPException(status_code=400, detail="Could not get email from GitHub")
        
        # Check if user exists in Supabase
        existing_user = supabase.table("users").select("*").eq("email", primary_email).execute()
        
        if existing_user.data:
            user_profile = existing_user.data[0]
            user_id = user_profile["id"]
            
            # Update GitHub info
            supabase.table("users").update({
                "github_username": github_user["login"],
                "github_id": github_user["id"],
                "avatar_url": github_user.get("avatar_url"),
                "last_login": datetime.utcnow().isoformat(),
            }).eq("id", user_id).execute()
        else:
            # Create new user
            user_profile = {
                "email": primary_email,
                "full_name": github_user.get("name"),
                "avatar_url": github_user.get("avatar_url"),
                "github_username": github_user["login"],
                "github_id": github_user["id"],
                "role": "member",
                "plan_tier": "starter",
                "is_active": True,
            }
            result = supabase.table("users").insert(user_profile).execute()
            user_id = result.data[0]["id"]
        
        # Generate tokens
        access_token = create_access_token({"sub": user_id, "email": primary_email})
        refresh_token = create_refresh_token({"sub": user_id, "email": primary_email})
        
        return AuthResponse(
            user=UserResponse(
                id=user_id,
                email=primary_email,
                full_name=github_user.get("name"),
                avatar_url=github_user.get("avatar_url"),
                github_username=github_user["login"],
                role="member",
                plan_tier="starter",
                is_active=True,
            ),
            access_token=access_token,
            refresh_token=refresh_token,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GitHub authentication failed: {str(e)}")


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        payload = jwt.decode(refresh_token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload.get("sub")
        email = payload.get("email")
        
        # Verify user still exists and is active
        supabase: Client = get_supabase()
        user = supabase.table("users").select("id,is_active").eq("id", user_id).single().execute()
        
        if not user.data or not user.data.get("is_active"):
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        new_access_token = create_access_token({"sub": user_id, "email": email})
        new_refresh_token = create_refresh_token({"sub": user_id, "email": email})
        
        return Token(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=settings.access_token_expire_minutes * 60,
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/logout")
async def logout(current_user: TokenData = Depends(get_current_user)):
    """Logout - in stateless JWT, just client-side token removal"""
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: TokenData = Depends(get_current_user)):
    """Get current user profile"""
    supabase: Client = get_supabase()
    
    user = supabase.table("users").select("*").eq("id", current_user.user_id).single().execute()
    
    if not user.data:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user.data["id"],
        email=user.data["email"],
        full_name=user.data.get("full_name"),
        avatar_url=user.data.get("avatar_url"),
        github_username=user.data.get("github_username"),
        role=user.data.get("role", "member"),
        plan_tier=user.data.get("plan_tier", "starter"),
        is_active=user.data.get("is_active", True),
    )


@router.put("/me", response_model=UserResponse)
async def update_profile(
    full_name: Optional[str] = None,
    avatar_url: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """Update current user profile"""
    supabase: Client = get_supabase()
    
    update_data = {}
    if full_name is not None:
        update_data["full_name"] = full_name
    if avatar_url is not None:
        update_data["avatar_url"] = avatar_url
    
    if update_data:
        supabase.table("users").update(update_data).eq("id", current_user.user_id).execute()
    
    return await get_current_user_profile(current_user)


@router.delete("/me")
async def delete_account(current_user: TokenData = Depends(get_current_user)):
    """Delete current user account"""
    supabase: Client = get_supabase()
    
    # Soft delete - mark as inactive
    supabase.table("users").update({"is_active": False}).eq("id", current_user.user_id).execute()
    
    # Also delete from Supabase Auth (requires service role)
    # supabase.auth.admin.delete_user(current_user.user_id)
    
    return {"message": "Account deleted successfully"}


# OAuth URL generation
@router.get("/github/url")
async def get_github_oauth_url(redirect_uri: str):
    """Get GitHub OAuth URL"""
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": redirect_uri,
        "scope": "read:user user:email repo admin:repo_hook",
        "state": "asl-v6-auth",
    }
    
    from urllib.parse import urlencode
    url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return {"url": url}


# Password reset
@router.post("/forgot-password")
async def forgot_password(email: EmailStr):
    """Request password reset"""
    supabase: Client = get_supabase()
    
    try:
        supabase.auth.reset_password_email(email)
        return {"message": "Password reset email sent"}
    except Exception:
        # Don't reveal if email exists
        return {"message": "If the email exists, a reset link has been sent"}


@router.post("/reset-password")
async def reset_password(new_password: str, token: str):
    """Reset password with token"""
    supabase: Client = get_supabase()
    
    try:
        supabase.auth.update_user({"password": new_password}, token=token)
        return {"message": "Password reset successful"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")