"""
ASL V6 SaaS Backend - GitHub Integration Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import json
import hmac
import hashlib
import httpx

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from app.core.config import settings
from supabase import Client

router = APIRouter()


class GitHubRepoResponse(BaseModel):
    id: str
    name: str
    full_name: str
    owner: str
    description: Optional[str] = None
    private: bool
    html_url: str
    clone_url: str
    default_branch: str
    language: Optional[str] = None
    stars: int
    forks: int
    size: int
    updated_at: str


class GitHubInstallationResponse(BaseModel):
    id: int
    account_login: str
    account_type: str
    repositories: List[GitHubRepoResponse]


class WebhookEvent(BaseModel):
    action: str
    repository: dict
    sender: dict
    installation: Optional[dict] = None


@router.get("/repositories", response_model=List[GitHubRepoResponse])
async def list_github_repositories(
    org_id: str = Query(..., alias="organization_id"),
    installation_id: Optional[int] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """List GitHub repositories accessible via GitHub App or OAuth"""
    supabase: Client = get_supabase()
    
    # Check authorization
    member = supabase.table("organization_members").select("role").eq("organization_id", org_id).eq("user_id", current_user.user_id).execute()
    if not member.data:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get GitHub access token (from user's OAuth or GitHub App)
    # This would need to be implemented based on your auth strategy
    # For now, return empty list
    return []


@router.get("/installations", response_model=List[GitHubInstallationResponse])
async def list_github_installations(
    current_user: TokenData = Depends(get_current_user),
):
    """List GitHub App installations for the user"""
    # This would require GitHub App credentials
    return []


@router.post("/webhook")
async def github_webhook(request: Request):
    """Handle GitHub webhook events"""
    supabase: Client = get_supabase()
    
    # Verify signature
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")
    
    payload = await request.body()
    
    # Verify webhook secret
    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse event
    event_type = request.headers.get("X-GitHub-Event")
    payload_json = json.loads(payload)
    
    # Process based on event type
    if event_type == "push":
        await _handle_push_event(payload_json)
    elif event_type == "pull_request":
        await _handle_pr_event(payload_json)
    elif event_type == "repository":
        await _handle_repository_event(payload_json)
    elif event_type == "installation":
        await _handle_installation_event(payload_json)
    elif event_type == "installation_repositories":
        await _handle_installation_repos_event(payload_json)
    
    return {"received": True}


async def _handle_push_event(payload: dict):
    """Handle push events - trigger scan if configured"""
    supabase = get_supabase()
    
    repo_full_name = payload["repository"]["full_name"]
    commit_sha = payload["after"]
    branch = payload["ref"].replace("refs/heads/", "")
    
    # Find matching repository in our system
    repo = supabase.table("repositories").select("*").eq("full_name", repo_full_name).execute()
    
    if not repo.data:
        return
    
    repo_data = repo.data[0]
    
    # Check if auto-scan is enabled
    if repo_data.get("settings", {}).get("auto_scan_on_push"):
        # Check if there's already a running scan
        running = supabase.table("scans").select("id").eq("repository_id", repo_data["id"]).in_("status", [
            "pending", "queued", "cloning", "discovery", "static_analysis", 
            "secrets_scan", "reachability", "context_analysis", "owasp_llm", 
            "mitre_atlas", "dynamic_validation", "ai_review", "evidence_collection",
            "report_generation"
        ]).execute()
        
        if not running.data:
            # Create new scan
            scan = {
                "repository_id": repo_data["id"],
                "project_id": repo_data["project_id"],
                "organization_id": repo_data["organization_id"],
                "initiated_by": "github_webhook",
                "commit_sha": commit_sha,
                "branch": branch,
                "status": "queued",
                "progress": 0,
                "current_layer": 0,
                "total_layers": 10,
                "scan_config": {"trigger": "push", "pusher": payload["pusher"]["name"]},
            }
            
            result = supabase.table("scans").insert(scan).execute()
            
            if result.data:
                scan_id = result.data[0]["id"]
                
                # Create scan layers
                layers = [
                    {"scan_id": scan_id, "layer_number": i, "name": name}
                    for i, name in enumerate([
                        "Repository Discovery", "Static Analysis", "Secrets Scanning",
                        "Reachability Analysis", "Context Analysis", "OWASP LLM Top 10",
                        "MITRE ATLAS", "Dynamic Validation", "AI Review", "Evidence Collection"
                    ], 1)
                ]
                
                supabase.table("scan_layers").insert(layers).execute()
                
                # Queue scan task
                # await queue_scan_task(scan_id)


async def _handle_pr_event(payload: dict):
    """Handle pull request events"""
    # Could trigger PR-specific scans
    pass


async def _handle_repository_event(payload: dict):
    """Handle repository events (created, deleted, archived, etc.)"""
    action = payload.get("action")
    repo = payload.get("repository")
    
    if action == "deleted":
        # Mark repository as disconnected
        supabase = get_supabase()
        supabase.table("repositories").update({"is_archived": True}).eq("full_name", repo["full_name"]).execute()


async def _handle_installation_event(payload: dict):
    """Handle GitHub App installation events"""
    pass


async def _handle_installation_repos_event(payload: dict):
    """Handle repository additions/removals from GitHub App installation"""
    pass


@router.post("/connect-repo")
async def connect_github_repo(
    repo_id: int,
    installation_id: int,
    project_id: str = Query(..., alias="project_id"),
    current_user: TokenData = Depends(get_current_user),
):
    """Connect a repository from GitHub App installation"""
    supabase = get_supabase()
    
    # Check project access
    project = supabase.table("projects").select("*").eq("id", project_id).single().execute()
    if not project.data:
        raise HTTPException(status_code=404, detail="Project not found")
    
    member = supabase.table("organization_members").select("role").eq("organization_id", project.data["organization_id"]).eq("user_id", current_user.user_id).execute()
    if not member.data or member.data[0]["role"] not in ["owner", "admin", "member"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get repository details from GitHub API using installation token
    # This would require GitHub App implementation
    
    return {"message": "Repository connected (implementation needed)"}


@router.get("/oauth/url")
async def get_github_oauth_url(
    redirect_uri: str,
    state: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """Get GitHub OAuth URL for user authorization"""
    from urllib.parse import urlencode
    
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": redirect_uri,
        "scope": "read:user user:email repo admin:repo_hook",
        "state": state or "asl-v6-github",
    }
    
    url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return {"url": url}


@router.post("/oauth/callback")
async def github_oauth_callback(
    code: str,
    redirect_uri: str,
    current_user: TokenData = Depends(get_current_user),
):
    """Handle GitHub OAuth callback"""
    async with httpx.AsyncClient() as client:
        # Exchange code for token
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_response.json()
        
        if "error" in token_data:
            raise HTTPException(status_code=400, detail=token_data.get("error_description"))
        
        access_token = token_data["access_token"]
        
        # Get user info
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        github_user = user_response.json()
        
        # Update user profile with GitHub info
        supabase = get_supabase()
        supabase.table("users").update({
            "github_username": github_user["login"],
            "github_id": github_user["id"],
            "avatar_url": github_user.get("avatar_url"),
            "github_access_token": access_token,  # Store encrypted in production
        }).eq("id", current_user.user_id).execute()
        
        return {"message": "GitHub account connected", "github_username": github_user["login"]}