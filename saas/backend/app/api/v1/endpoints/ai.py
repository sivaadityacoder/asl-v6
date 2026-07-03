"""
ASL V6 SaaS Backend - AI Endpoints (NVIDIA API Integration)
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import httpx
import json

from app.api.v1.endpoints.auth import get_current_user, TokenData
from app.core.database import get_supabase
from app.core.config import settings
from supabase import Client

router = APIRouter()


class AIReviewRequest(BaseModel):
    scan_id: str
    finding_ids: Optional[List[str]] = None
    context: Optional[str] = None


class AIReviewResponse(BaseModel):
    review_id: str
    scan_id: str
    status: str
    summary: Optional[str] = None
    findings_reviewed: int
    false_positives: int
    risk_assessment: Optional[str] = None
    recommendations: List[str]
    created_at: datetime


class AIAnalysisRequest(BaseModel):
    code: str
    language: str
    context: Optional[str] = None
    analysis_type: str = "security"  # security, quality, performance


class AIAnalysisResponse(BaseModel):
    analysis_id: str
    findings: List[Dict[str, Any]]
    summary: str
    risk_score: float
    recommendations: List[str]


class NVIDIAModel(BaseModel):
    id: str
    name: str
    description: str
    capabilities: List[str]
    max_tokens: int


@router.get("/models", response_model=List[NVIDIAModel])
async def list_nvidia_models(current_user: TokenData = Depends(get_current_user)):
    """List available NVIDIA AI models"""
    # Return curated list of NVIDIA models suitable for security analysis
    return [
        NVIDIAModel(
            id="meta/llama-3.1-405b-instruct",
            name="Llama 3.1 405B Instruct",
            description="Meta's largest open model, excellent for complex security reasoning",
            capabilities=["security-analysis", "code-review", "vulnerability-assessment"],
            max_tokens=128000,
        ),
        NVIDIAModel(
            id="meta/llama-3.1-70b-instruct",
            name="Llama 3.1 70B Instruct",
            description="High-quality model for security analysis and code review",
            capabilities=["security-analysis", "code-review", "vulnerability-assessment"],
            max_tokens=128000,
        ),
        NVIDIAModel(
            id="nvidia/nemotron-3-ultra",
            name="Nemotron 3 Ultra",
            description="NVIDIA's flagship model for complex reasoning tasks",
            capabilities=["security-analysis", "code-review", "reasoning"],
            max_tokens=4096,
        ),
        NVIDIAModel(
            id="nvidia/nemotron-4-340b-instruct",
            name="Nemotron 4 340B Instruct",
            description="Large-scale model for advanced security reasoning",
            capabilities=["security-analysis", "code-review", "vulnerability-assessment"],
            max_tokens=128000,
        ),
        NVIDIAModel(
            id="mistralai/mixtral-8x22b-instruct-v0.1",
            name="Mixtral 8x22B Instruct",
            description="Mixture of experts model, good for code analysis",
            capabilities=["code-review", "security-analysis"],
            max_tokens=65536,
        ),
    ]


@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze_code(
    request: AIAnalysisRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """Analyze code using NVIDIA AI models"""
    if not settings.nvidia_api_key:
        raise HTTPException(status_code=503, detail="NVIDIA API not configured")
    
    # Build prompt based on analysis type
    if request.analysis_type == "security":
        prompt = _build_security_prompt(request.code, request.language, request.context)
    elif request.analysis_type == "quality":
        prompt = _build_quality_prompt(request.code, request.language, request.context)
    elif request.analysis_type == "performance":
        prompt = _build_performance_prompt(request.code, request.language, request.context)
    else:
        prompt = _build_security_prompt(request.code, request.language, request.context)
    
    # Call NVIDIA API
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{settings.nvidia_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.nvidia_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "meta/llama-3.1-70b-instruct",
                    "messages": [
                        {"role": "system", "content": "You are an expert security researcher specializing in AI/LLM application security."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 4096,
                },
            )
            response.raise_for_status()
            result = response.json()
            
            content = result["choices"][0]["message"]["content"]
            
            # Parse structured response
            analysis = _parse_ai_response(content)
            
            return AIAnalysisResponse(
                analysis_id=f"ai-{datetime.utcnow().timestamp()}",
                findings=analysis.get("findings", []),
                summary=analysis.get("summary", ""),
                risk_score=analysis.get("risk_score", 0.0),
                recommendations=analysis.get("recommendations", []),
            )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"NVIDIA API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/review-findings", response_model=AIReviewResponse)
async def review_findings(
    request: AIReviewRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """Use AI to review and prioritize scan findings"""
    if not settings.nvidia_api_key:
        raise HTTPException(status_code=503, detail="NVIDIA API not configured")
    
    supabase: Client = get_supabase()
    
    # Get scan and findings
    scan = supabase.table("scans").select("*").eq("id", request.scan_id).single().execute()
    if not scan.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check authorization
    orgs = supabase.table("organization_members").select("organization_id").eq("user_id", current_user.user_id).execute()
    org_ids = [o["organization_id"] for o in orgs.data]
    if scan.data["organization_id"] not in org_ids:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get findings
    query = supabase.table("findings").select("*").eq("scan_id", request.scan_id)
    if request.finding_ids:
        query = query.in_("id", request.finding_ids)
    findings_result = query.execute()
    
    findings = findings_result.data
    
    # Build review prompt
    prompt = _build_review_prompt(findings, request.context)
    
    # Call NVIDIA API
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{settings.nvidia_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.nvidia_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "meta/llama-3.1-70b-instruct",
                    "messages": [
                        {"role": "system", "content": "You are a senior security architect reviewing AI/LLM application vulnerabilities. Provide actionable, prioritized feedback."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 8192,
                },
            )
            response.raise_for_status()
            result = response.json()
            
            content = result["choices"][0]["message"]["content"]
            review = _parse_review_response(content)
            
            # Save review to database
            review_record = {
                "scan_id": request.scan_id,
                "summary": review.get("summary"),
                "findings_reviewed": len(findings),
                "false_positives": review.get("false_positives", 0),
                "risk_assessment": review.get("risk_assessment"),
                "recommendations": review.get("recommendations", []),
            }
            
            # Store in scan metadata or separate table
            supabase.table("scans").update({
                "ai_review": review_record
            }).eq("id", request.scan_id).execute()
            
            return AIReviewResponse(
                review_id=f"review-{datetime.utcnow().timestamp()}",
                scan_id=request.scan_id,
                status="completed",
                **review_record,
                created_at=datetime.utcnow(),
            )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"NVIDIA API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Review failed: {str(e)}")


def _build_security_prompt(code: str, language: str, context: Optional[str]) -> str:
    return f"""Analyze the following {language} code for security vulnerabilities, especially focusing on AI/LLM application security risks.

Context: {context or 'General security analysis'}

Code:
```{language}
{code}
```

Look for:
1. Prompt injection vulnerabilities (LLM01)
2. Sensitive data exposure (LLM02)
3. Supply chain vulnerabilities (LLM03)
4. Data/model poisoning (LLM04)
5. Improper output handling (LLM05)
6. Insecure tool/MCP execution (ASI04/ASI05)
7. Agent identity/goal confusion (ASI01/ASI02)
8. Hardcoded secrets/API keys
9. Unsafe deserialization (pickle, etc.)
10. SSRF via LLM tool calls

Respond in JSON format:
{{
    "findings": [
        {{
            "title": "Brief title",
            "severity": "critical|high|medium|low|info",
            "description": "Detailed description",
            "location": "Function/line reference",
            "cwe": "CWE-ID if applicable",
            "owasp_llm": "LLM01-LLM10 or ASI01-ASI10",
            "recommendation": "Specific fix"
        }}
    ],
    "summary": "Overall security assessment",
    "risk_score": 0.0-10.0,
    "recommendations": ["Priority 1", "Priority 2", "..."]
}}"""


def _build_quality_prompt(code: str, language: str, context: Optional[str]) -> str:
    return f"""Review the following {language} code for quality issues, best practices, and maintainability concerns.

Context: {context or 'General code quality review'}

Code:
```{language}
{code}
```

Respond in JSON format with findings, summary, risk_score, and recommendations."""


def _build_performance_prompt(code: str, language: str, context: Optional[str]) -> str:
    return f"""Analyze the following {language} code for performance bottlenecks and optimization opportunities.

Context: {context or 'General performance analysis'}

Code:
```{language}
{code}
```

Respond in JSON format with findings, summary, risk_score, and recommendations."""


def _build_review_prompt(findings: List[Dict], context: Optional[str]) -> str:
    findings_summary = []
    for f in findings[:50]:  # Limit to 50 findings
        findings_summary.append(f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}: {f.get('description', '')[:200]}")
    
    return f"""Review the following security findings from an AI/LLM application scan and provide prioritized, actionable feedback.

Context: {context or 'General scan review'}

Total findings: {len(findings)}
Showing first {min(len(findings), 50)} findings:

{chr(10).join(findings_summary)}

Provide a JSON response:
{{
    "summary": "Executive summary of the security posture",
    "false_positives": <number>,
    "risk_assessment": "Overall risk level and key concerns",
    "recommendations": [
        "Immediate action items",
        "Short-term improvements",
        "Long-term strategic changes"
    ],
    "prioritized_findings": [
        {{
            "finding_id": "original finding identifier",
            "priority": "critical|high|medium|low",
            "action": "specific action to take",
            "effort": "low|medium|high"
        }}
    ]
}}"""


def _parse_ai_response(content: str) -> Dict[str, Any]:
    """Parse AI response, handling both JSON and text formats"""
    try:
        # Try to extract JSON from response
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            json_str = content[start:end]
            return json.loads(json_str)
    except Exception as e:
        import structlog
        logger = structlog.get_logger(__name__)
        logger.warning("Failed to parse JSON from AI response", error=str(e))
    
    # Fallback: return structured default
    return {
        "findings": [],
        "summary": content[:500] if content else "Analysis completed",
        "risk_score": 5.0,
        "recommendations": ["Review the analysis output manually"],
    }


def _parse_review_response(content: str) -> Dict[str, Any]:
    """Parse AI review response"""
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            json_str = content[start:end]
            return json.loads(json_str)
    except Exception as e:
        import structlog
        logger = structlog.get_logger(__name__)
        logger.warning("Failed to parse JSON from AI response", error=str(e))
    
    return {
        "summary": content[:500] if content else "Review completed",
        "false_positives": 0,
        "risk_assessment": "Unable to parse structured response",
        "recommendations": ["Review findings manually"],
    }