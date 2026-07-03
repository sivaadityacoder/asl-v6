"""
ASL V6 SaaS Backend - Database Models (Supabase Schema)
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid


# Enums
class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class PlanTier(str, Enum):
    STARTER = "starter"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    CLONING = "cloning"
    DISCOVERY = "discovery"
    STATIC_ANALYSIS = "static_analysis"
    SECRETS_SCAN = "secrets_scan"
    REACHABILITY = "reachability"
    CONTEXT_ANALYSIS = "context_analysis"
    OWASP_LLM = "owasp_llm"
    MITRE_ATLAS = "mitre_atlas"
    DYNAMIC_VALIDATION = "dynamic_validation"
    AI_REVIEW = "ai_review"
    EVIDENCE_COLLECTION = "evidence_collection"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    ACCEPTED_RISK = "accepted_risk"


class RepositoryProvider(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"


# Base Models
class TimestampMixin(BaseModel):
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IDMixin(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)


# User & Organization
class User(IDMixin, TimestampMixin):
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    github_username: Optional[str] = None
    github_id: Optional[int] = None
    role: UserRole = UserRole.MEMBER
    plan_tier: PlanTier = PlanTier.STARTER
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    is_active: bool = True
    last_login: Optional[datetime] = None


class Organization(IDMixin, TimestampMixin):
    name: str
    slug: str
    description: Optional[str] = None
    logo_url: Optional[str] = None
    owner_id: uuid.UUID
    plan_tier: PlanTier = PlanTier.STARTER
    stripe_customer_id: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)


class OrganizationMember(IDMixin, TimestampMixin):
    organization_id: uuid.UUID
    user_id: uuid.UUID
    role: UserRole = UserRole.MEMBER
    invited_by: Optional[uuid.UUID] = None
    invited_at: datetime = Field(default_factory=datetime.utcnow)
    joined_at: Optional[datetime] = None


# Projects & Repositories
class Project(IDMixin, TimestampMixin):
    organization_id: uuid.UUID
    name: str
    slug: str
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class Repository(IDMixin, TimestampMixin):
    project_id: uuid.UUID
    provider: RepositoryProvider = RepositoryProvider.GITHUB
    provider_repo_id: str  # GitHub repo ID
    owner: str  # GitHub owner/login
    name: str
    full_name: str  # owner/name
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
    webhook_id: Optional[int] = None
    last_synced_at: Optional[datetime] = None
    settings: Dict[str, Any] = Field(default_factory=dict)


# Scans
class Scan(IDMixin, TimestampMixin):
    repository_id: uuid.UUID
    project_id: uuid.UUID
    organization_id: uuid.UUID
    initiated_by: uuid.UUID
    commit_sha: str
    branch: str
    status: ScanStatus = ScanStatus.PENDING
    progress: int = 0
    current_layer: int = 0
    total_layers: int = 10
    layer_status: Dict[str, str] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    error_message: Optional[str] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_config: Dict[str, Any] = Field(default_factory=dict)
    celery_task_id: Optional[str] = None


class ScanLayer(BaseModel):
    layer_number: int
    name: str
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    findings_count: int = 0
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Findings
class Finding(IDMixin, TimestampMixin):
    scan_id: uuid.UUID
    repository_id: uuid.UUID
    project_id: uuid.UUID
    organization_id: uuid.UUID
    layer: int
    layer_name: str
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.OPEN
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_llm_id: Optional[str] = None
    mitre_atlas_id: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    confidence: Optional[float] = None
    assigned_to: Optional[uuid.UUID] = None
    triaged_by: Optional[uuid.UUID] = None
    triaged_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    is_suppressed: bool = False
    suppression_reason: Optional[str] = None


# Reports
class Report(IDMixin, TimestampMixin):
    scan_id: uuid.UUID
    project_id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    format: ReportFormat
    status: str = "generating"
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    download_url: Optional[str] = None
    expires_at: Optional[datetime] = None
    generated_at: Optional[datetime] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Rules
class Rule(IDMixin, TimestampMixin):
    rule_id: str  # Unique identifier like "ASL-LLM01-001"
    name: str
    description: str
    category: str  # e.g., "LLM01", "ASI04", "ATLAS-T0001"
    severity: FindingSeverity
    layer: int
    language: Optional[str] = None  # python, javascript, typescript, etc.
    pattern: Optional[str] = None  # Regex or semgrep pattern
    ast_pattern: Optional[Dict[str, Any]] = None  # Tree-sitter AST pattern
    is_active: bool = True
    is_custom: bool = False
    created_by: Optional[uuid.UUID] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Billing
class Subscription(IDMixin, TimestampMixin):
    organization_id: uuid.UUID
    stripe_subscription_id: str
    stripe_customer_id: str
    plan_tier: PlanTier
    status: str  # active, canceled, past_due, trialing
    current_period_start: datetime
    current_period_end: datetime
    cancel_at_period_end: bool = False
    canceled_at: Optional[datetime] = None
    trial_end: Optional[datetime] = None


class Invoice(IDMixin, TimestampMixin):
    organization_id: uuid.UUID
    stripe_invoice_id: str
    amount: int  # in cents
    currency: str = "usd"
    status: str  # draft, open, paid, void, uncollectible
    invoice_url: Optional[str] = None
    invoice_pdf: Optional[str] = None
    period_start: datetime
    period_end: datetime
    paid_at: Optional[datetime] = None


# Audit Log
class AuditLog(IDMixin, TimestampMixin):
    organization_id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    action: str
    resource_type: str
    resource_id: Optional[uuid.UUID] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


# Webhooks
class WebhookDelivery(IDMixin, TimestampMixin):
    webhook_id: uuid.UUID
    event_type: str
    payload: Dict[str, Any]
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    attempt: int = 1
    max_attempts: int = 5
    next_retry_at: Optional[datetime] = None
    succeeded_at: Optional[datetime] = None
    error: Optional[str] = None