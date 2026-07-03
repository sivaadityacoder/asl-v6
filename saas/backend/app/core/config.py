"""
ASL V6 SaaS Backend - Configuration
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)


class Settings(BaseSettings):
    # App
    app_name: str = "ASL V6 AI Security Platform"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=True, alias="DEBUG")
    api_prefix: str = "/api/v1"
    
    # Supabase
    supabase_url: str = Field(alias="SUPABASE_URL")
    supabase_anon_key: str = Field(alias="SUPABASE_ANON_KEY")
    supabase_service_role_key: str = Field(alias="SUPABASE_SERVICE_ROLE_KEY")
    supabase_jwt_secret: Optional[str] = Field(default=None, alias="SUPABASE_JWT_SECRET")
    
    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    
    # GitHub
    github_client_id: Optional[str] = Field(default=None, alias="GITHUB_CLIENT_ID")
    github_client_secret: Optional[str] = Field(default=None, alias="GITHUB_CLIENT_SECRET")
    github_webhook_secret: Optional[str] = Field(default=None, alias="GITHUB_WEBHOOK_SECRET")
    github_app_id: Optional[str] = Field(default=None, alias="GITHUB_APP_ID")
    github_app_private_key: Optional[str] = Field(default=None, alias="GITHUB_APP_PRIVATE_KEY")
    
    # AI Providers - NVIDIA Only
    nvidia_api_key: str = Field(alias="NVIDIA_API_KEY")
    nvidia_base_url: str = Field(default="https://integrate.api.nvidia.com/v1", alias="NVIDIA_BASE_URL")
    
    # Celery
    celery_broker_url: str = Field(default="redis://localhost:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/2", alias="CELERY_RESULT_BACKEND")
    
    # Security
    secret_key: str = Field(alias="SECRET_KEY")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # CORS
    cors_origins: list[str] = Field(default=["http://localhost:3000"], alias="CORS_ORIGINS")
    
    # Storage
    supabase_storage_bucket_reports: str = "reports"
    supabase_storage_bucket_uploads: str = "uploads"
    supabase_storage_bucket_logs: str = "logs"
    supabase_storage_bucket_screenshots: str = "screenshots"
    
    # Billing (Wise Manual)
    wise_account_name: Optional[str] = Field(default="ASL V6 Platform", alias="WISE_ACCOUNT_NAME")
    wise_iban: Optional[str] = Field(default="GB12WISE34567890123456", alias="WISE_IBAN")
    wise_swift_bic: Optional[str] = Field(default="WISEGB2L", alias="WISE_SWIFT_BIC")
    wise_routing_number: Optional[str] = Field(default="", alias="WISE_ROUTING_NUMBER")
    wise_account_number: Optional[str] = Field(default="34567890123456", alias="WISE_ACCOUNT_NUMBER")
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    
    # Scan Settings
    max_concurrent_scans: int = 5
    scan_timeout_minutes: int = 60
    max_repo_size_mb: int = 500
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()