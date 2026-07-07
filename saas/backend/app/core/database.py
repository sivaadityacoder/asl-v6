"""
ASL V6 SaaS Backend - Database Connection
"""
from supabase import create_client, Client
from app.core.config import settings
import structlog

logger = structlog.get_logger()

# Global Supabase client
_supabase_client: Client = None


def get_supabase() -> Client:
    """Get or create Supabase client"""
    return create_client(
        settings.supabase_url,
        settings.supabase_service_role_key
    )


def get_supabase_anon() -> Client:
    """Get Supabase client with anon key (for client-side operations)"""
    return create_client(
        settings.supabase_url,
        settings.supabase_anon_key
    )