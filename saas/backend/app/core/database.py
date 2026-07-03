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
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key
        )
        logger.info("Supabase client initialized")
    return _supabase_client


def get_supabase_anon() -> Client:
    """Get Supabase client with anon key (for client-side operations)"""
    return create_client(
        settings.supabase_url,
        settings.supabase_anon_key
    )