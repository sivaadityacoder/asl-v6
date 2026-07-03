"""
ASL V6 SaaS Backend - Redis Connection
"""
import redis.asyncio as redis
from app.core.config import settings
import structlog

logger = structlog.get_logger()

_redis_client: redis.Redis = None


async def get_redis() -> redis.Redis:
    """Get or create Redis client"""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50
        )
        logger.info("Redis client initialized")
    return _redis_client


async def close_redis():
    """Close Redis connection"""
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
        logger.info("Redis connection closed")