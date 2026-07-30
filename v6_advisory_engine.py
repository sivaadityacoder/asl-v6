"""Backward-compatible import for the retired advisory entitlement module.

New integrations should import :mod:`v6_subscription_engine` directly. This
module intentionally uses the same server-verification-safe entitlement model.
"""

from v6_subscription_engine import (
    COMMUNITY_FEATURES,
    PRO_FEATURES,
    SubscriptionManager,
    SubscriptionStatus,
    SubscriptionTier,
)

__all__ = [
    "COMMUNITY_FEATURES",
    "PRO_FEATURES",
    "SubscriptionManager",
    "SubscriptionStatus",
    "SubscriptionTier",
]
