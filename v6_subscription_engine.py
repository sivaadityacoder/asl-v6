"""Community and Pro edition metadata for ASL V6.1.

The open-source scanner is MIT licensed and never requires a subscription key.
This module describes product entitlements for user interfaces and integrations.
Actual Pro authorization must be verified by a trusted subscription service;
client-side environment variables are not a security boundary.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    class Console:
        def print(self, *args, **kwargs):
            pass

    Table = None


console = Console()


class SubscriptionTier(StrEnum):
    COMMUNITY = "Community"
    PRO = "Pro"


COMMUNITY_FEATURES = {
    "ten_specialist_scanners": True,
    "verification_gauntlet": True,
    "markdown_json_reports": True,
    "local_cli": True,
    "ci_exit_codes": True,
    "offline_remediation": True,
    "bring_your_own_model_key": True,
}

PRO_FEATURES = {
    **COMMUNITY_FEATURES,
    "organization_policy_packs": True,
    "centralized_team_dashboard": True,
    "scheduled_repository_scans": True,
    "sarif_and_pr_review_service": True,
    "team_history_and_trends": True,
    "compliance_report_exports": True,
    "priority_support": True,
}


@dataclass(frozen=True)
class SubscriptionStatus:
    tier: SubscriptionTier
    features: Mapping[str, bool]
    pro_key_configured: bool
    entitlement_verified: bool


class SubscriptionManager:
    """Expose edition status without restricting open-source capabilities."""

    def __init__(self, pro_key: str | None = None, entitlement_verified: bool = False):
        self._pro_key = pro_key if pro_key is not None else os.getenv("ASL_PRO_LICENSE_KEY", "")
        self._entitlement_verified = bool(entitlement_verified and self._pro_key)

    @property
    def status(self) -> SubscriptionStatus:
        if self._entitlement_verified:
            return SubscriptionStatus(
                tier=SubscriptionTier.PRO,
                features=PRO_FEATURES,
                pro_key_configured=True,
                entitlement_verified=True,
            )
        return SubscriptionStatus(
            tier=SubscriptionTier.COMMUNITY,
            features=COMMUNITY_FEATURES,
            pro_key_configured=bool(self._pro_key),
            entitlement_verified=False,
        )

    @property
    def tier(self) -> SubscriptionTier:
        return self.status.tier

    @property
    def unlocked_features(self) -> Mapping[str, bool]:
        return self.status.features

    def display_status(self) -> None:
        status = self.status
        console.print(f"ASL V6.1 edition: {status.tier.value}")
        if status.pro_key_configured and not status.entitlement_verified:
            console.print(
                "A Pro key is configured but has not been verified by a trusted "
                "subscription service; Community mode remains active."
            )
        elif status.tier is SubscriptionTier.COMMUNITY:
            console.print("The complete local scanner is available under the MIT License.")

    def get_feature_matrix_table(self):
        if Table is None:
            return None
        table = Table(title="ASL V6.1 Community and Pro")
        table.add_column("Capability")
        table.add_column("Community", justify="center")
        table.add_column("Pro", justify="center")
        rows = [
            ("Local scanner and 10 specialist agents", True, True),
            ("Markdown/JSON reports and CI exit codes", True, True),
            ("Offline remediation and BYO model key", True, True),
            ("Organization policy packs", False, True),
            ("Central dashboard, history, and trends", False, True),
            ("Scheduled scans and managed PR/SARIF service", False, True),
            ("Compliance exports and priority support", False, True),
        ]
        for capability, community, pro in rows:
            table.add_row(capability, "Yes" if community else "—", "Yes" if pro else "—")
        return table


if __name__ == "__main__":
    manager = SubscriptionManager()
    manager.display_status()
    feature_table = manager.get_feature_matrix_table()
    if feature_table:
        console.print(feature_table)
