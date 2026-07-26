"""
ASL V6 Enterprise Subscription & Licensing Module
=================================================
Module: v6_subscription_engine.py
Author: Siva Aditya Panuganti (Security Researcher)

Manages commercial subscription licensing, unlocked feature matrices, and
CI/CD automated deployment verification for B2B subscription sales.
"""

import os
import sys
from enum import Enum
from typing import Dict, Any, List

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    class Console:
        def print(self, *args, **kwargs): print(*args)
    Console = Console

console = Console()


class SubscriptionTier(str, Enum):
    COMMUNITY_OPEN_SOURCE = "ASL V6 Open Source Engine (Free / Lead Magnet)"
    ADVISORY_RETAINER = "Researcher Advisory Retainer ($2,500 / month)"
    EMERGENCY_ASSESSMENT = "Emergency Red-Team Assessment ($5,000 Fixed Sprint)"
    EU_AI_ACT_COMPLIANCE = "EU AI Act Compliance & Robustness Audit ($3,500 - $5,000 Fixed)"


class SubscriptionManager:
    """
    Validates high-ticket researcher engagement scopes and configures runtime capabilities
    for open-source community usage and enterprise advisory retainers.
    """
    def __init__(self, license_key: str = None):
        self.license_key = license_key or os.getenv("ASL_LICENSE_KEY", "OPEN-SOURCE-COMMUNITY")
        self.tier, self.unlocked_features = self._validate_and_decode(self.license_key)

    def _validate_and_decode(self, key: str) -> tuple[SubscriptionTier, Dict[str, bool]]:
        k_upper = key.upper().strip()
        
        if k_upper.startswith("ASL-ADV-") or "2500" in k_upper or "RETAINER" in k_upper:
            return SubscriptionTier.ADVISORY_RETAINER, {
                "sast_agents": True,
                "ast_gauntlet": True,
                "nvidia_nim_reasoning": True,
                "dast_docker_sandbox": True,
                "cyber_range_probing": True,
                "eu_ai_act_compliance": True,
                "researcher_advisory_hours": True,
                "max_files": 1000000
            }
        elif k_upper.startswith("ASL-EMRG-") or "5000" in k_upper or "SPRINT" in k_upper:
            return SubscriptionTier.EMERGENCY_ASSESSMENT, {
                "sast_agents": True,
                "ast_gauntlet": True,
                "nvidia_nim_reasoning": True,
                "dast_docker_sandbox": True,
                "cyber_range_probing": True,
                "eu_ai_act_compliance": True,
                "researcher_advisory_hours": True,
                "max_files": 1000000
            }
        elif k_upper.startswith("ASL-EU-") or "3500" in k_upper:
            return SubscriptionTier.EU_AI_ACT_COMPLIANCE, {
                "sast_agents": True,
                "ast_gauntlet": True,
                "nvidia_nim_reasoning": True,
                "dast_docker_sandbox": True,
                "cyber_range_probing": True,
                "eu_ai_act_compliance": True,
                "researcher_advisory_hours": True,
                "max_files": 1000000
            }
        else:
            # Default Free / Open Source Lead Magnet
            return SubscriptionTier.COMMUNITY_OPEN_SOURCE, {
                "sast_agents": True,
                "ast_gauntlet": True,
                "nvidia_nim_reasoning": True, # Included for open source community
                "dast_docker_sandbox": True,
                "cyber_range_probing": True,
                "eu_ai_act_compliance": False,
                "researcher_advisory_hours": False,
                "max_files": 50000
            }

    def display_status(self):
        """Displays formatted advisory engagement status header."""
        color = "green" if self.tier != SubscriptionTier.COMMUNITY_OPEN_SOURCE else "cyan"
        console.print(Panel.fit(
            f"[bold {color}]🔒 ASL V6 AI Security Engine & Advisory Status[/bold {color}]\n"
            f"[bold white]Engagement Scope:[/bold white] [yellow]{self.tier.value}[/yellow]\n"
            f"[bold white]Client ID / Scope Key:[/bold white] [dim]{self.license_key[:16]}...[/dim]\n"
            f"[dim]Author: Siva Aditya Panuganti (6+ CVEs in AI Infrastructure)[/dim]",
            border_style=color
        ))

    def get_feature_matrix_table(self):
        """Returns a rich table of high-ticket researcher advisory offerings vs free tool."""
        if not hasattr(Table, "__call__") and str(type(Table)) == "<class 'function'>":
            return None
        
        try:
            table = Table(title="ASL V6 Security Researcher Engagement Scope & Advisory Matrix", show_header=True, header_style="bold yellow")
            table.add_column("Capability / Deliverable", style="bold white", width=34)
            table.add_column("Open Source Engine\n(FREE on GitHub)", justify="center", style="cyan", width=20)
            table.add_column("Advisory Retainer\n($2,500 / month)", justify="center", style="green", width=20)
            table.add_column("Emergency Sprint\n($5,000 Fixed)", justify="center", style="bold magenta", width=20)
            
            table.add_row("ASL V6 Scanner (10 Agents + AST Gauntlet)", "✅ Full Free Access", "✅ Automated CI/CD Gate", "✅ Automated CI/CD Gate")
            table.add_row("Live Docker DAST Sandbox Exploit Proof", "✅ Full Free Access", "✅ Continuous Runtime Probing", "✅ Continuous Runtime Probing")
            table.add_row("Manual Architecture Deep-Dive Review", "❌ Tool Only", "✅ 4 Hrs/Month Deep-Dive", "✅ Full Pre-Launch Audit")
            table.add_row("Custom Patch Synthesis & Remediation PRs", "❌ Tool Only", "✅ Researcher Written Fixes", "✅ Full Remediated Codebase")
            table.add_row("Direct Access to Siva Aditya (6+ CVEs)", "❌ No", "✅ Priority Slack / Call Access", "✅ Dedicated 1-Week Sprint")
            table.add_row("EU AI Act Compliance & Regulatory Dossier", "❌ No", "✅ Quarterly Compliance Update", "✅ Full Audit Documentation")
            return table
        except Exception:
            return None


if __name__ == "__main__":
    # Test advisory engagement CLI
    key = sys.argv[1] if len(sys.argv) > 1 else "ASL-ADV-2026-RETAINER-SCOPE"
    manager = SubscriptionManager(key)
    manager.display_status()
    table = manager.get_feature_matrix_table()
    if table:
        console.print(table)
