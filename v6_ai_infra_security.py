"""
ASL V6: AI Infrastructure & LLM Security Platform
==================================================
Mission: Analyze the entire internet for AI/LLM projects, assess security posture
against OWASP Top 10 LLM 2025, OWASP Top 10 for Agents 2026, and MITRE ATLAS.

Architecture:
  Internet Discovery → Target Profiling → 10 Specialist Agents → 12-Layer Gauntlet → Intelligence

Run:
  uv run python v6/v6_ai_infra_security.py https://github.com/langchain-ai/langchain
  uv run python v6/v6_discovery_engine.py --query "langchain OR crewai" --output results.json
"""

import sys
import json
import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re
import hashlib

# Add paths for imports
_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(_ROOT / "src"))
sys.path.append(str(_ROOT / "v2"))
sys.path.append(str(_ROOT / "v4_asl_business"))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.tree import Tree
    from rich.syntax import Syntax
    from rich.markdown import Markdown
except ImportError:
    # Fallback if rich not available
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
    def Panel(*args, **kwargs): return ""
    def Table(*args, **kwargs): return ""
    class Progress:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def add_task(self, *args, **kwargs): return 0
        def update(self, *args, **kwargs): pass

console = Console()

# ─────────────────────────────────────────────────────────────────────
# ENUMS & DATA CLASSES
# ─────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class VulnerabilityCategory(str, Enum):
    # OWASP Top 10 LLM 2025
    PROMPT_INJECTION = "LLM01: Prompt Injection"
    SENSITIVE_DISCLOSURE = "LLM02: Sensitive Information Disclosure"
    SUPPLY_CHAIN = "LLM03: Supply Chain"
    DATA_MODEL_POISONING = "LLM04: Data & Model Poisoning"
    IMPROPER_OUTPUT = "LLM05: Improper Output Handling"
    OVERRELIANCE = "LLM06: Overreliance"
    SYSTEM_PROMPT_LEAK = "LLM07: System Prompt Leakage"
    VECTOR_WEAKNESS = "LLM08: Vector & Embedding Weaknesses"
    MISINFORMATION = "LLM09: Misinformation"
    UNBOUNDED_CONSUMPTION = "LLM10: Unbounded Consumption"
    
    # OWASP Top 10 for Agents 2026
    AGENT_IDENTITY = "ASI01: Agent Identity Confusion"
    GOAL_FORMULATION = "ASI02: Insecure Goal Formulation"
    MEMORY_CORRUPTION = "ASI03: Memory Corruption"
    TOOL_EXECUTION = "ASI04: Insecure Tool Execution"
    CODE_EXECUTION = "ASI05: Unexpected Code Execution"
    MEMORY_POISONING = "ASI06: Memory & Context Poisoning"
    INTER_AGENT_COMM = "ASI07: Insecure Inter-Agent Communication"
    CASCADING_FAILURE = "ASI08: Cascading Agent Failures"
    TRUST_EXPLOIT = "ASI09: Human-Agent Trust Exploitation"
    ROGUE_AGENT = "ASI10: Rogue Agents"
    
    # MITRE ATLAS
    RECONNAISSANCE = "ATLAS: Reconnaissance"
    INITIAL_ACCESS = "ATLAS: Initial Access"
    EXECUTION = "ATLAS: Execution"
    PERSISTENCE = "ATLAS: Persistence"
    PRIVILEGE_ESCALATION = "ATLAS: Privilege Escalation"
    DEFENSE_EVASION = "ATLAS: Defense Evasion"
    CREDENTIAL_ACCESS = "ATLAS: Credential Access"
    DISCOVERY = "ATLAS: Discovery"
    COLLECTION = "ATLAS: Collection"
    EXFILTRATION = "ATLAS: Exfiltration"
    IMPACT = "ATLAS: Impact"

@dataclass
class AIFinding:
    id: str = ""
    title: str = ""
    category: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    code_evidence: str = ""
    file_path: str = ""
    line_number: int = 0
    reachability: str = ""
    impact: str = ""
    poc_payload: str = ""
    expected_response: str = ""
    bounty_tier: str = ""
    remediation: str = ""
    cwe_id: str = ""
    mitre_atlas_id: str = ""
    owasp_llm_id: str = ""
    references: List[str] = field(default_factory=list)
    confidence_score: int = 0
    agent_source: str = ""
    timestamp: str = ""
    
    def to_dict(self):
        return asdict(self)

@dataclass
class TargetProfile:
    url: str = ""
    name: str = ""
    description: str = ""
    ai_frameworks: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    mcp_servers: List[str] = field(default_factory=list)
    vector_dbs: List[str] = field(default_factory=list)
    agents: List[str] = field(default_factory=list)
    apis: List[str] = field(default_factory=list)
    secrets_found: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    risk_score: int = 0
    last_scanned: str = ""

# ─────────────────────────────────────────────────────────────────────
# INTERNET DISCOVERY ENGINE
# ─────────────────────────────────────────────────────────────────────

class InternetDiscoveryEngine:
    """Discover AI/LLM projects across the entire internet"""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.results = []
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=60)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search_github(self, query: str, limit: int = 50) -> List[dict]:
        """Search GitHub for AI projects"""
        console.print(f"  [cyan]🔍 Searching GitHub: {query}[/cyan]")
        results = []
        
        # GitHub API endpoint
        url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page={min(limit, 100)}"
        
        try:
            headers = {"Accept": "application/vnd.github+json"}
            # If GITHUB_TOKEN is set, use it
            import os
            if token := os.getenv("GITHUB_TOKEN"):
                headers["Authorization"] = f"Bearer {token}"
            
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for repo in data.get("items", [])[:limit]:
                        results.append({
                            "source": "GitHub",
                            "name": repo["full_name"],
                            "url": repo["html_url"],
                            "description": repo.get("description", ""),
                            "language": repo.get("language", ""),
                            "stars": repo.get("stargazers_count", 0),
                            "updated_at": repo.get("updated_at", ""),
                            "default_branch": repo.get("default_branch", "main")
                        })
                else:
                    console.print(f"  [yellow]⚠️  GitHub API returned {resp.status}[/yellow]")
        except Exception as e:
            console.print(f"  [red]❌ GitHub search error: {e}[/red]")
        
        return results
    
    async def search_huggingface(self, query: str, limit: int = 50) -> List[dict]:
        """Search Hugging Face for AI models and spaces"""
        console.print(f"  [cyan]🤗 Searching Hugging Face: {query}[/cyan]")
        results = []
        
        try:
            # Search models
            url = f"https://huggingface.co/api/models?search={query}&limit={limit}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for model in data[:limit]:
                        results.append({
                            "source": "HuggingFace",
                            "name": model.get("id", ""),
                            "url": f"https://huggingface.co/{model.get('id', '')}",
                            "type": "model",
                            "downloads": model.get("downloads", 0),
                            "likes": model.get("likes", 0),
                            "pipeline_tag": model.get("pipeline_tag", ""),
                            "updated_at": model.get("lastModified", "")
                        })
            
            # Search spaces
            url = f"https://huggingface.co/api/spaces?search={query}&limit={limit//2}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for space in data[:limit//2]:
                        results.append({
                            "source": "HuggingFace",
                            "name": space.get("id", ""),
                            "url": f"https://huggingface.co/spaces/{space.get('id', '')}",
                            "type": "space",
                            "likes": space.get("likes", 0),
                            "sdk": space.get("sdk", ""),
                            "updated_at": space.get("lastModified", "")
                        })
        except Exception as e:
            console.print(f"  [red]❌ Hugging Face search error: {e}[/red]")
        
        return results
    
    async def search_pypi(self, query: str, limit: int = 50) -> List[dict]:
        """Search PyPI for AI packages"""
        console.print(f"  [cyan]📦 Searching PyPI: {query}[/cyan]")
        results = []
        
        try:
            url = f"https://pypi.org/search/?q={query}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Parse search results (simplified)
                    # In production, use the PyPI JSON API: https://pypi.org/pypi/{package}/json
                    pass
        except Exception as e:
            console.print(f"  [red]❌ PyPI search error: {e}[/red]")
        
        return results
    
    async def discover_targets(self, search_queries: List[str]) -> List[dict]:
        """Run comprehensive internet discovery"""
        console.print("\n[bold magenta]🌐 Internet Discovery Engine[/bold magenta]")
        console.print("   Searching GitHub, Hugging Face, PyPI for AI projects...\n")
        
        all_results = []
        
        async with self:
            for query in search_queries:
                tasks = [
                    self.search_github(query, limit=30),
                    self.search_huggingface(query, limit=20),
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, list):
                        all_results.extend(result)
        
        console.print(f"\n[green]✓ Discovered {len(all_results)} AI projects[/green]\n")
        return all_results

# ─────────────────────────────────────────────────────────────────────
# TARGET PROFILER
# ─────────────────────────────────────────────────────────────────────

class TargetProfiler:
    """Analyze discovered targets to identify AI stack and components"""
    
    AI_FRAMEWORK_PATTERNS = {
        "LangChain": ["langchain", "langgraph", "langsmith"],
        "LlamaIndex": ["llama_index", "llama-index"],
        "CrewAI": ["crewai", "crew_ai"],
        "AutoGen": ["autogen", "auto_gen", "microsoft/autogen"],
        "Haystack": ["haystack", "deepset"],
        "Semantic Kernel": ["semantic-kernel", "semantickernel"],
        "Transformers": ["transformers", "huggingface"],
        "vLLM": ["vllm"],
        "LLaMA.cpp": ["llama_cpp", "llama-cpp-python"],
        "Guardrails": ["guardrails", "guardrails-ai"],
        "LMQL": ["lmql"],
        "Guidance": ["guidance"],
    }
    
    COMPONENT_PATTERNS = {
        "Vector DB": ["chroma", "qdrant", "pinecone", "weaviate", "milvus", "faiss"],
        "MCP Server": ["mcp", "model-context-protocol"],
        "Agent Framework": ["agent", "multi-agent", "orchestrator"],
        "RAG": ["rag", "retrieval", "embedding"],
        "Fine-tuning": ["lora", "peft", "fine-tune", "rlhf"],
    }
    
    def profile_repository(self, repo_path: Path) -> TargetProfile:
        """Profile a local repository"""
        profile = TargetProfile(
            url=str(repo_path),
            name=repo_path.name,
            last_scanned=datetime.now().isoformat()
        )
        
        # Scan for AI frameworks
        for framework, patterns in self.AI_FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if self._search_files(repo_path, pattern):
                    profile.ai_frameworks.append(framework)
                    break
        
        # Scan for components
        for component, patterns in self.COMPONENT_PATTERNS.items():
            for pattern in patterns:
                if self._search_files(repo_path, pattern):
                    profile.components.append(component)
                    break
        
        # Scan for secrets
        profile.secrets_found = self._scan_secrets(repo_path)
        
        # Calculate risk score
        profile.risk_score = self._calculate_risk(profile)
        
        return profile
    
    def _search_files(self, path: Path, pattern: str) -> bool:
        """Search for pattern in files"""
        try:
            for file in path.rglob("*"):
                if file.is_file() and file.suffix in [".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"]:
                    try:
                        content = file.read_text(errors="ignore").lower()
                        if pattern.lower() in content:
                            return True
                    except:
                        pass
            return False
        except:
            return False
    
    def _scan_secrets(self, path: Path) -> List[str]:
        """Scan for exposed secrets"""
        secrets = []
        secret_patterns = [
            (r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})', "API Key"),
            (r'secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})', "Secret"),
            (r'password\s*[=:]\s*["\']([A-Za-z0-9_\-@#!]{8,})', "Password"),
            (r'token\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})', "Token"),
            (r'AWS_ACCESS_KEY_ID\s*[=:]\s*["\']?([A-Z0-9]{20})', "AWS Access Key"),
            (r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret"),
        ]
        
        try:
            for file in path.rglob("*"):
                if file.is_file() and file.suffix in [".py", ".js", ".env", ".json", ".yaml", ".yml"]:
                    try:
                        content = file.read_text(errors="ignore")
                        for pattern, secret_type in secret_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                secrets.append(f"{secret_type} in {file.relative_to(path)}")
                    except:
                        pass
        except:
            pass
        
        return secrets[:20]  # Limit to first 20
    
    def _calculate_risk(self, profile: TargetProfile) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # More AI frameworks = higher risk
        score += min(len(profile.ai_frameworks) * 10, 30)
        
        # Sensitive components
        if "Vector DB" in profile.components:
            score += 15
        if "MCP Server" in profile.components:
            score += 15
        if "Agent Framework" in profile.components:
            score += 10
        
        # Secrets exposure
        score += min(len(profile.secrets_found) * 5, 30)
        
        return min(score, 100)

# ─────────────────────────────────────────────────────────────────────
# CONTINUE IN NEXT FILE...
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python v6_ai_infra_security.py <github_url_or_path>[/red]")
        console.print("[dim]Example: python v6_ai_infra_security.py https://github.com/langchain-ai/langchain[/dim]")
        sys.exit(1)
    
    console.print(Panel.fit(
        "[bold red]ASL V6[/bold red]\\n"
        "[bold white]AI Infrastructure & LLM Security Platform[/bold white]\\n"
        "[dim]Powered by OWASP Top 10 LLM 2025, OWASP Top 10 for Agents 2026, MITRE ATLAS[/dim]",
        border_style="red"
    ))
    
    target = sys.argv[1]
    
    # Phase 1: Discovery
    console.print("\n[bold magenta]Phase 1: Target Discovery[/bold magenta]")
    if target.startswith("http"):
        console.print(f"   Target: {target}")
        console.print("   [yellow]Internet discovery not yet implemented for CLI run[/yellow]")
        console.print("   [dim]Use: python v6_discovery_engine.py --query \"langchain\" for internet scan[/dim]")
    else:
        repo_path = Path(target)
        if not repo_path.exists():
            console.print(f"[red]Error: Path not found: {repo_path}[/red]")
            sys.exit(1)
        
        # Phase 2: Profiling
        console.print("\n[bold magenta]Phase 2: Target Profiling[/bold magenta]")
        profiler = TargetProfiler()
        profile = profiler.profile_repository(repo_path)
        
        console.print(f"\n[bold]Repository:[/bold] {profile.name}")
        console.print(f"[bold]AI Frameworks:[/bold] {', '.join(profile.ai_frameworks) or 'None detected'}")
        console.print(f"[bold]Components:[/bold] {', '.join(profile.components) or 'None detected'}")
        console.print(f"[bold]Risk Score:[/bold] {profile.risk_score}/100")
        
        if profile.secrets_found:
            console.print(f"\n[yellow]⚠️  Secrets Detected:[/yellow]")
            for secret in profile.secrets_found[:5]:
                console.print(f"   - {secret}")
        
        console.print("\n[bold magenta]Phase 3-12: Security Analysis (Coming Soon)[/bold magenta]")
        console.print("   [dim]Specialist agents, verification gauntlet, and reporting under development[/dim]")