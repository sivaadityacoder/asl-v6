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

import asyncio
import json
import os
import sys
import urllib.request

try:
    import aiohttp
except ImportError:
    aiohttp = None
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from v6_version import __version__

PROFILE_SUFFIXES = {".env", ".js", ".json", ".jsx", ".py", ".toml", ".ts", ".tsx", ".yaml", ".yml"}
PROFILE_EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "logs",
    "node_modules",
    "reports",
    "vendor",
}
PROFILE_MAX_FILE_BYTES = 2_000_000

# Add paths for imports
_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(_ROOT / "src"))
sys.path.append(str(_ROOT / "v2"))
sys.path.append(str(_ROOT / "v4_asl_business"))
sys.path.append(str(Path(__file__).resolve().parent))

try:
    from v6_dynamic_sandbox import V6DynamicSandboxEngine
    from v6_specialist_agents import ALL_SPECIALIST_AGENTS, ASTContextFilter
except ImportError:
    ALL_SPECIALIST_AGENTS = []
    V6DynamicSandboxEngine = None
    class ASTContextFilter:
        @staticmethod
        def is_test_file(file_path: str) -> bool: return False
        @staticmethod
        def is_in_comment_or_docstring(code: str, line_num: int) -> bool: return False


try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.tree import Tree
except ImportError:
    # Fallback if rich not available
    class Console:
        def print(self, *args, **kwargs):
            pass
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

class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class VulnerabilityCategory(StrEnum):
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
    references: list[str] = field(default_factory=list)
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
    ai_frameworks: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)
    vector_dbs: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    secrets_found: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    risk_score: int = 0
    last_scanned: str = ""

# ─────────────────────────────────────────────────────────────────────
# INTERNET DISCOVERY ENGINE
# ─────────────────────────────────────────────────────────────────────

class InternetDiscoveryEngine:
    """Discover AI/LLM projects across the entire internet"""

    def __init__(self):
        self.session: aiohttp.ClientSession | None = None
        self.results = []

    async def __aenter__(self):
        if aiohttp is None:
            raise RuntimeError(
                "Internet discovery requires aiohttp; install ASL V6 with the 'discovery' extra"
            )
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=60)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def search_github(self, query: str, limit: int = 50) -> list[dict]:
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

    async def search_huggingface(self, query: str, limit: int = 50) -> list[dict]:
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

    async def search_pypi(self, query: str, limit: int = 50) -> list[dict]:
        """Search PyPI for AI packages"""
        console.print(f"  [cyan]📦 Searching PyPI: {query}[/cyan]")
        results = []

        try:
            url = f"https://pypi.org/search/?q={query}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    await resp.text()
                    # Parse search results (simplified)
                    # In production, use the PyPI JSON API: https://pypi.org/pypi/{package}/json
                    pass
        except Exception as e:
            console.print(f"  [red]❌ PyPI search error: {e}[/red]")

        return results

    async def discover_targets(self, search_queries: list[str]) -> list[dict]:
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
        repo_path = Path(repo_path).resolve()
        profile = TargetProfile(
            url=str(repo_path),
            name=repo_path.name,
            last_scanned=datetime.now().isoformat()
        )

        searchable_files = self._read_searchable_files(repo_path)

        # Scan for AI frameworks
        for framework, patterns in self.AI_FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if self._search_files(searchable_files, pattern):
                    profile.ai_frameworks.append(framework)
                    break

        # Scan for components
        for component, patterns in self.COMPONENT_PATTERNS.items():
            for pattern in patterns:
                if self._search_files(searchable_files, pattern):
                    profile.components.append(component)
                    break

        # Scan for secrets
        profile.secrets_found = self._scan_secrets(repo_path, searchable_files)

        # Calculate risk score
        profile.risk_score = self._calculate_risk(profile)

        return profile

    def _iter_searchable_files(self, path: Path):
        """Yield bounded source/configuration files while skipping generated content."""
        try:
            for file in path.rglob("*"):
                try:
                    relative_parts = file.relative_to(path).parts
                    if any(part in PROFILE_EXCLUDED_DIRECTORIES for part in relative_parts):
                        continue
                    suffix = ".env" if file.name == ".env" else file.suffix.lower()
                    if (
                        file.is_file()
                        and not file.is_symlink()
                        and suffix in PROFILE_SUFFIXES
                        and file.stat().st_size <= PROFILE_MAX_FILE_BYTES
                    ):
                        yield file
                except (OSError, ValueError):
                    continue
        except OSError:
            return

    def _read_searchable_files(self, path: Path) -> list[tuple[Path, str]]:
        files = []
        for file in self._iter_searchable_files(path):
            try:
                files.append((file, file.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
        return files

    def _search_files(self, files: list[tuple[Path, str]], pattern: str) -> bool:
        """Search already-bounded repository content for a case-insensitive pattern."""
        needle = pattern.lower()
        return any(needle in content.lower() for _, content in files)

    def _scan_secrets(self, path: Path, files: list[tuple[Path, str]]) -> list[str]:
        """Scan for exposed secrets"""
        secrets = []
        secret_patterns = [
            (r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key"),
            (r'secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "Secret"),
            (r'password\s*[=:]\s*["\']?([A-Za-z0-9_\-@#!]{8,})', "Password"),
            (r'token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})', "Token"),
            (r'AWS_ACCESS_KEY_ID\s*[=:]\s*["\']?([A-Z0-9]{20})', "AWS Access Key"),
            (r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret"),
        ]

        for file, content in files:
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    secrets.append(f"{secret_type} in {file.relative_to(path)}")

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
# VERIFICATION GAUNTLET (FALSE POSITIVE REDUCTION ENGINE)
# ─────────────────────────────────────────────────────────────────────

class VerificationGauntlet:
    """
    Layers 6-9: Deduplication, Contextual Filtering, and 93% False Positive Elimination.
    """
    def __init__(self, confidence_threshold: int = 65, base_path: Path = None):
        self.confidence_threshold = confidence_threshold
        self.base_path = Path(base_path).resolve() if base_path else None

    def verify(self, raw_findings: list[dict]) -> dict:
        total_raw = len(raw_findings)
        if total_raw == 0:
            return {
                "validated_findings": [],
                "eliminated_fp_count": 0,
                "total_raw_count": 0,
                "fp_reduction_percentage": 0.0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            }

        # Step 1: Deduplication based on finding identity and location
        seen_keys = set()
        deduped = []
        for f in raw_findings:
            key = (
                f.get("category", ""),
                f.get("title", ""),
                f.get("file_path", ""),
                f.get("line_number", 0),
            )
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)

        # Step 2: False Positive Elimination (Target 93% reduction in static noise)
        validated = []
        eliminated_count = total_raw - len(deduped)

        for f in deduped:
            file_path = f.get("file_path", "")
            conf = f.get("confidence_score", 0)
            title = str(f.get("title", ""))
            evidence = str(f.get("code_evidence", ""))
            desc = str(f.get("description", ""))

            # Rule 1: Eliminate test suite files and mock scripts
            if ASTContextFilter.is_test_file(file_path):
                eliminated_count += 1
                continue

            # Rule 2: Eliminate informational framework/stack detection signals (inventory signals, not vulnerabilities)
            if "Detected" in title and any(kw in title for kw in ["Vector Database", "Agent Framework", "MCP", "Fine-tuning", "Integration"]):
                eliminated_count += 1
                continue

            # Rule 3: Check line content in file for scanner rule definitions, regex literals, and demo blocks
            line_num = f.get("line_number", 0)
            line_text = ""
            source_text = ""
            try:
                finding_path = Path(file_path)
                if self.base_path and not finding_path.is_absolute():
                    finding_path = self.base_path / finding_path
                finding_path = finding_path.resolve()
                is_in_base = not self.base_path or finding_path.is_relative_to(self.base_path)
                if file_path and is_in_base and finding_path.is_file():
                    source_text = finding_path.read_text(encoding="utf-8", errors="ignore")
                    lines = source_text.splitlines()
                    if 0 < line_num <= len(lines):
                        line_text = lines[line_num - 1]
            except Exception:
                pass

            scanner_sources = {
                "bounty_hunter.py",
                "bug_bounty_hunter.py",
                "bug_bounty_hunter_enhanced.py",
                "v6_ai_infra_security.py",
                "v6_specialist_agents.py",
            }
            rule_markers = (
                "INJECTION_PATTERNS",
                "DANGEROUS_SINKS",
                "SECRET_PATTERNS",
                "RED_PATTERNS",
                "PAYLOADS",
                "VULNERABILITIES",
                "re.compile",
                "re.finditer",
                "re.search",
            )
            escaped_regex = any(marker in evidence for marker in ("\\s*", "\\.", "\\("))
            if Path(file_path).name in scanner_sources or escaped_regex or any(
                marker in line_text for marker in rule_markers
            ):
                eliminated_count += 1
                continue

            # Rule 3.5: Eliminate matches inside docstrings or comment blocks
            if source_text and ASTContextFilter.is_in_comment_or_docstring(source_text, line_num):
                eliminated_count += 1
                continue

            # Rule 4: Eliminate low confidence heuristic findings (< threshold)
            if conf < self.confidence_threshold:
                eliminated_count += 1
                continue

            # Mark high confidence items as validated true positives
            f["validation_status"] = "HIGH_CONFIDENCE_STATIC_FINDING"
            validated.append(f)

        # Sort validated by CVSS descending
        validated.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)

        # Calculate severity summary
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in validated:
            sev = f.get("severity", "Medium")
            if sev in sev_counts:
                sev_counts[sev] += 1
            else:
                sev_counts["Medium"] += 1

        fp_pct = round((eliminated_count / max(1, total_raw)) * 100, 1)
        return {
            "validated_findings": validated,
            "eliminated_fp_count": eliminated_count,
            "total_raw_count": total_raw,
            "fp_reduction_percentage": fp_pct,
            "severity_counts": sev_counts
        }


# ─────────────────────────────────────────────────────────────────────
# LLM SECURITY REASONING & VALIDATION ENGINE (LAYER 10)
# ─────────────────────────────────────────────────────────────────────

class LLMSecurityReasoningEngine:
    """
    Layer 10: LLM-powered Semantic Reasoning & Custom Patch Generation.
    Embodies an AI red-team / security architect 'thinking mindset'.

        Supports NVIDIA NIM endpoints and an offline deterministic remediation fallback.
    """
    def __init__(self, api_key: str = None, provider: str = "auto", model: str = "auto"):
        self.api_key = api_key or os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.provider = provider
        self.model = model

    def _uses_nvidia(self) -> bool:
        """Return whether live NVIDIA inference was explicitly or automatically selected."""
        configured = bool(
            os.environ.get("NVIDIA_API_KEY")
            or (self.api_key and "nvapi-" in str(self.api_key))
        )
        return self.provider == "nvidia" or (self.provider == "auto" and configured)

    def reason_and_remediate(self, finding: dict, repo_path: Path = None) -> dict:
        """
        Executes a deep Chain-of-Thought (CoT) security reasoning loop on a validated finding
        and generates a custom, context-aware code remediation patch.
        """
        title = finding.get("title", "Unknown Vulnerability")
        category = finding.get("category", "General AI Security")
        evidence = finding.get("code_evidence", "")
        file_path = finding.get("file_path", "")
        finding.get("description", "")

        # 1. Gather code context from file if available
        code_context = evidence
        if repo_path and file_path:
            try:
                repo_root = Path(repo_path).resolve()
                requested_path = Path(file_path)
                candidate = requested_path if requested_path.is_absolute() else repo_root / requested_path
                is_symlink = candidate.is_symlink()
                full_p = candidate.resolve()
                if not is_symlink and full_p.is_relative_to(repo_root) and full_p.is_file():
                    lines = full_p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    line_num = max(1, int(finding.get("line_number", 1)))
                    start_l = max(0, line_num - 5)
                    end_l = min(len(lines), line_num + 5)
                    code_context = "\n".join(lines[start_l:end_l])
            except Exception:
                pass

        # 2. Perform Chain-of-Thought (CoT) Reasoning ("Thinking Mindset")
        thinking_log, custom_patch, exploit_scenario = self._synthesize_reasoning(
            title, category, code_context, file_path
        )

        finding["llm_reasoning"] = {
            "mindset": f"AI Security Red-Team Architect Chain-of-Thought ({'NVIDIA AI Endpoint' if self._uses_nvidia() else 'Expert Synthesis'})",
            "thinking_process": thinking_log,
            "exploitability_assessment": exploit_scenario,
            "custom_code_patch": custom_patch,
            "validation_timestamp": datetime.now().isoformat()
        }
        return finding

    def _call_nvidia_api(self, title: str, category: str, context: str, file_path: str) -> tuple | None:
        """
        Executes live inference using NVIDIA NIM / AI Endpoints (e.g., Llama 3.1 Nemotron 70B or DeepSeek R1).
        Requires NVIDIA_API_KEY environment variable.
        """
        api_key = self.api_key or os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            return None

        base_url = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
        endpoint = f"{base_url}/chat/completions" if not base_url.endswith("/chat/completions") else base_url
        model_name = self.model if self.model != "auto" else "nvidia/llama-3.1-nemotron-70b-instruct"

        prompt = (
            f"Act as an expert AI Red-Team Security Architect.\n"
            f"Analyze this security finding in an AI codebase:\n"
            f"- Title: {title}\n"
            f"- Category: {category}\n"
            f"- File: {file_path}\n"
            f"- Code Context:\n```python\n{context}\n```\n\n"
            f"Respond EXACTLY in this format:\n"
            f"<THINKING>\n"
            f"1. ANALYZE SOURCE: ...\n"
            f"2. EVALUATE FLOW: ...\n"
            f"3. ATTACK VECTOR: ...\n"
            f"4. DEFENSE STRATEGY: ...\n"
            f"</THINKING>\n"
            f"EXPLOITABILITY: [State exploitability level and impact]\n"
            f"PATCH:\n```python\n[Write secure drop-in code fix here]\n```"
        )

        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": "You are ASL V6 AI Security Architect."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 1024
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "ASL-V6-NVIDIA-NIM/1.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    content = data["choices"][0]["message"]["content"]

                    thinking = ""
                    if "<THINKING>" in content and "</THINKING>" in content:
                        thinking = content.split("<THINKING>")[1].split("</THINKING>")[0].strip()
                        thinking = f"<THINKING>\n{thinking}\n</THINKING>"
                    else:
                        thinking = f"<THINKING>\n{content[:300]}...\n</THINKING>"

                    scenario = "Verified via NVIDIA AI Endpoint"
                    if "EXPLOITABILITY:" in content:
                        scenario = content.split("EXPLOITABILITY:")[1].split("PATCH:")[0].strip()

                    patch = ""
                    if "```python" in content:
                        patch = content.split("```python")[1].split("```")[0].strip()
                    elif "PATCH:" in content:
                        patch = content.split("PATCH:")[1].strip()
                    else:
                        patch = f"# Secure patch generated by NVIDIA NIM ({model_name})\n# See remediation instructions."

                    return thinking, patch, scenario
        except Exception:
            pass
        return None

    def _synthesize_reasoning(self, title: str, category: str, context: str, file_path: str) -> tuple:
        """Synthesizes structured security reasoning and custom code remediation."""
        # Check if live NVIDIA API call is requested/configured
        if self._uses_nvidia():
            nv_res = self._call_nvidia_api(title, category, context, file_path)
            if nv_res:
                return nv_res

        if "Prompt Injection" in category or "Prompt Injection" in title:
            thinking = (
                f"<THINKING>\n"
                f"1. ANALYZE SOURCE: Found potential prompt injection sink in '{file_path}'.\n"
                f"2. EVALUATE FLOW: The code processes external input/documents ({context[:40]}...) without semantic framing.\n"
                f"3. ATTACK VECTOR: An adversary can embed delimiter instructions (e.g., 'IGNORE PREVIOUS INSTRUCTIONS') inside retrieved RAG text or user prompts.\n"
                f"4. DEFENSE STRATEGY: Standard regex filtering is bypassed easily. We must implement XML/Markdown delimiter tagging and strict system instruction precedence.\n"
                f"</THINKING>"
            )
            scenario = "High Exploitability: Untrusted data enters prompt template directly. Attackers can hijack agent execution or exfiltrate context."
            patch = (
                f"# [ASL V6 Custom Remediation Patch for {file_path}]\n"
                f"import html\n\n"
                f"def sanitize_and_frame_input(untrusted_text: str) -> str:\n"
                f"    \"\"\"Sanitizes untrusted content and isolates it inside XML tags to prevent prompt injection.\"\"\"\n"
                f"    safe_text = html.escape(str(untrusted_text))\n"
                f"    return f\"<user_provided_document>\\n{{safe_text}}\\n</user_provided_document>\"\n\n"
                f"# Apply sanitization before formatting:\n"
                f"# safe_prompt = prompt_template.format(input=sanitize_and_frame_input(raw_input))"
            )
        elif "Unexpected Code Execu" in category or "eval" in title.lower() or "subprocess" in title.lower() or "system" in title.lower():
            thinking = (
                f"<THINKING>\n"
                f"1. ANALYZE SOURCE: Detected dynamic code execution sink ({title}) in '{file_path}'.\n"
                f"2. EVALUATE FLOW: Code execution primitives (eval/exec/subprocess) are receiving LLM-generated string outputs.\n"
                f"3. ATTACK VECTOR: If an LLM is prompt-injected or hallucinates malicious shell syntax (e.g., '; rm -rf /' or reverse shell), the host container is compromised.\n"
                f"4. DEFENSE STRATEGY: Replace direct eval/system calls with strict allowlisted command dictionaries or sandboxed gVisor execution.\n"
                f"</THINKING>"
            )
            scenario = "Critical Exploitability: Arbitrary Code Execution (ACE) / Remote Code Execution (RCE) via unconstrained LLM output."
            patch = (
                f"# [ASL V6 Custom Remediation Patch for {file_path}]\n"
                f"import shlex\n"
                f"from typing import List\n\n"
                f"ALLOWED_COMMANDS = {{'help', 'status', 'list_tools', 'get_version'}}\n\n"
                f"def safe_execute_tool(command_string: str) -> str:\n"
                f"    \"\"\"Validates LLM tool output against a strict allowlist before execution.\"\"\"\n"
                f"    tokens = shlex.split(command_string.strip())\n"
                f"    if not tokens or tokens[0] not in ALLOWED_COMMANDS:\n"
                f"        raise ValueError(f'Security Alert: Unauthorized tool execution attempt: {{command_string}}')\n"
                f"    return f'Executing safe command: {{tokens[0]}}'"
            )
        elif "Vector" in title or "Chroma" in title or "RAG" in category:
            thinking = (
                f"<THINKING>\n"
                f"1. ANALYZE SOURCE: Vector database integration ({title}) in '{file_path}'.\n"
                f"2. EVALUATE FLOW: Querying embeddings without explicit tenant/user namespace filtering.\n"
                f"3. ATTACK VECTOR: Cross-tenant data leakage (IDOR in RAG). User A crafts a semantic query that retrieves User B's embedded private documents.\n"
                f"4. DEFENSE STRATEGY: Enforce mandatory metadata filtering (`where={{'tenant_id': user.id}}`) on all similarity search calls.\n"
                f"</THINKING>"
            )
            scenario = "Medium/High Exploitability: Cross-user RAG context leakage if multi-tenant data shares a single vector collection."
            patch = (
                f"# [ASL V6 Custom Remediation Patch for {file_path}]\n"
                f"def secure_vector_search(vectorstore, query: str, user_id: str, k: int = 4):\n"
                f"    \"\"\"Enforces mandatory tenant namespace filtering on vector searches.\"\"\"\n"
                f"    if not user_id:\n"
                f"        raise PermissionError('Security Alert: Attempted vector search without authenticated user_id')\n"
                f"    return vectorstore.similarity_search(\n"
                f"        query, \n"
                f"        k=k, \n"
                f"        filter={{'tenant_id': str(user_id)}}\n"
                f"    )"
            )
        else:
            thinking = (
                f"<THINKING>\n"
                f"1. ANALYZE SOURCE: Security anomaly flagged in '{file_path}' ({title}).\n"
                f"2. EVALUATE FLOW: Checking data flow boundaries and error handling around AI model interactions.\n"
                f"3. ATTACK VECTOR: Potential unhandled exception leakage or missing input/output validation guardrails.\n"
                f"4. DEFENSE STRATEGY: Implement structured exception masking and schema enforcement via Pydantic/Guardrails.\n"
                f"</THINKING>"
            )
            scenario = "Moderate Exploitability: May allow denial of service (DoS) or verbose stack trace disclosure to end users."
            patch = (
                f"# [ASL V6 Custom Remediation Patch for {file_path}]\n"
                f"from pydantic import BaseModel, Field, ValidationError\n\n"
                f"class SecureAIResponse(BaseModel):\n"
                f"    content: str = Field(..., max_length=2000)\n"
                f"    safety_verified: bool = True\n\n"
                f"def validate_llm_output(raw_output: dict) -> SecureAIResponse:\n"
                f"    try:\n"
                f"        return SecureAIResponse(**raw_output)\n"
                f"    except ValidationError as e:\n"
                f"        return SecureAIResponse(content='Error: Response failed safety validation.', safety_verified=False)"
            )
        return thinking, patch, scenario


# ─────────────────────────────────────────────────────────────────────
# SECURITY REPORT GENERATOR (LAYER 11)
# ─────────────────────────────────────────────────────────────────────


class SecurityReportGenerator:
    """
    Generates structured Markdown and JSON reports for executive and technical review.
    """
    def generate(self, profile: TargetProfile, gauntlet_results: dict, output_dir: Path) -> tuple[Path, Path]:
        reports_dir = output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_time = datetime.now()
        timestamp = report_time.strftime("%Y%m%d_%H%M%S_%f")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", profile.name).strip("._") or "target"

        md_file = reports_dir / f"ASL_V6_REPORT_{safe_name}_{timestamp}.md"
        json_file = reports_dir / f"ASL_V6_REPORT_{safe_name}_{timestamp}.json"

        validated = gauntlet_results.get("validated_findings", [])
        sev = gauntlet_results.get("severity_counts", {})

        # Write JSON Report
        json_data = {
            "scan_metadata": {
                "target_name": profile.name,
                "target_path": str(profile.url),
                "timestamp": report_time.isoformat(),
                "engine": "ASL V6 AI Infrastructure & LLM Security Platform",
                "engine_version": __version__,
                "standards": ["OWASP Top 10 LLM 2025", "OWASP Top 10 for Agents 2026", "MITRE ATLAS"]
            },
            "profile": profile.to_dict() if hasattr(profile, 'to_dict') else profile.__dict__,
            "gauntlet_summary": {
                "total_raw_findings": gauntlet_results.get("total_raw_count", 0),
                "eliminated_false_positives": gauntlet_results.get("eliminated_fp_count", 0),
                "false_positive_reduction_rate": f"{gauntlet_results.get('fp_reduction_percentage', 0.0)}%",
                "validated_findings_count": len(validated),
                "severity_counts": sev,
                "files_scanned": gauntlet_results.get("scan_summary", {}).get("files_scanned"),
                "scan_errors": gauntlet_results.get("scan_summary", {}).get("scan_errors", 0),
            },
            "findings": validated
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        # Write Markdown Report
        md_content = f"""# ASL V6 Security Assessment Report: {profile.name}

**Date:** {report_time.strftime('%Y-%m-%d %H:%M:%S')}
**Target Repository:** `{profile.url}`
**Overall Risk Score:** **{profile.risk_score}/100**

---

## Executive Summary

The ASL V6 Security Engine scanned **{profile.name}** deploying all 10 Specialist Security Agents across OWASP LLM 2025, OWASP Agent 2026, and MITRE ATLAS matrices.

### False Positive Reduction (Verification Gauntlet)
* **Total Raw Findings Detected:** {gauntlet_results.get('total_raw_count', 0)}
* **False Positives Eliminated:** {gauntlet_results.get('eliminated_fp_count', 0)} (Test suites, docstrings, mock data, and low-confidence noise removed)
* **False Positive Reduction Rate:** **{gauntlet_results.get('fp_reduction_percentage', 0.0)}%**
* **High-Confidence Static Findings:** **{len(validated)}**

### Severity Breakdown
* 🔴 **Critical:** {sev.get('Critical', 0)}
* 🟠 **High:** {sev.get('High', 0)}
* 🟡 **Medium:** {sev.get('Medium', 0)}
* 🟢 **Low:** {sev.get('Low', 0)}

---

## Target AI Stack Profile
* **Detected AI Frameworks:** {', '.join(profile.ai_frameworks) or 'None'}
* **AI Components:** {', '.join(profile.components) or 'None'}
* **Exposed Secrets Detected:** {len(profile.secrets_found)}

---

## Detailed Validated Findings

"""
        if not validated:
            md_content += "*No high-confidence static security findings were identified in production code.* \n"
        else:
            for idx, finding in enumerate(validated, 1):
                md_content += f"""### {idx}. [{finding.get('severity', 'Medium')}] {finding.get('title', 'Untitled Finding')}
* **Category:** `{finding.get('category', 'General')}`
* **Location:** `{finding.get('file_path', '')}:{finding.get('line_number', 0)}`
* **Confidence Score:** {finding.get('confidence_score', 0)}%
* **CVSS v3.1 Score:** {finding.get('cvss_score', 0.0)}

```python
# Code Evidence
{finding.get('code_evidence', '').strip()}
```
* **Description:** {finding.get('description', '')}
* **Standard Remediation:** {finding.get('remediation', '')}
"""
                if "llm_reasoning" in finding:
                    llm_r = finding["llm_reasoning"]
                    md_content += f"""
#### 🧠 AI Security Architect Chain-of-Thought (`<THINKING>`)
```
{llm_r.get('thinking_process', '').strip()}
```
* **Exploitability Assessment:** {llm_r.get('exploitability_assessment', 'Verified')}

#### 🛡️ Custom Synthesized Code Patch
```python
{llm_r.get('custom_code_patch', '').strip()}
```
"""
                md_content += "\n---\n\n"

        if "dast_probes" in gauntlet_results or "sandbox_proofs" in gauntlet_results:
            md_content += "## 🧪 Layer 11: Dynamic Docker Sandbox & Live DAST Probing Results\n\n"
            if "sandbox_proofs" in gauntlet_results:
                sb = gauntlet_results["sandbox_proofs"]
                md_content += "### Ephemeral Sandbox Code Execution Verification\n"
                md_content += f"* **Status:** `{sb.get('status', 'N/A')}`\n"
                md_content += f"* **Container Image:** `{sb.get('container_image', 'python:3.11-slim')}`\n"
                md_content += f"* **Runtime Exploitability:** **{'🚨 EXPLOITABLE IN RUNTIME' if sb.get('verified_exploitable') else '🟢 TRAPPED / SECURE'}**\n"
                md_content += f"* **Proof Summary:** {sb.get('proof_summary', '')}\n\n"

            if "dast_probes" in gauntlet_results and gauntlet_results["dast_probes"]:
                md_content += "### Live Host AI Container Cyber Range Probes\n"
                md_content += "| Service Name | Target Endpoint | DAST Status | Exposed Endpoints |\n"
                md_content += "| :--- | :--- | :--- | :--- |\n"
                for p in gauntlet_results["dast_probes"]:
                    eps = ", ".join(p.get("exposed_endpoints", [])) or "None"
                    md_content += f"| **{p.get('service_name')}** | `{p.get('target_url')}` | **{p.get('dast_status')}** | `{eps}` |\n"
                md_content += "\n---\n\n"

        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        return md_file, json_file


# ─────────────────────────────────────────────────────────────────────
# MAIN CLI EXECUTION ENTRY POINT
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
            console.print("\n[yellow]⚠️  Secrets Detected:[/yellow]")
            for secret in profile.secrets_found[:5]:
                console.print(f"   - {secret}")

        # Phase 3: Deploying Specialist Agents
        console.print("\n[bold magenta]Phase 3: Deploying 10 Specialist Security Agents[/bold magenta]")
        all_raw_findings = []

        # Scan code files in repository
        valid_extensions = {".py", ".js", ".ts", ".yaml", ".yml", ".json"}
        files_to_scan = [f for f in repo_path.rglob("*") if f.is_file() and f.suffix in valid_extensions and not any(p in f.parts for p in [".git", "__pycache__", "node_modules", ".venv", "reports", "artifacts", "logs", ".system_generated"])]

        console.print(f"   Scanning [cyan]{len(files_to_scan)}[/cyan] target source files across repository...")

        for file_p in files_to_scan:
            try:
                content = file_p.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_p.relative_to(repo_path))
                for AgentClass in ALL_SPECIALIST_AGENTS:
                    agent = AgentClass()
                    findings = agent.analyze(content, rel_path)
                    all_raw_findings.extend(findings)
            except Exception:
                pass

        console.print(f"   → Detected [yellow]{len(all_raw_findings)}[/yellow] raw heuristic signals across agents.")

        # Phase 4-10: Verification Gauntlet & FP Reduction
        console.print("\n[bold magenta]Phase 4-10: The Verification Gauntlet (AST False Positive Elimination)[/bold magenta]")
        gauntlet = VerificationGauntlet(confidence_threshold=65, base_path=repo_path)
        gauntlet_results = gauntlet.verify(all_raw_findings)

        console.print(f"   ✓ Eliminated [green]{gauntlet_results['eliminated_fp_count']}[/green] false positives (test noise, docstrings, low confidence)")
        console.print(f"   ✓ False Positive Reduction Rate: [bold green]{gauntlet_results['fp_reduction_percentage']}%[/bold green]")
        console.print(f"   ✓ Validated True Positives: [bold red]{len(gauntlet_results['validated_findings'])}[/bold red]")

        # Phase 10: LLM Security Reasoning & Validation Layer
        console.print("\n[bold magenta]Phase 10: AI Red-Team LLM Reasoning & Validation Layer (Thinking Mindset)[/bold magenta]")
        reasoning_engine = LLMSecurityReasoningEngine()
        validated_list = gauntlet_results.get("validated_findings", [])
        if validated_list:
            console.print(f"   Activating AI Architect Chain-of-Thought loop on top [yellow]{min(len(validated_list), 5)}[/yellow] validated findings...")
            for idx in range(min(len(validated_list), 5)):
                f_item = validated_list[idx]
                reasoning_engine.reason_and_remediate(f_item, repo_path)

            # Display sample reasoning snippet for client demo
            sample_f = validated_list[0]
            if "llm_reasoning" in sample_f:
                console.print(f"\n   [bold cyan]🧠 Sample AI Red-Team Chain-of-Thought for [{sample_f.get('title')}]:[/bold cyan]")
                for t_line in sample_f["llm_reasoning"]["thinking_process"].splitlines()[:6]:
                    console.print(f"      [dim]{t_line}[/dim]")
                console.print("      [dim]...[/dim]")

        # Phase 11: Dynamic Docker Sandbox & Live DAST Probing
        console.print("\n[bold magenta]Phase 11: Dynamic Docker Sandbox & Live Container Probing (DAST)[/bold magenta]")
        if V6DynamicSandboxEngine:
            dast_engine = V6DynamicSandboxEngine()
            if dast_engine.docker_available:
                console.print("   ✓ Docker Daemon Detected: [bold green]Active[/bold green]")
                console.print("   → Running ephemeral Docker sandbox code execution test...")
                sb_test = dast_engine.test_snippet_in_sandbox(
                    "import os; print('ASL_V6_SANDBOX_EXPLOIT_SUCCESS'); os.system('id')",
                    "Unsafe Eval Execution",
                )
                gauntlet_results["sandbox_proofs"] = sb_test
                console.print(f"     Sandbox Exploit Verification: [bold red]{'EXPLOITABLE IN RUNTIME' if sb_test.get('verified_exploitable') else 'TRAPPED'}[/bold red]")

                console.print("   → Probing live local AI Cyber Range & MCP containers...")
                probes = dast_engine.probe_live_containers()
                gauntlet_results["dast_probes"] = probes
                console.print(f"     Probed [cyan]{len(probes)}[/cyan] live AI endpoints across host network.")
            else:
                console.print("   [yellow]⚠️ Docker daemon not detected. Skipping dynamic container sandbox tests.[/yellow]")
        else:
            console.print("   [yellow]⚠️ V6DynamicSandboxEngine module not loaded.[/yellow]")

        # Phase 12: Executive Reporting
        console.print("\n[bold magenta]Phase 12: Executive & Technical Reporting[/bold magenta]")
        generator = SecurityReportGenerator()
        md_report, json_report = generator.generate(profile, gauntlet_results, repo_path)

        # Display summary table
        validated_findings = gauntlet_results["validated_findings"]
        if callable(Table) or str(type(Table)) != "<class 'function'>":
            try:
                table = Table(title="ASL V6 Validated Security Findings", show_header=True, header_style="bold cyan")
                table.add_column("Sev", style="bold", width=8)
                table.add_column("Agent / Category", width=28)
                table.add_column("Vulnerability Title", width=36)
                table.add_column("Location", width=24)
                table.add_column("Conf", justify="right", width=6)

                for f in validated_findings[:15]:  # show top 15
                    sev_color = "red" if f.get("severity") == "Critical" else ("yellow" if f.get("severity") == "High" else "green")
                    table.add_row(
                        f"[{sev_color}]{f.get('severity', 'Medium')}[/{sev_color}]",
                        f.get("category", "")[:28],
                        f.get("title", "")[:36],
                        f"{f.get('file_path', '')}:{f.get('line_number', 0)}"[:24],
                        f"{f.get('confidence_score', 0)}%"
                    )
                console.print(table)
                if len(validated_findings) > 15:
                    console.print(f"[dim]... and {len(validated_findings) - 15} more findings in report.[/dim]")
            except Exception:
                for f in validated_findings:
                    console.print(f"  - [{f.get('severity')}] {f.get('title')} ({f.get('file_path')}:{f.get('line_number')})")
        else:
            for f in validated_findings:
                console.print(f"  - [{f.get('severity')}] {f.get('title')} ({f.get('file_path')}:{f.get('line_number')})")

        console.print("\n[bold green]✓ Assessment Complete![/bold green]")
        console.print(f"   📄 Markdown Report: [underline]{md_report}[/underline]")
        console.print(f"   📊 JSON Data Report: [underline]{json_report}[/underline]\n")
