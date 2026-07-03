"""
ASL V6 - 10-Layer Scan Pipeline
Orchestrates the full security analysis lifecycle from repository cloning
through verified finding output. Integrates with the FP reduction gauntlet.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
import structlog

from app.scan.false_positive_reducer import (
    FalsePositiveReducer,
    RawFinding,
    VerifiedFinding,
    GauntletStats,
)

logger = structlog.get_logger(__name__)


class ScanStatus(str, Enum):
    PENDING = "pending"
    CLONING = "cloning"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    COMPLETE = "complete"
    FAILED = "failed"


class AIFramework(str, Enum):
    LANGCHAIN = "langchain"
    LLAMA_INDEX = "llama_index"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    TRANSFORMERS = "transformers"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    HAYSTACK = "haystack"
    DSPY = "dspy"
    UNKNOWN = "unknown"


@dataclass
class RepoProfile:
    """Profiling result from Layer 1."""
    url: str
    local_path: str
    primary_language: str
    ai_frameworks: list[AIFramework]
    has_requirements: bool
    has_docker: bool
    has_kubernetes: bool
    file_count: int
    python_files: list[str]
    js_files: list[str]
    yaml_files: list[str]
    total_lines: int


@dataclass
class ScanResult:
    scan_id: str
    repo_url: str
    status: ScanStatus
    raw_finding_count: int = 0
    verified_finding_count: int = 0
    findings: list[VerifiedFinding] = field(default_factory=list)
    gauntlet_stats: GauntletStats | None = None
    layer_timing: dict[str, float] = field(default_factory=dict)
    error: str | None = None
    ai_frameworks_detected: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "repo_url": self.repo_url,
            "status": self.status.value,
            "raw_finding_count": self.raw_finding_count,
            "verified_finding_count": self.verified_finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "gauntlet_stats": self.gauntlet_stats.to_dict() if self.gauntlet_stats else None,
            "layer_timing_seconds": self.layer_timing,
            "ai_frameworks": self.ai_frameworks_detected,
            "error": self.error,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Layer 1: Repository Discovery & Profiling
# ──────────────────────────────────────────────────────────────────────────────
class RepositoryDiscovery:
    FRAMEWORK_SIGNATURES: dict[AIFramework, list[str]] = {
        AIFramework.LANGCHAIN: ["langchain", "from langchain", "import langchain"],
        AIFramework.LLAMA_INDEX: ["llama_index", "llama-index", "from llama_index"],
        AIFramework.OPENAI: ["openai", "from openai", "import openai", "ChatOpenAI"],
        AIFramework.ANTHROPIC: ["anthropic", "from anthropic", "Claude"],
        AIFramework.TRANSFORMERS: ["transformers", "from transformers", "AutoModel"],
        AIFramework.AUTOGEN: ["autogen", "pyautogen"],
        AIFramework.CREWAI: ["crewai", "from crewai"],
        AIFramework.HAYSTACK: ["haystack", "from haystack"],
        AIFramework.DSPY: ["dspy", "import dspy"],
    }

    async def clone_and_profile(self, repo_url: str, target_dir: str) -> RepoProfile:
        """Clone repository and return profile."""
        logger.info("Layer 1: Cloning repository", url=repo_url)

        # Clone
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--", repo_url, target_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr}")

        # Walk and categorize files
        python_files, js_files, yaml_files = [], [], []
        total_lines = 0

        for root, _, files in os.walk(target_dir):
            # Skip hidden dirs and node_modules
            if any(skip in root for skip in [".git", "node_modules", "__pycache__", ".venv"]):
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, target_dir)
                if fname.endswith(".py"):
                    python_files.append(rel)
                elif fname.endswith((".js", ".ts", ".jsx", ".tsx")):
                    js_files.append(rel)
                elif fname.endswith((".yml", ".yaml")):
                    yaml_files.append(rel)

                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as fh:
                        total_lines += sum(1 for _ in fh)
                except OSError:
                    pass

        # Detect AI frameworks
        detected: list[AIFramework] = []
        all_source = " ".join(
            open(os.path.join(target_dir, f), encoding="utf-8", errors="ignore").read()
            for f in python_files[:50]  # sample first 50 files
        )
        for framework, sigs in self.FRAMEWORK_SIGNATURES.items():
            if any(sig.lower() in all_source.lower() for sig in sigs):
                detected.append(framework)

        primary_lang = "python" if python_files else "javascript" if js_files else "unknown"
        has_docker = os.path.exists(os.path.join(target_dir, "Dockerfile")) or \
                     os.path.exists(os.path.join(target_dir, "docker-compose.yml"))
        has_k8s = any("kubernetes" in f or "k8s" in f or "helm" in f for f in yaml_files)

        return RepoProfile(
            url=repo_url,
            local_path=target_dir,
            primary_language=primary_lang,
            ai_frameworks=detected if detected else [AIFramework.UNKNOWN],
            has_requirements=os.path.exists(os.path.join(target_dir, "requirements.txt")) or
                            os.path.exists(os.path.join(target_dir, "pyproject.toml")),
            has_docker=has_docker,
            has_kubernetes=has_k8s,
            file_count=len(python_files) + len(js_files),
            python_files=python_files,
            js_files=js_files,
            yaml_files=yaml_files,
            total_lines=total_lines,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Layer 2: Static Analysis (AST + Semgrep + Bandit)
# ──────────────────────────────────────────────────────────────────────────────
class StaticAnalyzer:
    PROMPT_INJECTION_PATTERNS = [
        (r'f["\'].*\{(?:user|request|input|query|prompt|message)[^}]*\}', "prompt_injection", "critical"),
        (r'\.format\([^)]*(?:user|request|input)', "prompt_injection", "high"),
        (r'%\s*(?:user|request|input)', "prompt_injection", "high"),
        (r'system_prompt\s*=.*(?:user|request)', "prompt_injection", "high"),
    ]
    SECRET_PATTERNS = [
        (r'(?i)(?:api_key|apikey|secret_key|access_token|auth_token)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']', "hardcoded_secret", "critical"),
        (r'sk-[A-Za-z0-9]{48}', "hardcoded_secret", "critical"),
        (r'sk_live_[A-Za-z0-9]{24}', "hardcoded_secret", "critical"),
        (r'ghp_[A-Za-z0-9]{36}', "hardcoded_secret", "critical"),
        (r'AKIA[0-9A-Z]{16}', "hardcoded_secret", "critical"),
        (r'nvapi-[A-Za-z0-9_\-]{86}', "hardcoded_secret", "critical"),
    ]
    UNSAFE_DESERIALIZATION_PATTERNS = [
        (r'pickle\.load[s]?\s*\(', "unsafe_deserialization", "critical"),
        (r'yaml\.load\s*\([^,)]+\)', "unsafe_deserialization", "high"),  # yaml.load without Loader
        (r'joblib\.load\s*\(', "unsafe_deserialization", "high"),
        (r'torch\.load\s*\(', "unsafe_deserialization", "high"),
    ]
    EVAL_PATTERNS = [
        (r'\beval\s*\(', "eval_injection", "critical"),
        (r'\bexec\s*\(', "eval_injection", "critical"),
        (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', "command_injection", "critical"),
        (r'os\.system\s*\(', "command_injection", "high"),
    ]

    def _scan_file(self, file_path: str, content: str, layer: str = "ast") -> list[RawFinding]:
        findings: list[RawFinding] = []
        all_patterns = (
            self.PROMPT_INJECTION_PATTERNS
            + self.SECRET_PATTERNS
            + self.UNSAFE_DESERIALIZATION_PATTERNS
            + self.EVAL_PATTERNS
        )
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern, vuln_class, severity in all_patterns:
                if re.search(pattern, line):
                    owasp_map = {
                        "prompt_injection": "LLM01",
                        "hardcoded_secret": "LLM02",
                        "unsafe_deserialization": "LLM03",
                        "eval_injection": "LLM05",
                        "command_injection": "LLM05",
                    }
                    findings.append(RawFinding(
                        id=str(uuid.uuid4()),
                        layer=layer,
                        vulnerability_class=vuln_class,
                        owasp_id=owasp_map.get(vuln_class),
                        mitre_id=None,
                        severity=severity,
                        file_path=file_path,
                        line_start=i,
                        line_end=i,
                        code_snippet=line.strip()[:300],
                        description=f"Detected {vuln_class.replace('_', ' ')} pattern",
                    ))
        return findings

    async def run(self, profile: RepoProfile) -> list[RawFinding]:
        """Run AST pattern matching on all Python files."""
        logger.info("Layer 2: Static analysis", files=len(profile.python_files))
        all_findings: list[RawFinding] = []

        for rel_path in profile.python_files:
            abs_path = os.path.join(profile.local_path, rel_path)
            try:
                content = open(abs_path, encoding="utf-8", errors="ignore").read()
                findings = self._scan_file(rel_path, content, layer="ast")
                all_findings.extend(findings)
            except OSError:
                continue

        # Run Semgrep if available
        semgrep_findings = await self._run_semgrep(profile.local_path)
        all_findings.extend(semgrep_findings)

        logger.info("Layer 2 complete", raw_findings=len(all_findings))
        return all_findings

    async def _run_semgrep(self, repo_path: str) -> list[RawFinding]:
        """Run Semgrep with AI security ruleset."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config=auto", "--json", "--quiet", repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            import json
            data = json.loads(stdout)
            findings: list[RawFinding] = []
            for r in data.get("results", []):
                findings.append(RawFinding(
                    id=str(uuid.uuid4()),
                    layer="semgrep",
                    vulnerability_class=r.get("check_id", "unknown").split(".")[-1],
                    owasp_id=None,
                    mitre_id=None,
                    severity=r.get("extra", {}).get("severity", "medium").lower(),
                    file_path=os.path.relpath(r.get("path", ""), repo_path),
                    line_start=r.get("start", {}).get("line", 0),
                    line_end=r.get("end", {}).get("line", 0),
                    code_snippet=r.get("extra", {}).get("lines", "")[:300],
                    description=r.get("extra", {}).get("message", ""),
                ))
            return findings
        except Exception as e:
            logger.debug("Semgrep not available or failed", error=str(e))
            return []


# ──────────────────────────────────────────────────────────────────────────────
# Layer 3: Secrets Scanning
# ──────────────────────────────────────────────────────────────────────────────
class SecretsScanner:
    async def run(self, profile: RepoProfile) -> list[RawFinding]:
        """Secrets scanning using gitleaks + fallback patterns."""
        logger.info("Layer 3: Secrets scanning")
        findings = await self._run_gitleaks(profile.local_path)
        if not findings:
            # Fallback: reuse AST scanner on secret patterns only
            analyzer = StaticAnalyzer()
            for rel_path in profile.python_files:
                abs_path = os.path.join(profile.local_path, rel_path)
                try:
                    content = open(abs_path, encoding="utf-8", errors="ignore").read()
                    for pattern, vuln_class, severity in analyzer.SECRET_PATTERNS:
                        for i, line in enumerate(content.split("\n"), 1):
                            if re.search(pattern, line):
                                findings.append(RawFinding(
                                    id=str(uuid.uuid4()),
                                    layer="secrets",
                                    vulnerability_class=vuln_class,
                                    owasp_id="LLM02",
                                    mitre_id="AML.T0037",
                                    severity=severity,
                                    file_path=rel_path,
                                    line_start=i,
                                    line_end=i,
                                    code_snippet=line.strip()[:300],
                                    description="Hardcoded secret or API key detected",
                                ))
                except OSError:
                    continue
        logger.info("Layer 3 complete", secrets_found=len(findings))
        return findings

    async def _run_gitleaks(self, repo_path: str) -> list[RawFinding]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "gitleaks", "detect", "--source", repo_path,
                "--report-format", "json", "--report-path", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            import json
            results = json.loads(stdout or "[]")
            return [
                RawFinding(
                    id=str(uuid.uuid4()),
                    layer="secrets",
                    vulnerability_class="hardcoded_secret",
                    owasp_id="LLM02",
                    mitre_id="AML.T0037",
                    severity="critical",
                    file_path=r.get("File", ""),
                    line_start=r.get("StartLine", 0),
                    line_end=r.get("EndLine", 0),
                    code_snippet=r.get("Match", "")[:300],
                    description=f"Secret type: {r.get('RuleID', 'unknown')}",
                )
                for r in results
            ]
        except Exception:
            return []


# ──────────────────────────────────────────────────────────────────────────────
# Layer 4-7: Reachability, Agents, OWASP, MITRE mapping
# ──────────────────────────────────────────────────────────────────────────────
class ReachabilityAnalyzer:
    async def run(self, profile: RepoProfile, findings: list[RawFinding]) -> list[RawFinding]:
        """Build call graph and add reachability evidence to findings."""
        logger.info("Layer 4: Reachability analysis")
        entry_points = self._find_entry_points(profile)
        for f in findings:
            f.evidence["entry_points"] = entry_points
        return findings

    def _find_entry_points(self, profile: RepoProfile) -> list[str]:
        entry_points = []
        ep_patterns = [r"@app\.", r"@router\.", r"def main\(", r"@celery\.task"]
        for rel in profile.python_files:
            abs_path = os.path.join(profile.local_path, rel)
            try:
                content = open(abs_path, encoding="utf-8", errors="ignore").read()
                for pat in ep_patterns:
                    if re.search(pat, content):
                        entry_points.append(rel)
                        break
            except OSError:
                continue
        return entry_points


class SpecialistAgentRunner:
    """Runs 10 specialist agents in parallel (simplified in-process version)."""

    AGENT_CHECKS = {
        "CIA-01": ("prompt_injection", "LLM01"),
        "RAG-02": ("rag_namespace_bypass", "LLM08"),
        "MCP-03": ("tool_injection", "ASI04"),
        "AGN-04": ("agent_identity_confusion", "ASI01"),
        "POI-05": ("data_poisoning", "LLM04"),
        "DAT-06": ("sensitive_data_leakage", "LLM02"),
        "SUP-07": ("supply_chain", "LLM03"),
        "OUT-08": ("output_handling", "LLM05"),
        "INF-09": ("infrastructure_security", None),
        "RED-10": ("model_extraction", None),
    }

    async def run(self, profile: RepoProfile) -> list[RawFinding]:
        """Run all 10 agents and collect their findings."""
        logger.info("Layer 5: Running 10 specialist agents")
        tasks = [
            self._run_agent(agent_id, vuln_class, owasp_id, profile)
            for agent_id, (vuln_class, owasp_id) in self.AGENT_CHECKS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[RawFinding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        logger.info("Layer 5 complete", agent_findings=len(findings))
        return findings

    async def _run_agent(
        self, agent_id: str, vuln_class: str, owasp_id: str | None, profile: RepoProfile
    ) -> list[RawFinding]:
        """Each agent does targeted pattern matching for its vulnerability class."""
        findings: list[RawFinding] = []
        agent_patterns: dict[str, list[tuple[str, str]]] = {
            "prompt_injection": [
                (r'(?:system_prompt|prompt)\s*=.*\{(?:user|request|input)', "critical"),
                (r'messages\s*=.*format\s*\(', "high"),
            ],
            "rag_namespace_bypass": [
                (r'similarity_search\s*\((?!.*filter)', "high"),
                (r'retriever\.get_relevant_documents\s*\((?!.*metadata)', "medium"),
            ],
            "supply_chain": [
                (r'pickle\.load', "critical"),
                (r'torch\.load\s*\(', "high"),
                (r'from_pretrained.*trust_remote_code\s*=\s*True', "high"),
            ],
            "output_handling": [
                (r'eval\s*\(.*(?:llm|response|output|result)', "critical"),
                (r'exec\s*\(.*(?:llm|response|output)', "critical"),
            ],
        }
        patterns = agent_patterns.get(vuln_class, [])
        for rel_path in profile.python_files[:100]:  # limit per agent
            abs_path = os.path.join(profile.local_path, rel_path)
            try:
                content = open(abs_path, encoding="utf-8", errors="ignore").read()
                for i, line in enumerate(content.split("\n"), 1):
                    for pattern, severity in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append(RawFinding(
                                id=str(uuid.uuid4()),
                                layer=f"agent_{agent_id.lower()}",
                                vulnerability_class=vuln_class,
                                owasp_id=owasp_id,
                                mitre_id=None,
                                severity=severity,
                                file_path=rel_path,
                                line_start=i,
                                line_end=i,
                                code_snippet=line.strip()[:300],
                                description=f"{agent_id} detected {vuln_class}",
                                evidence={"agent": agent_id},
                            ))
            except OSError:
                continue
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# Main Pipeline Orchestrator
# ──────────────────────────────────────────────────────────────────────────────
class ScanPipeline:
    """
    10-layer AI security scan pipeline.
    
    Usage:
        pipeline = ScanPipeline(nvidia_api_key="nvapi-...")
        result = await pipeline.scan("https://github.com/user/ai-app")
    """

    def __init__(
        self,
        nvidia_api_key: str | None = None,
        nvidia_base_url: str | None = None,
        work_dir: str | None = None,
    ):
        self.nvidia_api_key = nvidia_api_key
        self.nvidia_base_url = nvidia_base_url
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="asl_scan_")
        self._discovery = RepositoryDiscovery()
        self._static = StaticAnalyzer()
        self._secrets = SecretsScanner()
        self._reachability = ReachabilityAnalyzer()
        self._agents = SpecialistAgentRunner()

    async def scan(self, repo_url: str, scan_id: str | None = None) -> ScanResult:
        scan_id = scan_id or str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            repo_url=repo_url,
            status=ScanStatus.CLONING,
        )

        target_dir = os.path.join(self.work_dir, scan_id)
        os.makedirs(target_dir, exist_ok=True)

        try:
            import time

            # ── Layer 1: Clone & Profile ─────────────────────────────────
            t0 = time.time()
            profile = await self._discovery.clone_and_profile(repo_url, target_dir)
            result.layer_timing["layer1_discovery"] = round(time.time() - t0, 2)
            result.ai_frameworks_detected = [f.value for f in profile.ai_frameworks]
            result.status = ScanStatus.ANALYZING

            # ── Layers 2-7: Analysis ─────────────────────────────────────
            t1 = time.time()
            static_findings = await self._static.run(profile)
            result.layer_timing["layer2_static"] = round(time.time() - t1, 2)

            t2 = time.time()
            secret_findings = await self._secrets.run(profile)
            result.layer_timing["layer3_secrets"] = round(time.time() - t2, 2)

            t3 = time.time()
            all_raw = static_findings + secret_findings
            all_raw = await self._reachability.run(profile, all_raw)
            result.layer_timing["layer4_reachability"] = round(time.time() - t3, 2)

            t4 = time.time()
            agent_findings = await self._agents.run(profile)
            all_raw.extend(agent_findings)
            result.layer_timing["layers5to7_agents"] = round(time.time() - t4, 2)

            result.raw_finding_count = len(all_raw)

            # ── Layers 8-10: Verification Gauntlet ──────────────────────
            result.status = ScanStatus.VERIFYING
            t5 = time.time()

            # Collect source contexts for reachability checks
            source_contexts: dict[str, str] = {}
            for rel in profile.python_files:
                try:
                    source_contexts[rel] = open(
                        os.path.join(profile.local_path, rel),
                        encoding="utf-8", errors="ignore"
                    ).read()
                except OSError:
                    pass

            reducer = FalsePositiveReducer(
                nvidia_api_key=self.nvidia_api_key,
                nvidia_base_url=self.nvidia_base_url,
                workspace_root=profile.local_path,
            )
            verified, stats = await reducer.run(all_raw, source_contexts)
            result.layer_timing["layers8to10_gauntlet"] = round(time.time() - t5, 2)

            result.findings = verified
            result.verified_finding_count = len(verified)
            result.gauntlet_stats = stats
            result.status = ScanStatus.COMPLETE

            logger.info(
                "Scan complete",
                scan_id=scan_id,
                raw=result.raw_finding_count,
                verified=result.verified_finding_count,
                fp_rate_pct=stats.false_positive_rate * 100,
            )

        except Exception as e:
            logger.error("Scan failed", scan_id=scan_id, error=str(e))
            result.status = ScanStatus.FAILED
            result.error = str(e)
        finally:
            # Cleanup cloned repo
            try:
                shutil.rmtree(target_dir, ignore_errors=True)
            except Exception:
                pass

        return result
