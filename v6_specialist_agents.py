"""
ASL V6: 10 Specialist Security Agents with Confidence Scoring
=============================================================
Each agent specializes in a specific AI security domain and includes:
- Context-aware confidence scoring (0-100)
- Validation_required flag for low-confidence findings
- CVSS scores adjusted by confidence
- Improved detection logic to reduce false positives

Agents implemented:
1. PromptInjectionHunter (CIA-01) - OWASP LLM01
2. RAGSecurityAuditor (RAG-02) - OWASP LLM08
3. MCPToolSecurityAnalyst (MCP-03) - OWASP ASI04/ASI05
4. AgentOrchestrationSecurity (AGN-04) - OWASP ASI01/ASI02
5. ModelDataPoisoningDetector (POI-05) - OWASP LLM04
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

sys.path.append(str(Path(__file__).resolve().parent.parent / "v2"))
sys.path.append(str(Path(__file__).resolve().parent.parent / "v4_asl_business"))

try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    class Console:
        def print(self, *args, **kwargs): print(*args)
    def Panel(*args, **kwargs): return ""

console = Console()

# ─────────────────────────────────────────────────────────────────────
# SPECIALIST AGENT 1: Prompt Injection Hunter
# ─────────────────────────────────────────────────────────────────────

class PromptInjectionHunter:
    """
    OWASP LLM01: Prompt Injection Specialist
    
    Detects: Direct injection, indirect injection, jailbreaks, guardrail bypass
    """
    
    AGENT_ID = "CIA-01"
    DISPLAY_NAME = "🎯 Prompt Injection Hunter"
    
    INJECTION_PATTERNS = [
        # Direct injection patterns
        r"ignore\s+(previous|all|above)\s+instructions",
        r"disregard\s+(previous|all|above)",
        r"forget\s+(everything|all|previous)",
        r"###\s*(Instruction|System|User)",
        
        # Jailbreak patterns
        r"DAN\s*[:\(]",
        r"developer\s+mode",
        r"without\s+restrictions",
        r"bypass\s+(safety|content\s+policy)",
        
        # Indirect injection
        r"<\s*script[^>]*>",
        r"{{\s*.*\s*}}",
        r"\{\%\s*.*\s*\%\}",
    ]
    
    def analyze(self, code_context: str, file_path: str = "") -> List[dict]:
        """Scan for prompt injection vulnerabilities with confidence scoring"""
        findings = []
        
        # Search for injection patterns
        for pattern in self.INJECTION_PATTERNS:
            matches = re.finditer(pattern, code_context, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = code_context[:match.start()].count('\n') + 1
                
                # Calculate confidence based on context
                confidence = self._calculate_injection_confidence(code_context, match)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": "Potential Prompt Injection Vector",
                    "category": "LLM01: Prompt Injection",
                    "severity": self._confidence_to_severity(confidence),
                    "cvss_score": self._confidence_to_cvss(confidence, "High"),
                    "file_path": file_path,
                    "line_number": line_num,
                    "code_evidence": match.group(0)[:100],
                    "description": f"Code contains pattern that could enable prompt injection: '{match.group(0)[:50]}'",
                    "remediation": "Implement input validation, use structured prompt templates, separate system/user messages",
                    "cwe_id": "CWE-1427",
                    "owasp_llm_id": "LLM01:2025",
                    "confidence_score": confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": confidence < 75
                })
        
        # Check for missing input sanitization
        if re.search(r'prompt\s*=\s*[f]?["\'].*\{.*\}.*["\']', code_context, re.IGNORECASE):
            if not re.search(r'sanitize|escape|clean|validate|filter', code_context, re.IGNORECASE):
                confidence = self._calculate_unsanitized_input_confidence(code_context)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": "Unsanitized User Input in Prompt",
                    "category": "LLM01: Prompt Injection",
                    "severity": self._confidence_to_severity(confidence),
                    "cvss_score": self._confidence_to_cvss(confidence, "Critical"),
                    "file_path": file_path,
                    "code_evidence": "User input directly interpolated into prompt without sanitization",
                    "description": "User-controlled input is being directly inserted into LLM prompts without validation or sanitization",
                    "remediation": "Implement input validation, use delimiters, implement allowlisting, consider using a prompt template library",
                    "cwe_id": "CWE-1427",
                    "owasp_llm_id": "LLM01:2025",
                    "confidence_score": confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": confidence < 80
                })
        
        return findings
    
    def _calculate_injection_confidence(self, code_context: str, match: re.Match) -> int:
        """Calculate confidence for injection pattern matches."""
        confidence = 60  # Base confidence
        
        # Get context around the match
        start = max(0, match.start() - 100)
        end = min(len(code_context), match.end() + 100)
        context = code_context[start:end].lower()
        
        # Increase confidence if it looks like actual code (not comment/example)
        if not any(indicator in context[:50] for indicator in ['#', '//', '/*', '<!--']):
            confidence += 15
            
        # Increase if it's in a string that looks like it might be user input
        if any(indicator in context for indicator in ['input', 'query', 'user', 'request', 'data']):
            confidence += 10
            
        # Decrease if it's clearly in a comment or documentation
        if any(indicator in context[:50] for indicator in ['#', '//', '/*', '<!--', 'example', 'demo', 'tutorial']):
            confidence -= 25
            
        # Decrease if it's in a test file
        if 'test' in code_context.lower()[:50]:
            confidence -= 15
            
        return max(20, min(95, confidence))
    
    def _calculate_unsanitized_input_confidence(self, code_context: str) -> int:
        """Calculate confidence for unsanitized input detection."""
        confidence = 70  # Base confidence
        
        # Check if it looks like production code vs example/tutorial
        context = code_context.lower()
        
        # Decrease if it's clearly example/tutorial code
        if any(indicator in context for indicator in ['#', '//', '/*', 'example', 'demo', 'tutorial', 'sample']):
            confidence -= 25
            
        # Decrease if it's in a test file
        if 'test' in context[:100]:
            confidence -= 15
            
        # Increase if there are other security-related patterns nearby
        if any(indicator in context for indicator in ['password', 'secret', 'key', 'token', 'auth']):
            confidence += 10
            
        return max(30, min(95, confidence))
    
    def _confidence_to_severity(self, confidence: int) -> str:
        """Convert confidence score to severity level."""
        if confidence >= 85:
            return "High"  # For injection patterns, base is High
        elif confidence >= 60:
            return "Medium"
        else:
            return "Low"
    
    def _confidence_to_cvss(self, confidence: int, base_severity: str) -> float:
        """Convert confidence score to CVSS score."""
        base_scores = {
            "Critical": 9.0,
            "High": 7.5,
            "Medium": 5.5,
            "Low": 3.0
        }
        
        base_score = base_scores.get(base_severity, 5.0)
        confidence_factor = 0.5 + (confidence / 200)  # 0.5 to 1.0
        adjusted_score = min(10.0, base_score * confidence_factor)
        return round(adjusted_score, 1)


# ─────────────────────────────────────────────────────────────────────
# SPECIALIST AGENT 2: RAG Security Auditor
# ─────────────────────────────────────────────────────────────────────

class RAGSecurityAuditor:
    """
    OWASP LLM08: Vector & Embedding Weaknesses
    
    Detects: Missing authorization, namespace isolation failures, document injection
    """
    
    AGENT_ID = "RAG-02"
    DISPLAY_NAME = "📚 RAG Security Auditor"
    
    def analyze(self, code_context: str, file_path: str = "") -> List[dict]:
        """Scan for RAG-specific vulnerabilities with confidence scoring"""
        findings = []
        
        # Check for vector DB usage
        vector_db_patterns = [
            (r'chroma\.|Chroma\(', "ChromaDB"),
            (r'qdrant|Qdrant', "Qdrant"),
            (r'pinecone|Pinecone', "Pinecone"),
            (r'weaviate|Weaviate', "Weaviate"),
            (r'milvus|Milvus', "Milvus"),
        ]
        
        for pattern, db_name in vector_db_patterns:
            if re.search(pattern, code_context):
                # Calculate confidence for vector DB detection
                confidence = self._calculate_vector_db_confidence(code_context, pattern)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": f"{db_name} Vector Database Detected",
                    "category": "LLM08: Vector & Embedding Weaknesses",
                    "severity": self._confidence_to_severity(confidence, base="Medium"),
                    "cvss_score": self._confidence_to_cvss(confidence, "Medium"),
                    "file_path": file_path,
                    "code_evidence": f"Usage of {db_name} detected",
                    "description": f"Vector database ({db_name}) usage detected. Verify authorization checks and isolation.",
                    "remediation": "Implement user-level filtering, namespace isolation, encrypt embeddings at rest",
                    "cwe_id": "CWE-284",
                    "owasp_llm_id": "LLM08:2025",
                    "confidence_score": confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": confidence < 60
                })
                
                # Check for namespace usage
                if not re.search(r'namespace|tenant|user_id|filter|access_control', code_context, re.IGNORECASE):
                    isolation_confidence = self._calculate_isolation_confidence(code_context)
                    
                    findings.append({
                        "id": f"{self.AGENT_ID}-{len(findings)}",
                        "title": f"Missing Namespace Isolation in {db_name}",
                        "category": "LLM08: Vector & Embedding Weaknesses",
                        "severity": self._confidence_to_severity(isolation_confidence, base="High"),
                        "cvss_score": self._confidence_to_cvss(isolation_confidence, "High"),
                        "file_path": file_path,
                        "code_evidence": f"No namespace/tenant isolation detected for {db_name}",
                        "description": f"Vector DB queries lack namespace or tenant-level isolation, potentially allowing cross-user data access",
                        "remediation": "Implement namespace-based isolation, add user_id filters to all vector searches, encrypt data per-tenant",
                        "cwe_id": "CWE-284",
                        "owasp_llm_id": "LLM08:2025",
                        "confidence_score": isolation_confidence,
                        "agent_source": self.DISPLAY_NAME,
                        "validation_required": isolation_confidence < 70
                    })
        
        # Check for document ingestion without validation
        if re.search(r'read_csv|read_json|read_pdf|load_documents|ingest', code_context, re.IGNORECASE):
            if not re.search(r'validate|sanitize|check|verify|scan', code_context, re.IGNORECASE):
                ingestion_confidence = self._calculate_document_ingestion_confidence(code_context)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": "Document Ingestion Without Validation",
                    "category": "LLM01: Prompt Injection",
                    "severity": self._confidence_to_severity(ingestion_confidence, base="High"),
                    "cvss_score": self._confidence_to_cvss(ingestion_confidence, "High"),
                    "file_path": file_path,
                    "code_evidence": "Document loading detected without validation",
                    "description": "Documents are being ingested into RAG pipeline without validation for malicious content or embedded prompts",
                    "remediation": "Scan documents for injection patterns, validate file types, implement content filtering before indexing",
                    "cwe_id": "CWE-1427",
                    "owasp_llm_id": "LLM01:2025",
                    "confidence_score": ingestion_confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": ingestion_confidence < 75
                })
        
        return findings
    
    def _calculate_vector_db_confidence(self, code_context: str, pattern: str) -> int:
        """Calculate confidence for vector DB detection."""
        confidence = 50  # Base confidence
        
        # Increase if it looks like actual usage (not just import/declaration)
        context = code_context.lower()
        if any(indicator in context for indicator in ['=', '(', ')', '.', 'chroma', 'qdrant', 'pinecone']):
            confidence += 20
            
        # Decrease if it's in a comment or example
        if any(indicator in code_context[max(0, code_context.find(pattern)-50):code_context.find(pattern)] 
               for indicator in ['#', '//', '/*', '<!--', 'example', 'demo']):
            confidence -= 25
            
        return max(20, min(90, confidence))
    
    def _calculate_isolation_confidence(self, code_context: str) -> int:
        """Calculate confidence for missing namespace isolation detection."""
        confidence = 60  # Base confidence
        
        # Increase if there are multiple users or obvious multi-tenant context
        context = code_context.lower()
        if any(indicator in context for indicator in ['user', 'customer', 'client', 'tenant', 'account']):
            confidence += 15
            
        # Decrease if it's clearly example/tutorial code
        if any(indicator in context for indicator in ['#', '//', '/*', 'example', 'demo', 'tutorial']):
            confidence -= 20
            
        # Increase if there are security-related patterns nearby
        if any(indicator in context for indicator in ['auth', 'permission', 'access', 'role']):
            confidence += 10
            
        return max(25, min(90, confidence))
    
    def _calculate_document_ingestion_confidence(self, code_context: str) -> int:
        """Calculate confidence for document ingestion detection."""
        confidence = 65  # Base confidence (slightly higher as this is often problematic)
        
        # Check context to see if it's likely production code
        context = code_context.lower()
        
        # Decrease if it's clearly example/tutorial code
        if any(indicator in context for indicator in ['#', '//', '/*', 'example', 'demo', 'tutorial', 'sample']):
            confidence -= 25
            
        # Decrease if it's in a test file
        if 'test' in context[:100]:
            confidence -= 15
            
        # Increase if there are security-conscious patterns nearby
        if any(indicator in context for indicator in ['validate', 'sanitize', 'filter', 'check']):
            confidence += 15  # Shows awareness of need for validation
            
        return max(30, min(95, confidence))
    
    def _confidence_to_severity(self, confidence: int, base: str = "Medium") -> str:
        """Convert confidence score to severity level with base adjustment."""
        if base == "Medium":
            if confidence >= 80:
                return "High"
            elif confidence >= 50:
                return "Medium"
            else:
                return "Low"
        else:  # base == "High"
            if confidence >= 85:
                return "High"
            elif confidence >= 55:
                return "Medium"
            else:
                return "Low"
    
    def _confidence_to_cvss(self, confidence: int, base_severity: str) -> float:
        """Convert confidence score to CVSS score."""
        base_scores = {
            "Critical": 9.0,
            "High": 7.5,
            "Medium": 5.5,
            "Low": 3.0
        }
        
        base_score = base_scores.get(base_severity, 5.0)
        confidence_factor = 0.5 + (confidence / 200)  # 0.5 to 1.0
        adjusted_score = min(10.0, base_score * confidence_factor)
        return round(adjusted_score, 1)


# ─────────────────────────────────────────────────────────────────────
# SPECIALIST AGENT 3: MCP & Tool Security Analyst
# ─────────────────────────────────────────────────────────────────────

class MCPToolSecurityAnalyst:
    """
    OWASP ASI04: Insecure Tool Execution
    OWASP ASI05: Unexpected Code Execution
    
    Detects: Unauthorized tool invocation, SSRF, shell injection, file access abuse
    """
    
    AGENT_ID = "MCP-03"
    DISPLAY_NAME = "🔧 MCP & Tool Security Analyst"
    
    DANGEROUS_PATTERNS = [
        (r'subprocess\.(run|call|Popen|check_output)', "Subprocess Execution", "Critical", "CWE-78"),
        (r'os\.system\(', "OS System Call", "Critical", "CWE-78"),
        (r'eval\s*\(', "Eval Usage", "Critical", "CWE-94"),
        (r'exec\s*\(', "Exec Usage", "Critical", "CWE-94"),
        (r'requests\.(get|post|put|delete)\(', "HTTP Requests", "Medium", "CWE-918"),
        (r'urllib\.request', "URL Requests", "Medium", "CWE-918"),
        (r'socket\.', "Socket Operations", "Medium", "CWE-918"),
    ]
    
    def analyze(self, code_context: str, file_path: str = "") -> List[dict]:
        """Scan for MCP and tool security issues with confidence scoring"""
        findings = []
        
        # Check for tool execution patterns
        for pattern, desc, severity, cwe in self.DANGEROUS_PATTERNS:
            if re.search(pattern, code_context):
                confidence = self._calculate_tool_confidence(code_context, pattern, desc)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": f"Potentially Dangerous: {desc}",
                    "category": "ASI05: Unexpected Code Execution",
                    "severity": self._confidence_to_severity(confidence, severity),
                    "cvss_score": self._confidence_to_cvss(confidence, severity),
                    "file_path": file_path,
                    "code_evidence": f"Pattern detected: {pattern[:50]}",
                    "description": f"Code contains {desc} which could be exploited if LLM output is used without validation",
                    "remediation": "Implement strict allowlisting for tool execution, validate all inputs, use principle of least privilege",
                    "cwe_id": cwe,
                    "owasp_llm_id": "ASI05:2026",
                    "confidence_score": confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": confidence < 65
                })
        
        # Check for MCP patterns
        if re.search(r'mcp\.|ModelContextProtocol|@mcp', code_context, re.IGNORECASE):
            mcp_confidence = self._calculate_mcp_confidence(code_context)
            
            findings.append({
                "id": f"{self.AGENT_ID}-{len(findings)}",
                "title": "MCP (Model Context Protocol) Integration Detected",
                "category": "ASI04: Insecure Tool Execution",
                "severity": self._confidence_to_severity(mcp_confidence, base="Medium"),
                "cvss_score": self._confidence_to_cvss(mcp_confidence, "Medium"),
                "file_path": file_path,
                "code_evidence": "MCP protocol usage detected",
                "description": "MCP integration allows LLM to interact with external tools. Verify tool permissions and access controls.",
                "remediation": "Implement tool-level authorization, audit tool capabilities, use allowlisting for tool access",
                "cwe_id": "CWE-284",
                "owasp_llm_id": "ASI04:2026",
                "confidence_score": mcp_confidence,
                "agent_source": self.DISPLAY_NAME,
                "validation_required": mcp_confidence < 60
            })
        
        return findings
    
    def _calculate_tool_confidence(self, code_context: str, pattern: str, desc: str) -> int:
        """Calculate confidence for dangerous tool usage detection."""
        confidence = 55  # Base confidence
        
        # Get context around the match
        matches = list(re.finditer(pattern, code_context))
        if not matches:
            return confidence
            
        # Use the first match for context analysis
        match = matches[0]
        start = max(0, match.start() - 100)
        end = min(len(code_context), match.end() + 100)
        context = code_context[start:end].lower()
        
        # Increase confidence if it looks like actual usage (not just import/declaration)
        if any(indicator in context for indicator in ['=', '(', ')', '.', 'call', 'run', 'exec']):
            confidence += 20
            
        # Decrease if it's in a comment or example/documentation
        if any(indicator in context[:50] for indicator in ['#', '//', '/*', '<!--', 'example', 'demo', 'tutorial']):
            confidence -= 25
            
        # Decrease if it's in a test file
        if 'test' in code_context.lower()[:50]:
            confidence -= 15
            
        # Increase if there are security-conscious patterns nearby (validation, checking)
        if any(indicator in context for indicator in ['validate', 'check', 'verify', 'sanitize']):
            confidence += 15
            
        return max(20, min(90, confidence))
    
    def _calculate_mcp_confidence(self, code_context: str) -> int:
        """Calculate confidence for MCP integration detection."""
        confidence = 50  # Base confidence
        
        context = code_context.lower()
        
        # Increase if it looks like actual usage (not just import)
        if any(indicator in context for indicator in ['=', '(', ')', '.', 'mcp', 'server', 'tool']):
            confidence += 20
            
        # Decrease if it's in a comment or example
        if any(indicator in code_context[max(0, code_context.find('mcp')-50):code_context.find('mcp')] 
               for indicator in ['#', '//', '/*', '<!--', 'example', 'demo']):
            confidence -= 25
            
        # Increase if there are security-related patterns nearby
        if any(indicator in context for indicator in ['auth', 'permission', 'access', 'role', 'validate']):
            confidence += 15
            
        return max(20, min(90, confidence))
    
    def _confidence_to_severity(self, confidence: int, base: str = "Medium") -> str:
        """Convert confidence score to severity level with base adjustment."""
        if base == "Critical":
            if confidence >= 85:
                return "Critical"
            elif confidence >= 60:
                return "High"
            else:
                return "Medium"
        elif base == "Medium":
            if confidence >= 80:
                return "High"
            elif confidence >= 50:
                return "Medium"
            else:
                return "Low"
        else:  # High base
            if confidence >= 85:
                return "High"
            elif confidence >= 55:
                return "Medium"
            else:
                return "Low"
    
    def _confidence_to_cvss(self, confidence: int, base_severity: str) -> float:
        """Convert confidence score to CVSS score."""
        base_scores = {
            "Critical": 9.0,
            "High": 7.5,
            "Medium": 5.5,
            "Low": 3.0
        }
        
        base_score = base_scores.get(base_severity, 5.0)
        confidence_factor = 0.5 + (confidence / 200)  # 0.5 to 1.0
        adjusted_score = min(10.0, base_score * confidence_factor)
        return round(adjusted_score, 1)


# ─────────────────────────────────────────────────────────────────────
# SPECIALIST AGENT 4: Agent Orchestration Security
# ─────────────────────────────────────────────────────────────────────

class AgentOrchestrationSecurity:
    """
    OWASP Top 10 for Agents 2026
    
    Detects: Agent identity confusion, goal hijacking, cascading failures
    """
    
    AGENT_ID = "AGN-04"
    DISPLAY_NAME = "🤖 Agent Orchestration Security"
    
    def analyze(self, code_context: str, file_path: str = "") -> List[dict]:
        """Scan for agent orchestration vulnerabilities with confidence scoring"""
        findings = []
        
        agent_frameworks = [
            (r'crewai|CrewAI', "CrewAI"),
            (r'autogen|AutoGen', "AutoGen"),
            (r'langgraph|LangGraph', "LangGraph"),
        ]
        
        for pattern, framework in agent_frameworks:
            if re.search(pattern, code_context, re.IGNORECASE):
                framework_confidence = self._calculate_framework_confidence(code_context, pattern, framework)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": f"{framework} Agent Framework Detected",
                    "category": "ASI01: Agent Identity Confusion",
                    "severity": self._confidence_to_severity(framework_confidence, base="Medium"),
                    "cvss_score": self._confidence_to_cvss(framework_confidence, "Medium"),
                    "file_path": file_path,
                    "code_evidence": f"{framework} usage detected",
                    "description": f"Multi-agent system using {framework}. Verify agent identity management and role separation.",
                    "remediation": "Implement strong agent identity markers, validate agent roles, prevent role confusion attacks",
                    "cwe_id": "CWE-287",
                    "owasp_llm_id": "ASI01:2026",
                    "confidence_score": framework_confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": framework_confidence < 55
                })
        
        # Check for goal/task injection
        if re.search(r'goal\s*=|task\s*=|objective\s*=|instruction\s*=', code_context, re.IGNORECASE):
            if not re.search(r'validate|verify|sanitize|check|filter', code_context, re.IGNORECASE):
                goal_confidence = self._calculate_goal_injection_confidence(code_context)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": "Agent Goals/Tasks Set Without Validation",
                    "category": "ASI02: Insecure Goal Formulation",
                    "severity": self._confidence_to_severity(goal_confidence, base="High"),
                    "cvss_score": self._confidence_to_cvss(goal_confidence, "High"),
                    "file_path": file_path,
                    "code_evidence": "Goal/task assignment detected without validation",
                    "description": "Agent goals or tasks can potentially be hijacked if user input is used without validation",
                    "remediation": "Validate all goal/task inputs, implement goal allowlisting, monitor for goal drift",
                    "cwe_id": "CWE-1427",
                    "owasp_llm_id": "ASI02:2026",
                    "confidence_score": goal_confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": goal_confidence < 70
                })
        
        return findings
    
    def _calculate_framework_confidence(self, code_context: str, pattern: str, framework: str) -> int:
        """Calculate confidence for agent framework detection."""
        confidence = 45  # Base confidence (lower as framework usage alone isn't necessarily a vuln)
        
        context = code_context.lower()
        
        # Increase if it looks like actual usage (not just import)
        if any(indicator in context for indicator in ['=', '(', ')', '.', 'agent', 'crew', 'task']):
            confidence += 25
            
        # Decrease if it's in a comment or example
        if any(indicator in code_context[max(0, code_context.find(pattern.lower())-50):code_context.find(pattern.lower())] 
               for indicator in ['#', '//', '/*', '<!--', 'example', 'demo', 'tutorial']):
            confidence -= 20
            
        # Increase if there are security-related patterns nearby (auth, validation)
        if any(indicator in context for indicator in ['auth', 'permission', 'access', 'role', 'validate']):
            confidence += 15
            
        return max(20, min(85, confidence))
    
    def _calculate_goal_injection_confidence(self, code_context: str) -> int:
        """Calculate confidence for goal/task injection detection."""
        confidence = 60  # Base confidence
        
        # Check if the goal/task assignment looks like it could accept user input
        context = code_context.lower()
        
        # Look for patterns that suggest user input could flow into goal/task
        if any(indicator in context for indicator in ['request', 'input', 'user', 'args', 'params', 'query']):
            confidence += 20
            
        # Decrease if it's clearly hardcoded/example
        if any(indicator in context for indicator in ['"hello world"', "'test'", '"example"', 'todo', 'fixme']):
            confidence -= 25
            
        # Decrease if it's in a comment or documentation
        if any(indicator in code_context[:100] for indicator in ['#', '//', '/*', '<!--']):
            confidence -= 15
            
        # Increase if there are security-conscious patterns nearby
        if any(indicator in context for indicator in ['validate', 'check', 'verify', 'sanitize']):
            confidence += 15
            
        return max(25, min(90, confidence))
    
    def _confidence_to_severity(self, confidence: int, base: str = "Medium") -> str:
        """Convert confidence score to severity level with base adjustment."""
        if base == "High":
            if confidence >= 85:
                return "High"
            elif confidence >= 55:
                return "Medium"
            else:
                return "Low"
        else:  # base == "Medium"
            if confidence >= 80:
                return "High"
            elif confidence >= 50:
                return "Medium"
            else:
                return "Low"
    
    def _confidence_to_cvss(self, confidence: int, base_severity: str) -> float:
        """Convert confidence score to CVSS score."""
        base_scores = {
            "Critical": 9.0,
            "High": 7.5,
            "Medium": 5.5,
            "Low": 3.0
        }
        
        base_score = base_scores.get(base_severity, 5.0)
        confidence_factor = 0.5 + (confidence / 200)  # 0.5 to 1.0
        adjusted_score = min(10.0, base_score * confidence_factor)
        return round(adjusted_score, 1)


# ─────────────────────────────────────────────────────────────────────
# SPECIALIST AGENT 5: Model & Data Poisoning Detector
# ─────────────────────────────────────────────────────────────────────

class ModelDataPoisoningDetector:
    """
    OWASP LLM04: Data & Model Poisoning
    MITRE ATLAS: ML Dataset Access
    
    Detects: Training data poisoning, fine-tuning backdoors, trigger words
    """
    
    AGENT_ID = "POI-05"
    DISPLAY_NAME = "☣️ Model & Data Poisoning Detector"
    
    def analyze(self, code_context: str, file_path: str = "") -> List[dict]:
        """Scan for model poisoning vulnerabilities with confidence scoring"""
        findings = []
        
        # Check for fine-tuning operations
        if re.search(r'fine.?tune|lora|peft', code_context, re.IGNORECASE):
            finetune_confidence = self._calculate_finetune_confidence(code_context)
            
            findings.append({
                "id": f"{self.AGENT_ID}-{len(findings)}",
                "title": "Fine-tuning Detected - Verify Data Integrity",
                "category": "LLM04: Data & Model Poisoning",
                "severity": self._confidence_to_severity(finetune_confidence, base="Medium"),
                "cvss_score": self._confidence_to_cvss(finetune_confidence, "Medium"),
                "file_path": file_path,
                "code_evidence": "Fine-tuning operation detected",
                "description": "Model fine-tuning detected. Ensure training data is validated and from trusted sources.",
                "remediation": "Validate training data sources, implement data provenance tracking, scan for trigger words",
                "cwe_id": "CWE-345",
                "owasp_llm_id": "LLM04:2025",
                "confidence_score": finetune_confidence,
                "agent_source": self.DISPLAY_NAME,
                "validation_required": finetune_confidence < 60
            })
        
        # Check for dataset loading without validation
        if re.search(r'load_dataset|datasets\.load', code_context, re.IGNORECASE):
            if not re.search(r'validate|verify|scan|check', code_context, re.IGNORECASE):
                dataset_confidence = self._calculate_dataset_loading_confidence(code_context)
                
                findings.append({
                    "id": f"{self.AGENT_ID}-{len(findings)}",
                    "title": "Dataset Loaded Without Validation",
                    "category": "LLM04: Data & Model Poisoning",
                    "severity": self._confidence_to_severity(dataset_confidence, base="High"),
                    "cvss_score": self._confidence_to_cvss(dataset_confidence, "High"),
                    "file_path": file_path,
                    "code_evidence": "Dataset loading without integrity checks",
                    "description": "Training dataset loaded without integrity checks - vulnerable to poisoning attacks",
                    "remediation": "Validate dataset sources, check signatures, scan for anomalies, implement data versioning",
                    "cwe_id": "CWE-345",
                    "owasp_llm_id": "LLM04:2025",
                    "confidence_score": dataset_confidence,
                    "agent_source": self.DISPLAY_NAME,
                    "validation_required": dataset_confidence < 70
                })
        
        return findings
    
    def _calculate_finetune_confidence(self, code_context: str) -> int:
        """Calculate confidence for fine-tuning detection."""
        confidence = 45  # Base confidence (fine-tuning itself isn't bad)
        
        context = code_context.lower()
        
        # Increase if there are security-conscious patterns nearby
        if any(indicator in context for indicator in ['validate', 'verify', 'check', 'trusted', 'secure']):
            confidence += 20
            
        # Decrease if it's clearly example/tutorial code
        if any(indicator in context for indicator in ['#', '//', '/*', 'example', 'demo', 'tutorial']):
            confidence -= 20
            
        # Increase if it looks like actual usage (not just definition)
        if any(indicator in context for indicator in ['=', '(', ')', '.', 'model', 'train']):
            confidence += 15
            
        # Decrease if it's in a test file
        if 'test' in context[:50]:
            confidence -= 15
            
        return max(20, min(85, confidence))
    
    def _calculate_dataset_loading_confidence(self, code_context: str) -> int:
        """Calculate confidence for dataset loading detection."""
        confidence = 55  # Base confidence
        
        # Check context to see if it's likely production code
        context = code_context.lower()
        
        # Decrease if it's clearly example/tutorial code
        if any(indicator in context for indicator in ['#', '//', '/*', 'example', 'demo', 'tutorial', 'sample']):
            confidence -= 25
            
        # Decrease if it's in a test file
        if 'test' in context[:100]:
            confidence -= 15
            
        # Increase if there are security-conscious patterns nearby
        if any(indicator in context for indicator in ['validate', 'verify', 'check', 'signature', 'checksum']):
            confidence += 20
            
        # Increase if it looks like actual usage (not just definition)
        if any(indicator in context for indicator in ['=', '(', ')', '.', 'data', 'dataset', 'load']):
            confidence += 15
            
        return max(25, min(90, confidence))
    
    def _confidence_to_severity(self, confidence: int, base: str = "Medium") -> str:
        """Convert confidence score to severity level with base adjustment."""
        if base == "High":
            if confidence >= 85:
                return "High"
            elif confidence >= 55:
                return "Medium"
            else:
                return "Low"
        else:  # base == "Medium"
            if confidence >= 80:
                return "High"
            elif confidence >= 50:
                return "Medium"
            else:
                return "Low"
    
    def _confidence_to_cvss(self, confidence: int, base_severity: str) -> float:
        """Convert confidence score to CVSS score."""
        base_scores = {
            "Critical": 9.0,
            "High": 7.5,
            "Medium": 5.5,
            "Low": 3.0
        }
        
        base_score = base_scores.get(base_severity, 5.0)
        confidence_factor = 0.5 + (confidence / 200)  # 0.5 to 1.0
        adjusted_score = min(10.0, base_score * confidence_factor)
        return round(adjusted_score, 1)


# ─────────────────────────────────────────────────────────────────────
# AGENTS REGISTRY
# ─────────────────────────────────────────────────────────────────────

ALL_SPECIALIST_AGENTS = [
    PromptInjectionHunter,
    RAGSecurityAuditor,
    MCPToolSecurityAnalyst,
    AgentOrchestrationSecurity,
    ModelDataPoisoningDetector,
]


def run_all_agents_on_code(code: str, file_path: str = "") -> List[dict]:
    """Run all specialist agents on code and aggregate findings"""
    all_findings = []
    
    console.print(f"\n  [bold]Deploying 5 Specialist Agents...[/bold]")
    
    for AgentClass in ALL_SPECIALIST_AGENTS:
        agent = AgentClass()
        console.print(f"    ▶ {agent.DISPLAY_NAME}")
        findings = agent.analyze(code, file_path)
        all_findings.extend(findings)
        console.print(f"      → {len(findings)} findings")
    
    return all_findings


if __name__ == "__main__":
    # Test with sample vulnerable code
    test_code = """
    from langchain.chat_models import ChatOpenAI
    from langchain.prompts import ChatPromptTemplate

    # Vulnerable: User input directly in prompt
    def generate_response(user_input):
        prompt = f"Answer this: {user_input}"
        return ChatOpenAI().invoke(prompt)

    # RAG without isolation
    from langchain.vectorstores import Chroma
    vectorstore = Chroma()

    # Dangerous: eval
    def process_code(code):
        return eval(code)
    """
    
    findings = run_all_agents_on_code(test_code, "test.py")
    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        validation_req = " (VALIDATION REQ)" if f.get('validation_required') else ""
        print(f"  - [{f['severity']}] {f['title']} (Conf: {f['confidence_score']}%){validation_req}")