"""
ASL V6 SaaS Backend - Report Generator Service
"""
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import structlog

from app.core.config import settings
from app.core.database import get_supabase
from supabase import Client

logger = structlog.get_logger()


class ReportGenerator:
    def __init__(self, report_id: str):
        self.report_id = report_id
        self.supabase: Client = get_supabase()
        self.report_data: Dict = {}
        self.scan_data: Dict = {}
        self.findings: List[Dict] = []
    
    async def generate(self):
        """Generate report based on format"""
        try:
            await self._load_data()
            
            format_type = self.report_data["format"]
            
            if format_type == "markdown":
                content = await self._generate_markdown()
            elif format_type == "html":
                content = await self._generate_html()
            elif format_type == "pdf":
                content = await self._generate_pdf()
            elif format_type == "json":
                content = await self._generate_json()
            elif format_type == "sarif":
                content = await self._generate_sarif()
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            # Save to storage
            file_path = await self._save_report(content, format_type)
            
            # Update report record
            self.supabase.table("reports").update({
                "status": "completed",
                "file_path": file_path,
                "file_size": len(content) if isinstance(content, str) else len(content),
                "generated_at": datetime.utcnow().isoformat(),
                "download_url": f"/api/v1/reports/{self.report_id}/download",
            }).eq("id", self.report_id).execute()
            
            logger.info("Report generated", report_id=self.report_id, format=format_type)
            
        except Exception as e:
            logger.error("Report generation failed", report_id=self.report_id, error=str(e))
            self.supabase.table("reports").update({
                "status": "failed",
                "error": str(e),
            }).eq("id", self.report_id).execute()
            raise
    
    async def _load_data(self):
        """Load report, scan, and findings data"""
        # Get report
        report = self.supabase.table("reports").select("*").eq("id", self.report_id).single().execute()
        if not report.data:
            raise Exception("Report not found")
        self.report_data = report.data
        
        # Get scan
        scan = self.supabase.table("scans").select("*").eq("id", self.report_data["scan_id"]).single().execute()
        if not scan.data:
            raise Exception("Scan not found")
        self.scan_data = scan.data
        
        # Get findings
        findings = self.supabase.table("findings").select("*").eq("scan_id", self.report_data["scan_id"]).order("layer").order("severity", desc=True).execute()
        self.findings = findings.data or []
    
    async def _generate_markdown(self) -> str:
        """Generate Markdown report"""
        scan = self.scan_data
        findings = self.findings
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        md = f"""# {self.report_data['title']}

**Scan ID:** {scan['id']}  
**Repository:** {scan.get('repository', {}).get('full_name', 'Unknown')}  
**Branch:** {scan['branch']}  
**Commit:** {scan['commit_sha'][:8]}  
**Scan Date:** {scan.get('completed_at', scan.get('started_at', 'Unknown'))}  
**Duration:** {scan.get('duration_seconds', 0)} seconds  

## Executive Summary

This report presents the results of an AI/LLM security assessment conducted by ASL V6.

### Findings Overview

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['critical']} |
| High | {severity_counts['high']} |
| Medium | {severity_counts['medium']} |
| Low | {severity_counts['low']} |
| Info | {severity_counts['info']} |
| **Total** | **{len(findings)}** |

### Risk Assessment

{self._generate_risk_assessment(severity_counts)}

## Detailed Findings

"""
        
        # Group by layer
        by_layer = {}
        for f in findings:
            layer = f.get("layer", 0)
            if layer not in by_layer:
                by_layer[layer] = []
            by_layer[layer].append(f)
        
        for layer_num in sorted(by_layer.keys()):
            layer_findings = by_layer[layer_num]
            layer_name = layer_findings[0].get("layer_name", f"Layer {layer_num}") if layer_findings else f"Layer {layer_num}"
            
            md += f"\n### Layer {layer_num}: {layer_name}\n\n"
            
            for i, finding in enumerate(layer_findings, 1):
                md += self._format_finding_markdown(finding, i)
        
        md += "\n---\n\n## Remediation Guidance\n\n"
        md += self._generate_remediation_guidance()
        
        md += "\n---\n\n## Appendix: Scan Configuration\n\n"
        md += f"```json\n{json.dumps(scan.get('scan_config', {}), indent=2)}\n```\n"
        
        return md
    
    def _format_finding_markdown(self, finding: Dict, index: int) -> str:
        """Format a single finding as markdown"""
        severity = finding.get("severity", "info").upper()
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(severity, "⚪")
        
        md = f"#### {index}. {severity_emoji} {finding.get('title', 'Untitled')} [{severity}]\n\n"
        
        if finding.get("rule_id"):
            md += f"**Rule ID:** {finding['rule_id']}  \n"
        if finding.get("file_path"):
            md += f"**File:** `{finding['file_path']}`"
            if finding.get("line_start"):
                md += f":{finding['line_start']}"
            md += "  \n"
        if finding.get("cvss_score"):
            md += f"**CVSS:** {finding['cvss_score']} ({finding.get('cvss_vector', 'N/A')})  \n"
        if finding.get("cwe_id"):
            md += f"**CWE:** {finding['cwe_id']}  \n"
        if finding.get("owasp_llm_id"):
            md += f"**OWASP LLM:** {finding['owasp_llm_id']}  \n"
        if finding.get("mitre_atlas_id"):
            md += f"**MITRE ATLAS:** {finding['mitre_atlas_id']}  \n"
        
        md += f"\n**Description:**\n{finding.get('description', 'No description')}\n\n"
        
        if finding.get("code_snippet"):
            md += f"**Code:**\n```\n{finding['code_snippet']}\n```\n\n"
        
        if finding.get("evidence"):
            md += f"**Evidence:**\n```json\n{json.dumps(finding['evidence'], indent=2)}\n```\n\n"
        
        if finding.get("remediation"):
            md += f"**Remediation:**\n{finding['remediation']}\n\n"
        
        if finding.get("references"):
            md += "**References:**\n"
            for ref in finding["references"]:
                md += f"- {ref}\n"
            md += "\n"
        
        md += "---\n\n"
        return md
    
    def _generate_risk_assessment(self, severity_counts: Dict) -> str:
        """Generate risk assessment text"""
        if severity_counts["critical"] > 0:
            return "🔴 **CRITICAL RISK** - Immediate action required. Critical vulnerabilities found that could lead to complete system compromise."
        elif severity_counts["high"] > 0:
            return "🟠 **HIGH RISK** - Urgent remediation needed. High-severity vulnerabilities present significant security risk."
        elif severity_counts["medium"] > 0:
            return "🟡 **MEDIUM RISK** - Remediation recommended. Medium-severity vulnerabilities should be addressed in next sprint."
        elif severity_counts["low"] > 0:
            return "🟢 **LOW RISK** - Minor issues found. Consider addressing during routine maintenance."
        else:
            return "🔵 **INFORMATIONAL** - No significant vulnerabilities detected. Good security posture."
    
    def _generate_remediation_guidance(self) -> str:
        """Generate remediation guidance"""
        # Group findings by category
        categories = {}
        for f in self.findings:
            cat = f.get("owasp_llm_id") or f.get("mitre_atlas_id") or f.get("category", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f)
        
        md = "### Priority Remediation Actions\n\n"
        
        for cat, findings in sorted(categories.items()):
            critical_high = [f for f in findings if f.get("severity") in ["critical", "high"]]
            if critical_high:
                md += f"#### {cat}\n"
                md += f"Found {len(critical_high)} critical/high findings. Recommended actions:\n"
                for f in critical_high[:3]:
                    md += f"- {f.get('remediation', 'Review and remediate')}\n"
                md += "\n"
        
        return md
    
    async def _generate_html(self) -> str:
        """Generate HTML report"""
        markdown = await self._generate_markdown()
        # Convert markdown to HTML (would use markdown library)
        # For now, wrap in basic HTML
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.report_data['title']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3, h4 {{ color: #1a1a2e; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 6px; overflow-x: auto; }}
        .critical {{ color: #dc2626; }} .high {{ color: #ea580c; }}
        .medium {{ color: #ca8a04; }} .low {{ color: #16a34a; }} .info {{ color: #2563eb; }}
    </style>
</head>
<body>
{markdown}
</body>
</html>"""
    
    async def _generate_pdf(self) -> bytes:
        """Generate PDF report using WeasyPrint"""
        html = await self._generate_html()
        # Would use weasyprint to convert HTML to PDF
        # For now, return HTML as bytes
        return html.encode()
    
    async def _generate_json(self) -> str:
        """Generate JSON report"""
        return json.dumps({
            "report": self.report_data,
            "scan": self.scan_data,
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self._count_by_severity(),
                "by_layer": self._count_by_layer(),
            },
            "generated_at": datetime.utcnow().isoformat(),
        }, indent=2)
    
    async def _generate_sarif(self) -> str:
        """Generate SARIF report for IDE integration"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ASL V6",
                        "version": settings.app_version,
                        "informationUri": "https://aslv6.com",
                        "rules": [],
                    }
                },
                "results": [],
            }]
        }
        
        rule_map = {}
        for finding in self.findings:
            rule_id = finding.get("rule_id", "unknown")
            if rule_id not in rule_map:
                rule_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("title", rule_id),
                    "shortDescription": {"text": finding.get("description", "")[:100]},
                    "fullDescription": {"text": finding.get("description", "")},
                    "defaultConfiguration": {"level": self._map_severity_to_sarif(finding.get("severity", "info"))},
                }
            
            result = {
                "ruleId": rule_id,
                "level": self._map_severity_to_sarif(finding.get("severity", "info")),
                "message": {"text": finding.get("title", "Finding")},
                "locations": [],
            }
            
            if finding.get("file_path"):
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["file_path"]},
                        "region": {
                            "startLine": finding.get("line_start", 1),
                            "endLine": finding.get("line_end", finding.get("line_start", 1)),
                        }
                    }
                })
            
            sarif["runs"][0]["results"].append(result)
        
        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rule_map.values())
        
        return json.dumps(sarif, indent=2)
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        return mapping.get(severity, "note")
    
    def _count_by_severity(self) -> Dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def _count_by_layer(self) -> Dict:
        counts = {}
        for f in self.findings:
            layer = f.get("layer", 0)
            counts[layer] = counts.get(layer, 0) + 1
        return counts
    
    async def _save_report(self, content: str, format_type: str) -> str:
        """Save report to Supabase Storage"""
        file_name = f"{self.report_data['scan_id']}/{self.report_id}.{format_type}"
        
        if isinstance(content, str):
            content_bytes = content.encode()
        else:
            content_bytes = content
        
        self.supabase.storage.from_("reports").upload(
            file_name,
            content_bytes,
            {"content-type": self._get_content_type(format_type)}
        )
        
        return file_name
    
    def _get_content_type(self, format_type: str) -> str:
        mapping = {
            "markdown": "text/markdown",
            "html": "text/html",
            "pdf": "application/pdf",
            "json": "application/json",
            "sarif": "application/sarif+json",
        }
        return mapping.get(format_type, "application/octet-stream")


async def generate_report(report_id: str):
    """Entry point for Celery task"""
    generator = ReportGenerator(report_id)
    await generator.generate()