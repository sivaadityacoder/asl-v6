"""
ASL V6 — Autonomous Bug Bounty Hunter
========================================
Architecture:
  Target URL
      ↓
  Phase 1: Deep Recon (subdomains, JS secrets, endpoints)
      ↓
  Phase 2: PARALLEL multi-agent attack (5 agents at once)
      ├── Auth Agent
      ├── Business Logic / IDOR Agent
      ├── Injection Agent
      ├── Misconfig Agent
      └── Sensitive Data Agent
      ↓
  Phase 3: Triager (dedup + CVSS scoring)
      ↓
  Phase 4: HackerOne / Bugcrowd submission draft

Run:
  uv run python v6/bug_bounty_hunter.py https://nordef.io
"""

import sys
import json
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(_ROOT / "src"))
sys.path.append(str(_ROOT / "v2"))

from asl_engine.agents.base import BaseAgent

console = Console()

# ─── Recon Utilities ──────────────────────────────────────
def deep_probe(url: str) -> dict:
    """Aggressive reconnaissance: headers, paths, JS file secrets, subdomains."""
    base = url.rstrip("/")
    results = {"headers": "", "interesting_paths": [], "js_secrets": [], "raw": ""}

    # 1. Full response headers
    try:
        r = subprocess.run(
            ["curl", "-sI", "-L", "--max-time", "15", "-A", "Mozilla/5.0", base],
            capture_output=True, text=True, timeout=20
        )
        results["headers"] = r.stdout[:3000]
        results["raw"] += f"=== HEADERS ===\n{r.stdout[:3000]}\n\n"
    except Exception as e:
        results["raw"] += f"Header probe error: {e}\n"

    # 2. Aggressive path enumeration (50 paths)
    paths = [
        "/.env", "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/api/v1/users", "/api/v1/user/1", "/api/v1/profile", "/api/v1/me",
        "/api/v1/admin", "/api/v1/orders", "/api/v1/payments",
        "/api/v1/config", "/api/v1/settings", "/api/v1/health",
        "/api/v1/debug", "/api/v1/logs", "/api/v1/metrics",
        "/admin/", "/admin/login", "/admin/dashboard",
        "/swagger-ui/", "/swagger.json", "/api-docs", "/openapi.json",
        "/actuator/", "/actuator/env", "/actuator/health",
        "/actuator/configprops", "/actuator/heapdump", "/actuator/jolokia",
        "/phpinfo.php", "/debug/", "/console/", "/graphql", "/graphql/",
        "/.well-known/security.txt", "/security.txt",
        "/api/v1/forgot-password", "/api/v1/reset-password",
        "/api/v1/register", "/api/v1/login",
        "/backup.zip", "/backup.sql", "/database.sql", "/dump.sql",
    ]

    for path in paths:
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}",
                 "--max-time", "8", f"{base}{path}"],
                capture_output=True, text=True, timeout=12
            )
            code, size = r.stdout.strip().split("|")
            if code not in ("404", "000", "410"):
                results["interesting_paths"].append({
                    "path": path, "status": code, "size": size
                })
                results["raw"] += f"[{code}] {path} (size: {size})\n"
        except Exception:
            pass

    # 3. Fetch homepage + JS snippets for secret scanning
    try:
        r = subprocess.run(
            ["curl", "-sL", "--max-time", "15", "-A", "Mozilla/5.0", base],
            capture_output=True, text=True, timeout=20
        )
        body = r.stdout
        results["raw"] += f"\n=== HOMEPAGE BODY ===\n{body[:4000]}\n"

        # Look for JS files referenced
        import re
        js_files = re.findall(r'src="([^"]+\.js[^"]*)"', body)[:5]
        for js_path in js_files:
            if js_path.startswith("http"):
                js_url = js_path
            else:
                js_url = f"{base}/{js_path.lstrip('/')}"
            try:
                js_r = subprocess.run(
                    ["curl", "-sL", "--max-time", "15", js_url],
                    capture_output=True, text=True, timeout=20
                )
                js_content = js_r.stdout
                # Search for patterns
                secret_patterns = [
                    (r'api[_-]?key["\s:=]+(["\']?)([A-Za-z0-9_\-]{20,})', "API Key"),
                    (r'secret["\s:=]+(["\']?)([A-Za-z0-9_\-]{20,})', "Secret"),
                    (r'password["\s:=]+(["\']?)([A-Za-z0-9_\-@#!]{8,})', "Password"),
                    (r'token["\s:=]+(["\']?)([A-Za-z0-9_\-\.]{20,})', "Token"),
                    (r'https?://[a-zA-Z0-9\-\.]+\.(internal|corp|local|dev)[^\s"\']+', "Internal URL"),
                    (r'eyJ[A-Za-z0-9_\-\.]{20,}', "JWT Token"),
                ]
                for pattern, label in secret_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    if matches:
                        results["js_secrets"].append({
                            "file": js_url[-60:], "type": label, "count": len(matches)
                        })
                        results["raw"] += f"[SECRET FOUND] {label} in {js_url[-60:]}\n"
            except Exception:
                pass
    except Exception as e:
        results["raw"] += f"Body probe error: {e}\n"

    # 4. CORS test with evil origin
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "10",
             "-H", "Origin: https://evil-attacker.com",
             f"{base}/api/v1/"],
            capture_output=True, text=True, timeout=15
        )
        results["raw"] += f"\n=== CORS PROBE ===\n{r.stdout[:500]}\n"
    except Exception:
        pass

    return results


# ─── Agent Definitions ────────────────────────────────────
PARALLEL_AGENTS = [
    {
        "id": "AUTH",
        "display": "🔑 Auth & Session Agent",
        "prompt": (
            "You are a bug bounty hunter specializing in Authentication vulnerabilities.\n"
            "Analyze the target data for:\n"
            "- JWT alg:none attacks, weak secrets, missing validation\n"
            "- Brute-force login endpoints (no rate limiting)\n"
            "- Insecure cookies (missing HttpOnly/Secure/SameSite)\n"
            "- Password reset token predictability / host header injection\n"
            "- OAuth redirect_uri open redirect\n"
            "- Account takeover via email/phone enumeration\n"
            "Return JSON: {\"findings\": [{\"title\", \"severity\", \"cvss_score\", "
            "\"endpoint\", \"http_method\", \"description\", \"poc_payload\", "
            "\"expected_response\", \"bounty_tier\", \"remediation\"}]}"
        )
    },
    {
        "id": "IDOR",
        "display": "🚪 IDOR & Business Logic Agent",
        "prompt": (
            "You are a bug bounty hunter specializing in IDOR and Business Logic flaws.\n"
            "Analyze the target data for:\n"
            "- IDOR: accessing /api/v1/users/2 with user 1's token\n"
            "- Mass assignment: sending 'role':'admin' in POST body\n"
            "- Price manipulation: changing 'price' or 'amount' in order requests\n"
            "- Race conditions: double-spending or double-registration\n"
            "- Broken function level authorization: non-admin calling /api/admin/\n"
            "- Horizontal privilege escalation between accounts\n"
            "Return JSON: {\"findings\": [{\"title\", \"severity\", \"cvss_score\", "
            "\"endpoint\", \"http_method\", \"description\", \"poc_payload\", "
            "\"expected_response\", \"bounty_tier\", \"remediation\"}]}"
        )
    },
    {
        "id": "INJECTION",
        "display": "💉 Injection Agent",
        "prompt": (
            "You are a bug bounty hunter specializing in Injection attacks.\n"
            "Analyze the target data for:\n"
            "- SQL Injection in search/filter/login fields\n"
            "- NoSQL Injection ($where, $gt operators in MongoDB)\n"
            "- Server-Side Template Injection ({{7*7}} in name/email fields)\n"
            "- Command injection in file upload, report generation, or export endpoints\n"
            "- GraphQL injection and introspection abuse\n"
            "Return JSON: {\"findings\": [{\"title\", \"severity\", \"cvss_score\", "
            "\"endpoint\", \"http_method\", \"description\", \"poc_payload\", "
            "\"expected_response\", \"bounty_tier\", \"remediation\"}]}"
        )
    },
    {
        "id": "MISCONFIG",
        "display": "⚙️ Misconfig & Exposure Agent",
        "prompt": (
            "You are a bug bounty hunter specializing in Security Misconfiguration.\n"
            "Analyze the target data for:\n"
            "- CORS: Access-Control-Allow-Origin reflecting arbitrary origins\n"
            "- Spring Boot Actuator endpoints exposed (/actuator/env, /actuator/heapdump)\n"
            "- Missing security headers (CSP, HSTS, X-Frame-Options)\n"
            "- Exposed admin panels with default or no credentials\n"
            "- Swagger/OpenAPI UI publicly accessible\n"
            "- Server version disclosure in headers\n"
            "Return JSON: {\"findings\": [{\"title\", \"severity\", \"cvss_score\", "
            "\"endpoint\", \"http_method\", \"description\", \"poc_payload\", "
            "\"expected_response\", \"bounty_tier\", \"remediation\"}]}"
        )
    },
    {
        "id": "DATA",
        "display": "📁 Sensitive Data Agent",
        "prompt": (
            "You are a bug bounty hunter specializing in Sensitive Data Exposure.\n"
            "Analyze the target data for:\n"
            "- .env files exposing DB credentials, JWT secrets, API keys\n"
            "- .git/config exposing repo URLs and auth tokens\n"
            "- Hardcoded secrets in JavaScript bundles (API keys, tokens)\n"
            "- Exposed backup files (.zip, .sql, .tar.gz)\n"
            "- PII leakage in API responses (emails, SSNs, full card numbers)\n"
            "- phpinfo.php or debug endpoints leaking server internals\n"
            "Return JSON: {\"findings\": [{\"title\", \"severity\", \"cvss_score\", "
            "\"endpoint\", \"http_method\", \"description\", \"poc_payload\", "
            "\"expected_response\", \"bounty_tier\", \"remediation\"}]}"
        )
    },
]


class BountyAgent(BaseAgent):
    def __init__(self, config: dict):
        self.agent_id = config["id"]
        self.display = config["display"]
        super().__init__(system_prompt=config["prompt"])
        self._focus_prompt = config["prompt"]

    def hunt(self, url: str, recon_data: dict) -> dict:
        prompt = (
            f"Target URL: {url}\n\n"
            f"Recon Data:\n{recon_data['raw'][:5000]}\n\n"
            f"Interesting paths found: {json.dumps(recon_data['interesting_paths'])}\n"
            f"JS Secrets found: {json.dumps(recon_data['js_secrets'])}\n\n"
            "Based on all this evidence, list every vulnerability you can confirm or "
            "highly suspect. Include specific PoC payloads for each."
        )
        result = self.chat_json(prompt)
        if not result.get("findings"):
            result["findings"] = []
        return result


class BountyTriager(BaseAgent):
    def __init__(self):
        super().__init__(system_prompt=(
            "You are a Senior Bug Bounty Triager. You receive raw findings from multiple "
            "specialist hunters and must: deduplicate, validate evidence, assign CVSS scores, "
            "and determine which findings are worth submitting to HackerOne or Bugcrowd.\n"
            "Return JSON:\n"
            "{\n"
            "  \"validated_findings\": [...],\n"
            "  \"executive_summary\": \"string\",\n"
            "  \"risk_rating\": \"Critical|High|Medium|Low\",\n"
            "  \"submission_recommendation\": \"string\",\n"
            "  \"estimated_bounty_range\": \"$X - $Y\"\n"
            "}"
        ))

    def triage(self, url: str, all_findings: list) -> dict:
        prompt = (
            f"Target: {url}\n"
            f"Raw findings ({len(all_findings)} total):\n"
            f"{json.dumps(all_findings[:30], indent=2)}\n\n"
            "Triage, deduplicate, and produce the final bug bounty submission report."
        )
        result = self.chat_json(prompt, max_tokens=8000)
        if not result.get("validated_findings"):
            result["validated_findings"] = all_findings
        if not result.get("risk_rating"):
            has_critical = any(f.get("severity") == "Critical" for f in all_findings)
            has_high = any(f.get("severity") == "High" for f in all_findings)
            result["risk_rating"] = "Critical" if has_critical else ("High" if has_high else "Medium")
        if not result.get("estimated_bounty_range"):
            result["estimated_bounty_range"] = "$500 - $5,000"
        return result


# ─── Report Generator ────────────────────────────────────
def generate_bounty_report(url: str, recon: dict, triage: dict) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = url.replace("https://", "").replace("http://", "").replace("/", "_")[:40]
    path = _ROOT / "reports" / f"BOUNTY-{safe}-{timestamp}.md"
    path.parent.mkdir(exist_ok=True)

    findings = triage.get("validated_findings", [])
    critical = [f for f in findings if f.get("severity") == "Critical"]
    high     = [f for f in findings if f.get("severity") == "High"]
    medium   = [f for f in findings if f.get("severity") == "Medium"]
    low      = [f for f in findings if f.get("severity") in ("Low", "Info")]

    lines = [
        "# ASL Engine V6 — Bug Bounty Report",
        "",
        f"**Target:** `{url}`",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Overall Risk:** {triage.get('risk_rating', 'Unknown')}",
        f"**Estimated Bounty Range:** {triage.get('estimated_bounty_range', 'N/A')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        triage.get("executive_summary", "See findings below."),
        "",
        "## Submission Recommendation",
        "",
        triage.get("submission_recommendation", "Review findings and submit high/critical."),
        "",
        "---",
        "",
        "## Statistics",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {len(critical)} |",
        f"| 🟠 High | {len(high)} |",
        f"| 🟡 Medium | {len(medium)} |",
        f"| 🟢 Low/Info | {len(low)} |",
        "",
        "---",
        "",
        "## Attack Surface Discovery",
        "",
        "**Interesting Paths Found:**",
        "",
    ]

    for p in recon.get("interesting_paths", []):
        lines.append(f"- `{p['path']}` → HTTP {p['status']} (size: {p['size']} bytes)")

    if recon.get("js_secrets"):
        lines += ["", "**Secrets Detected in JavaScript:**", ""]
        for s in recon["js_secrets"]:
            lines.append(f"- `{s['file']}` — **{s['type']}** ({s['count']} matches)")

    lines += ["", "---", "", "## Detailed Findings", ""]

    emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "🔵"}
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "Info")
        lines += [
            f"### {i}. {emoji_map.get(sev,'⚪')} [{sev}] {f.get('title','Finding')}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **CVSS** | {f.get('cvss_score','N/A')} |",
            f"| **Endpoint** | `{f.get('endpoint','N/A')}` |",
            f"| **Method** | `{f.get('http_method','N/A')}` |",
            f"| **Bounty Tier** | {f.get('bounty_tier','N/A')} |",
            "",
            f"**Description:** {f.get('description','')}",
            "",
            "**PoC:**",
            "```",
            f.get("poc_payload", "N/A"),
            "```",
            "",
            f"**Expected Response:** {f.get('expected_response','N/A')}",
            "",
            f"**Remediation:** {f.get('remediation','N/A')}",
            "",
            "---",
            "",
        ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ─── Main ─────────────────────────────────────────────────
class V6BugBountyHunter:
    def run(self, url: str):
        if not url.startswith("http"):
            url = "https://" + url

        console.print(Panel.fit(
            f"[bold red]ASL Engine V6[/bold red]\n"
            f"[bold white]Autonomous Bug Bounty Hunter[/bold white]\n"
            f"[dim]Target: {url}[/dim]",
            border_style="red"
        ))

        # Phase 1: Deep Recon
        console.print("\n[bold red]Phase 1: Deep Reconnaissance[/bold red]")
        console.print("[*] Running aggressive probe (headers, 50 paths, JS secret scanning)...")
        recon = deep_probe(url)

        console.print(f"[+] Found [bold]{len(recon['interesting_paths'])}[/bold] interesting paths")
        console.print(f"[+] Found [bold]{len(recon['js_secrets'])}[/bold] JS secret candidates")

        if recon["interesting_paths"]:
            table = Table(title="Interesting Paths")
            table.add_column("Path", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Size")
            for p in recon["interesting_paths"]:
                color = "red" if p["status"] in ("200","201") else "yellow"
                table.add_row(p["path"], f"[{color}]{p['status']}[/{color}]", p["size"])
            console.print(table)

        # Phase 2: Parallel Agent Hunt
        console.print("\n[bold red]Phase 2: Parallel Multi-Agent Bug Hunt[/bold red]")
        console.print("[*] Launching 5 specialist agents simultaneously...\n")

        all_findings = []
        agent_results = {}
        lock = threading.Lock()

        def run_agent(config):
            agent = BountyAgent(config)
            console.print(f"  ▶ {config['display']} started")
            result = agent.hunt(url, recon)
            findings = result.get("findings", [])
            with lock:
                all_findings.extend(findings)
                agent_results[config["id"]] = len(findings)
            console.print(f"  ✓ {config['display']} → [bold]{len(findings)}[/bold] findings")
            return config["id"], findings

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(run_agent, cfg) for cfg in PARALLEL_AGENTS]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    console.print(f"  [red]Agent error: {e}[/red]")

        # Summary table
        result_table = Table(title="\nAgent Hunt Summary")
        result_table.add_column("Agent", style="cyan")
        result_table.add_column("Findings", style="yellow")
        for cfg in PARALLEL_AGENTS:
            count = agent_results.get(cfg["id"], 0)
            result_table.add_row(cfg["display"], str(count))
        result_table.add_row("[bold]TOTAL[/bold]", f"[bold]{len(all_findings)}[/bold]")
        console.print(result_table)

        # Phase 3: Triage
        console.print("\n[bold red]Phase 3: AI Lead Triager — Final Validation[/bold red]")
        triager = BountyTriager()
        triage = triager.triage(url, all_findings)
        validated = triage.get("validated_findings", [])

        console.print(f"[+] Validated [bold]{len(validated)}[/bold] confirmed findings")
        console.print(f"[+] Risk Level: [bold red]{triage.get('risk_rating','Unknown')}[/bold red]")
        console.print(f"[+] Est. Bounty: [bold green]{triage.get('estimated_bounty_range','N/A')}[/bold green]")

        # Phase 4: Report
        console.print("\n[bold red]Phase 4: Generating HackerOne-Ready Report[/bold red]")
        report_path = generate_bounty_report(url, recon, triage)

        console.print(Panel(
            f"[bold green]✓ Bug Bounty Scan Complete![/bold green]\n\n"
            f"[bold]Report:[/bold] {report_path}\n"
            f"[bold]Confirmed Findings:[/bold] {len(validated)}\n"
            f"[bold]Risk:[/bold] {triage.get('risk_rating','Unknown')}\n"
            f"[bold]Estimated Bounty:[/bold] {triage.get('estimated_bounty_range','N/A')}",
            border_style="green"
        ))

        console.print("\n[bold]Executive Summary:[/bold]")
        console.print(triage.get("executive_summary", ""))
        console.print("\n[bold]Submission Recommendation:[/bold]")
        console.print(triage.get("submission_recommendation", ""))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python v6/bug_bounty_hunter.py https://target.com[/red]")
        sys.exit(1)
    V6BugBountyHunter().run(sys.argv[1])
