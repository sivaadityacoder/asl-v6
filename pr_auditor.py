import os
import sys
import json
import logging
from pathlib import Path
import requests

# Set up path to import ASL V6 core modules from the parent directory
_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(_ROOT))

from v6_specialist_agents import ALL_SPECIALIST_AGENTS
from v6_ai_infra_security import VerificationGauntlet, LLMSecurityReasoningEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def get_pr_files(github_token, repo, pr_number):
    """Fetch changed files for a PR."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def post_pr_review(github_token, repo, pr_number, commit_id, comments):
    """Post inline comments as a PR review."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {
        "commit_id": commit_id,
        "event": "COMMENT",
        "comments": comments
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code not in (200, 201):
        logging.error(f"Failed to post PR review: {response.text}")

def generate_sarif(findings, repo_path, output_file="asl-v6-results.sarif"):
    """Generate SARIF JSON from ASL V6 findings."""
    rules = []
    results = []
    rule_ids_seen = set()

    for finding in findings:
        rule_id = finding.get("owasp_llm_id", finding.get("category", "ASL-001"))
        if rule_id not in rule_ids_seen:
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.get("category", "General AI Security Issue")},
                "fullDescription": {"text": finding.get("title", "")},
                "help": {"text": finding.get("remediation", "")},
                "properties": {
                    "tags": ["security", "ai-security", "asl-v6"]
                }
            })
            rule_ids_seen.add(rule_id)
        
        results.append({
            "ruleId": rule_id,
            "message": {"text": finding.get("description", "Potential vulnerability detected.")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("file_path", "")},
                    "region": {
                        "startLine": finding.get("line_number", 1),
                        "snippet": {"text": finding.get("code_evidence", "")}
                    }
                }
            }]
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ASL V6 AI Security",
                    "informationUri": "https://adityasecuritylabs.com",
                    "rules": rules
                }
            },
            "results": results
        }]
    }
    
    with open(output_file, "w") as f:
        json.dump(sarif_data, f, indent=2)
    logging.info(f"Generated SARIF report: {output_file}")

def scan_file_with_agents(file_path: Path, relative_path: str):
    """Run ASL V6 Specialist Agents on a specific file."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        for AgentClass in ALL_SPECIALIST_AGENTS:
            agent = AgentClass()
            findings.extend(agent.analyze(content, relative_path))
    except Exception as e:
        logging.error(f"Error scanning {relative_path}: {e}")
    return findings

def main():
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        logging.error("GITHUB_TOKEN is missing!")
        sys.exit(1)

    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        logging.error("GITHUB_EVENT_PATH not found. Are we running in GitHub Actions?")
        sys.exit(1)

    with open(event_path, "r") as f:
        event = json.load(f)

    pr = event.get("pull_request")
    if not pr:
        logging.info("Not a pull request event. Skipping PR inline scan.")
        sys.exit(0)

    repo_name = event.get("repository", {}).get("full_name")
    pr_number = pr.get("number")
    commit_id = pr.get("head", {}).get("sha")
    workspace = Path(os.getenv("GITHUB_WORKSPACE", "."))

    logging.info(f"Fetching changed files for {repo_name} PR #{pr_number}")
    changed_files = get_pr_files(github_token, repo_name, pr_number)
    
    all_raw_findings = []
    for file_info in changed_files:
        if file_info.get("status") in ("removed",):
            continue
            
        filename = file_info.get("filename")
        file_path = workspace / filename
        if not file_path.exists():
            continue
            
        if file_path.suffix in {".py", ".js", ".ts", ".yaml", ".yml", ".json"}:
            logging.info(f"Scanning changed file: {filename}")
            all_raw_findings.extend(scan_file_with_agents(file_path, filename))

    logging.info(f"Detected {len(all_raw_findings)} raw heuristic signals.")

    gauntlet = VerificationGauntlet(confidence_threshold=65)
    gauntlet_results = gauntlet.verify(all_raw_findings)
    validated_findings = gauntlet_results.get("validated_findings", [])
    
    logging.info(f"Validated findings: {len(validated_findings)} (False positive reduction: {gauntlet_results.get('fp_reduction_percentage')}%)")

    # Optional: Reason and remediate the top findings to get a patch
    reasoning_engine = LLMSecurityReasoningEngine()
    for finding in validated_findings:
        reasoning_engine.reason_and_remediate(finding, workspace)

    generate_sarif(validated_findings, workspace)

    comments = []
    high_severity_found = False
    
    for finding in validated_findings:
        sev = finding.get("severity", "Medium")
        if sev in ("High", "Critical"):
            high_severity_found = True
            
        # Format the inline comment body
        body = f"### 🚨 ASL V6 AI Security Issue Detected\n\n"
        body += f"**{sev} Severity:** {finding.get('title', 'Unknown')}\n"
        body += f"**Category:** `{finding.get('category', 'General')}`\n\n"
        body += f"{finding.get('description', '')}\n\n"
        
        if "llm_reasoning" in finding:
            llm_r = finding["llm_reasoning"]
            body += f"#### 🛡️ AI Architect Patch\n```python\n{llm_r.get('custom_code_patch', '').strip()}\n```\n"
            
        comments.append({
            "path": finding.get("file_path"),
            "line": finding.get("line_number", 1), # Might need mapping to PR diff context
            "body": body
        })

    if comments:
        logging.info(f"Posting {len(comments)} inline comments to PR.")
        post_pr_review(github_token, repo_name, pr_number, commit_id, comments)
        
    fail_on_high = os.getenv("FAIL_ON_HIGH_SEVERITY", "true").lower() == "true"
    if high_severity_found and fail_on_high:
        logging.error("Verified High/Critical severity issues were found. Failing the CI gate.")
        sys.exit(1)
    
    logging.info("ASL V6 Scan complete.")

if __name__ == "__main__":
    main()
