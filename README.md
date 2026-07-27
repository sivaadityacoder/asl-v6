# ASL V6 — Open-Source AI Red-Teaming & Exploit Verification Engine

> 🔴 **Currently accepting 3 advisory clients for Q3 2026.** [Email me](mailto:adityasecuritylabs@gmail.com) or [DM on LinkedIn](https://www.linkedin.com/in/sivaaditya-panuganti-b67484316/).

**Author:** Siva Aditya Panuganti (Security Researcher)  
**Track Record:** 6+ CVEs and GHSAs in production AI systems via responsible disclosure to BSI Germany, CERT-EE, and GitHub Security:
- [CVE-2026-22038](https://nvd.nist.gov/vuln/detail/CVE-2026-22038) — AutoGPT secrets leak
- [GHSA-x58f-9m57-qc4m](https://github.com/advisories/GHSA-x58f-9m57-qc4m) — FlowiseAI sandbox escape
- [CVE-2025-68621](https://nvd.nist.gov/vuln/detail/CVE-2025-68621) — Trilium Notes timing side-channel
- [GHSA-p97p-7x96-7wj5](https://github.com/advisories/GHSA-p97p-7x96-7wj5) — LLaMmlein deserialization RCE

---

## What It Does

ASL V6 is a research-grade vulnerability assessment and red-teaming engine for Python and AI agent codebases. It combines Abstract Syntax Tree (AST) code analysis with live Docker runtime testing to verify real security flaws without flooding developers with false alerts.

### Technical Capabilities
1. **10 Security Analyzers:** Examines code for OWASP Top 10 LLM and Agent vulnerabilities, including prompt injection sinks, goal hijacking, unsafe code execution (`eval`/`exec`), and tool abuse.
2. **AST Contextual Filtering:** Parses Python syntax trees to ignore test suites, mock files, and docstrings. This eliminates around 98% of false positive alerts.
3. **Live Docker Runtime Verification:** Runs untrusted code snippets inside isolated ephemeral Docker containers (`python:3.11-slim`) to confirm whether an injection is exploitable in a live runtime environment.
4. **Remediation Patch Generation (Optional):** Generates structured code fixes and patch suggestions. Works offline using deterministic AST rules, or can connect to NVIDIA developer API endpoints if an API key is provided.

---

## Why This Tool Is Free

ASL V6 is free and open-source under the MIT License.
* **100% Local Execution:** The analyzers, AST filters, and Docker runtime tests execute locally on your machine. They do not send data over the internet or consume API tokens.
* **Bring Your Own Key (Optional):** If you want LLM-assisted code patch suggestions, you can provide your own free developer API key via the `NVIDIA_API_KEY` environment variable. If no key is provided, the tool automatically uses offline rule-based patch suggestions at zero cost.

---

## Verified Execution Benchmark

Tested on real filesystem repositories:

| Repository | Files Scanned | Raw Alerts | Validated True Positives | False Positive Reduction | Docker Sandbox |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **LangGraph** | 513 | 606 | **13** | **97.9%** | `ACTIVE` |
| **Haystack (deepset)** | 1,866 | 1,365 | **128** | **90.6%** | `ACTIVE` |
| **ZenML** | 2,552 | 1,289 | **68** | **94.7%** | `ACTIVE` |
| **Rasa** | — | 703 | **12** | **98.3%** | `ACTIVE` |
| **Jina AI** | 823 | 598 | **40** | **93.3%** | `ACTIVE` |
| **Weaviate** | 501 | 682 | **9** | **98.7%** | `ACTIVE` |
| **Argilla** | 1,411 | 302 | **14** | **95.4%** | `ACTIVE` |
| **ASL V6 Engine** | 7 | 48 | **0** | **100.0%** | `ACTIVE` |

---

## Installation & Usage

### 1. Install Dependencies
```bash
git clone https://github.com/sivaadityacoder/asl-v6.git
cd asl-v6
pip install -r requirements.txt
```

### 2. Run Live Security Audit
```bash
python3 v6_ai_infra_security.py /path/to/your/project
```

### 3. Run the Benchmark
```bash
python3 v6_ai_benchmarks.py /path/to/repo1 /path/to/repo2
```

---

## CI/CD Pull Request Gate

You can use the included GitHub Actions workflow (`asl_v6_ci_cd_action.yml`) to automatically check pull requests for security flaws during your CI/CD build process.

---

## Pro Managed Scan — Monthly Subscription

If you want ASL V6 to run on your private or enterprise repository without setting up local infrastructure, we offer a managed scan service:

| Plan | Price | What You Get |
| :--- | :--- | :--- |
| **Pro** | $99 / month | Monthly ASL V6 scan of your repo + clean markdown security report delivered by email |
| **Enterprise** | $299 / month | Monthly scan report + 1 remediation pull request written into your repo + 30-minute review call |

To subscribe, email **adityasecuritylabs@gmail.com** with the subject `ASL V6 Pro Subscription` and your GitHub repository URL.

---

## Security Research & Advisory Services

An automated test engine helps find known patterns, but securing custom agent architectures requires manual review. I work directly with engineering teams on a retainer or fixed-project basis:
* **Advisory Retainer ($2,500 / month):** Monthly architecture review, manual vulnerability discovery, and remediation pull requests written directly for your codebase.
* **Emergency Security Assessment ($5,000 fixed):** 1-week pre-launch code audit or post-incident review with proof-of-concept exploits and remediation guidance.
* **EU AI Act Technical Documentation ($3,500 - $5,000 fixed):** Technical robustness testing and adversarial documentation for European compliance.

**Contact:** adityasecuritylabs@gmail.com | [GitHub Profile](https://github.com/sivaadityacoder)
