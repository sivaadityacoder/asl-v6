# ASL V6 — Open-Source AI Vulnerability Scanner

**Author:** Siva Aditya Panuganti (Security Researcher)  
**Track Record:** 6+ CVEs and GHSAs in production AI systems (AutoGPT, FlowiseAI, LLaMmlein, LangGraph MsgPack RCE) via responsible disclosure to BSI Germany, CERT-EE, and GitHub Security.

---

## What It Does

ASL V6 is an automated vulnerability scanner for Python and AI agent codebases. It combines Abstract Syntax Tree (AST) code analysis with Docker runtime testing to find real security flaws without flooding developers with false alerts.

### Technical Capabilities
1. **10 Security Scanners:** Analyzes code for OWASP Top 10 LLM and Agent vulnerabilities, including prompt injection sinks, goal hijacking, unsafe code execution (`eval`/`exec`), and tool abuse.
2. **AST Contextual Filtering:** Parses Python syntax trees to ignore test suites, mock files, and docstrings. This eliminates around 98% of false positive alerts.
3. **Live Docker Runtime Verification:** Runs untrusted code snippets inside isolated ephemeral Docker containers (`python:3.11-slim`) to confirm whether an injection is exploitable in a live runtime environment.
4. **Remediation Patch Generation (Optional):** Generates structured code fixes and patch suggestions. Works offline using deterministic AST rules, or can connect to NVIDIA developer API endpoints if an API key is provided.

---

## Why This Tool Is Free

ASL V6 is free and open-source under the MIT License.
* **100% Local Execution:** The scanners, AST filters, and Docker runtime tests execute locally on your machine. They do not send data over the internet or consume API tokens.
* **Bring Your Own Key (Optional):** If you want LLM-assisted code patch suggestions, you can provide your own free developer API key via the `NVIDIA_API_KEY` environment variable. If no key is provided, the tool automatically uses offline rule-based patch suggestions at zero cost.

---

## Verified Execution Benchmark

Tested on real filesystem repositories:

| Repository | Files Scanned | Raw Alerts | Validated True Positives | False Positive Reduction | Runtime Verification |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **LangGraph** | 513 | 606 | **13** | **97.9%** | `VERIFIED IN RUNTIME` |
| **ASL V6 Engine** | 7 | 48 | **0** | **100.0%** | `VERIFIED IN RUNTIME` |

---

## Installation & Usage

### 1. Install Dependencies
```bash
git clone https://github.com/sivaadityacoder/asl-v6.git
cd asl-v6
pip install -r requirements.txt
```

### 2. Scan a Codebase
```bash
python3 v6_ai_infra_security.py /path/to/your/project
```

### 3. Run the Benchmark
```bash
python3 v6_ai_benchmarks.py /path/to/repo1 /path/to/repo2
```

---

## CI/CD Pull Request Gate

You can use the included GitHub Actions workflow (`asl_v6_ci_cd_action.yml`) to automatically scan pull requests for security flaws during your CI/CD build process.

---

## Security Research & Advisory Services

An automated scanner helps find known patterns, but securing custom agent architectures requires manual review. I work directly with engineering teams on a retainer or fixed-project basis:
* **Advisory Retainer ($2,500 / month):** Monthly architecture review, manual vulnerability discovery, and remediation pull requests written directly for your codebase.
* **Emergency Security Assessment ($5,000 fixed):** 1-week pre-launch code audit or post-incident review with proof-of-concept exploits and remediation guidance.
* **EU AI Act Technical Documentation ($3,500 - $5,000 fixed):** Technical robustness testing and adversarial documentation for European compliance.

**Contact:** adityasecuritylabs@gmail.com | [GitHub Profile](https://github.com/sivaadityacoder)
