import asyncio
from app.scan.pipeline import ScanPipeline

async def main():
    print("Starting Architecture Verification...")
    
    # Target our mock vulnerable repository
    repo_url = "file:///home/siva/asl-private-research/asl-research-engine/v6/mock_repos/vulnerable-langchain"
    
    pipeline = ScanPipeline()
    result = await pipeline.scan(repo_url=repo_url)
    
    print("\n--- Scan Results ---")
    print(f"Status: {result.status}")
    print(f"Error: {result.error}")
    print(f"AI Frameworks Detected: {result.ai_frameworks_detected}")
    print(f"Layer Timing: {result.layer_timing}")
    
    print(f"\nRaw Findings: {result.raw_finding_count}")
    print(f"Verified Findings: {result.verified_finding_count}")
    
    if result.gauntlet_stats:
        print("\n--- FP Gauntlet Stats ---")
        print(result.gauntlet_stats.to_dict())
        
    print("\n--- Verified Findings Detail ---")
    for f in result.findings:
        print(f"ID: {f.raw.id}")
        print(f"Vulnerability: {f.raw.vulnerability_class} (OWASP: {f.raw.owasp_id})")
        print(f"Severity: {f.raw.severity}")
        print(f"File: {f.raw.file_path}:{f.raw.line_start}")
        print(f"Stages Passed: {f.verification_stages_passed}")
        print("-" * 40)

if __name__ == "__main__":
    asyncio.run(main())
