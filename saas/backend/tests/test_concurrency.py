import asyncio
import time
import httpx
import uuid
from typing import List

BASE_URL = "http://localhost:8000/api/v1"

async def start_scan(client: httpx.AsyncClient, token: str, project_id: str, repo_url: str):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "url": repo_url,
        "github_repo_id": str(uuid.uuid4()),
        "owner": "test",
        "name": "test-repo",
        "full_name": "test/test-repo",
        "clone_url": repo_url
    }
    # Connect repo
    res = await client.post(f"{BASE_URL}/repositories/connect?project_id={project_id}", json=payload, headers=headers)
    if res.status_code != 201:
        return f"Failed to connect repo: {res.text}"
    repo_id = res.json()["id"]
    
    # Start scan
    scan_payload = {
        "repository_id": repo_id,
        "commit_sha": "HEAD",
        "branch": "main"
    }
    res = await client.post(f"{BASE_URL}/scans/", json=scan_payload, headers=headers)
    if res.status_code == 201:
        return res.json()["id"]
    return f"Failed to start scan: {res.text}"

async def main():
    print("--- Starting Concurrency Test ---")
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Register a test user
        email = f"loadtest_{uuid.uuid4().hex[:8]}@example.com"
        password = "LoadTestPassword123!"
        res = await client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": password})
        if res.status_code != 201:
            print(f"Failed to register user: {res.text}")
            return
        
        # Login
        res = await client.post(f"{BASE_URL}/auth/login", json={"email": email, "password": password})
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Create Org and Project
        res = await client.post(f"{BASE_URL}/organizations/", json={"name": "Load Test Org", "slug": f"lt-{uuid.uuid4().hex[:6]}"}, headers=headers)
        org_id = res.json()["id"]
        
        res = await client.post(f"{BASE_URL}/projects/?organization_id={org_id}", json={"name": "Load Test Project", "slug": f"ltp-{uuid.uuid4().hex[:6]}"}, headers=headers)
        if res.status_code != 201:
            print(f"Failed to create project: {res.text}")
            return
        project_id = res.json()["id"]
        
        # Start 5 concurrent scans
        print("Triggering 5 concurrent scans...")
        start_time = time.time()
        
        tasks = []
        for _ in range(5):
            tasks.append(start_scan(client, token, project_id, "https://github.com/expressjs/express"))
            
        results = await asyncio.gather(*tasks)
        print(f"Triggered in {time.time() - start_time:.2f} seconds.")
        print(f"Results: {results}")

if __name__ == "__main__":
    asyncio.run(main())
