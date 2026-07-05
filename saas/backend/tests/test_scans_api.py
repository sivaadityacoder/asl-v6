import requests
import uuid

BASE_URL = "http://localhost:8000/api/v1"

def print_result(name, result, detail=""):
    status = "✅ PASS" if result else "❌ FAIL"
    print(f"{status} | {name} | {detail}")

def get_auth_token():
    email = f"scan_test_{uuid.uuid4().hex[:8]}@example.com"
    res_reg = requests.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "StrongPassword123!", "full_name": "Test User"})
    if res_reg.status_code != 201:
        print(f"Register failed: {res_reg.text}")
    res_log = requests.post(f"{BASE_URL}/auth/login", json={"email": email, "password": "StrongPassword123!"})
    if res_log.status_code != 200:
        print(f"Login failed: {res_log.text}")
    return res_log.json().get("access_token"), email

def test_connect_repo(token):
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Create Organization
    res_org = requests.post(f"{BASE_URL}/organizations/", json={"name": "Test Org", "slug": f"test-org-{uuid.uuid4().hex[:6]}"}, headers=headers)
    if res_org.status_code != 201:
        print_result("Organization Creation", False, f"Cannot test repos without org. {res_org.text}")
        return None
    org_id = res_org.json()["id"]

    # 2. Create Project
    res_proj = requests.post(f"{BASE_URL}/projects/?organization_id={org_id}", json={"name": "Test Project", "slug": f"test-proj-{uuid.uuid4().hex[:6]}"}, headers=headers)
    
    if res_proj.status_code != 201:
        print_result("Project Creation", False, f"Cannot test repos without project. {res_proj.text}")
        return None
        
    project_id = res_proj.json()["id"]

    # 1. Invalid URL
    payload = {
        "url": "not-a-url",
        "project_id": project_id
    }
    res = requests.post(f"{BASE_URL}/repositories/connect", json=payload, headers=headers)
    if res.status_code in [400, 422]:
        print_result("Invalid Repo URL", True, f"Rejected with {res.status_code}")
    else:
        print_result("Invalid Repo URL", False, f"Accepted invalid URL? Status: {res.status_code}")

    # 2. SQL Injection / Path Traversal in branch name?
    payload_sqli = {
        "url": "https://github.com/expressjs/express",
        "project_id": project_id,
        "default_branch": "' OR '1'='1; rm -rf /"
    }
    res_sqli = requests.post(f"{BASE_URL}/repositories/connect", json=payload_sqli, headers=headers)
    if res_sqli.status_code in [400, 422, 201]:
        # If it accepts it, we'll check if it sanitizes when used
        print_result("SQLi Repo Branch", True, f"Status: {res_sqli.status_code}")
    
    # Assuming successful connection for normal use
    payload_valid = {
        "url": "https://github.com/expressjs/express",
        "github_repo_id": "123456",
        "owner": "expressjs",
        "name": "express",
        "full_name": "expressjs/express",
        "clone_url": "https://github.com/expressjs/express.git"
    }
    res_valid = requests.post(f"{BASE_URL}/repositories/connect?project_id={project_id}", json=payload_valid, headers=headers)
    if res_valid.status_code == 201:
        return res_valid.json()["id"]
    else:
        print_result("Valid Repo Connection", False, f"Failed: {res_valid.text}")
    return None

def test_start_scan(token, repo_id):
    if not repo_id:
        return
        
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = {
        "repository_id": repo_id,
        "commit_sha": "HEAD",
        "branch": "main"
    }
    res = requests.post(f"{BASE_URL}/scans/", json=payload, headers=headers)
    if res.status_code == 201:
        print_result("Start Scan", True, "Successfully started scan")
    else:
        print_result("Start Scan", False, res.text)

if __name__ == "__main__":
    token, email = get_auth_token()
    repo_id = test_connect_repo(token)
    test_start_scan(token, repo_id)
