import requests
import json
import uuid

BASE_URL = "http://localhost:8000/api/v1"

def print_result(name, result, detail=""):
    status = "✅ PASS" if result else "❌ FAIL"
    print(f"{status} | {name} | {detail}")

def test_registration():
    print("\n--- Testing Registration ---")
    
    # 1. Valid Registration
    test_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": test_email,
        "password": "StrongPassword123!",
        "full_name": "Gauntlet Test User"
    }
    res = requests.post(f"{BASE_URL}/auth/register", json=payload)
    if res.status_code == 201:
        print_result("Valid Registration", True)
    else:
        print_result("Valid Registration", False, res.text)
        return False
        
    # 2. Duplicate Registration
    res_dup = requests.post(f"{BASE_URL}/auth/register", json=payload)
    if res_dup.status_code == 400:
        print_result("Duplicate Registration", True, "Correctly rejected")
    else:
        print_result("Duplicate Registration", False, f"Expected 400, got {res_dup.status_code}. Response: {res_dup.text}")
        
    # 3. Invalid Email Format
    payload_invalid_email = {
        "email": "not-an-email",
        "password": "StrongPassword123!",
        "full_name": "Invalid Email"
    }
    res_inv = requests.post(f"{BASE_URL}/auth/register", json=payload_invalid_email)
    if res_inv.status_code == 422:
        print_result("Invalid Email Registration", True, "Correctly rejected")
    else:
        print_result("Invalid Email Registration", False, f"Expected 422, got {res_inv.status_code}. Response: {res_inv.text}")

    # 4. Weak Password
    payload_weak_pass = {
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "123",
        "full_name": "Weak Pass User"
    }
    res_weak = requests.post(f"{BASE_URL}/auth/register", json=payload_weak_pass)
    # The API might not have strict password validation yet
    if res_weak.status_code == 422 or res_weak.status_code == 400:
         print_result("Weak Password Registration", True, "Correctly rejected")
    else:
         print_result("Weak Password Registration", False, f"Accepted weak password! Status: {res_weak.status_code}")

    return test_email

def test_login(email):
    print("\n--- Testing Login ---")
    # 1. Valid Login
    payload = {
        "email": email,
        "password": "StrongPassword123!"
    }
    res = requests.post(f"{BASE_URL}/auth/login", json=payload)
    if res.status_code == 200:
        print_result("Valid Login", True)
        return res.json().get("access_token")
    else:
        print_result("Valid Login", False, res.text)
        return None

    # 2. Invalid Login
    payload_invalid = {
        "email": email,
        "password": "WrongPassword!"
    }
    res_inv = requests.post(f"{BASE_URL}/auth/login", json=payload_invalid)
    if res_inv.status_code in [400, 401]:
        print_result("Invalid Login", True, "Correctly rejected")
    else:
        print_result("Invalid Login", False, f"Expected 401, got {res_inv.status_code}")

def test_sql_injection_login():
    print("\n--- Testing SQL Injection on Auth ---")
    payload_sqli = {
        "email": "' OR '1'='1",
        "password": "' OR '1'='1"
    }
    res = requests.post(f"{BASE_URL}/auth/login", json=payload_sqli)
    if res.status_code in [400, 401, 404, 422]:
        print_result("SQL Injection Auth", True, f"Blocked. Status: {res.status_code}")
    else:
        print_result("SQL Injection Auth", False, f"Potentially vulnerable! Status: {res.status_code}")

if __name__ == "__main__":
    email = test_registration()
    if email:
        token = test_login(email)
    test_sql_injection_login()
