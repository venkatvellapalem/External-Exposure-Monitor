import sys
import os
import pyotp
sys.path.insert(0, os.path.abspath("."))

from api.index import app, auth_manager

def test_phase2():
    print("=== Testing Phase 2 Auth & IAM API Routes ===")
    client = app.test_client()

    # Test 1: Step 1 Login
    res = client.post('/api/auth/login', json={
        "username": "admin",
        "password": "Admin@2026Secure!"
    })
    data = res.get_json()
    assert res.status_code == 200 and data["success"], "Step 1 Login failed"
    assert data["must_change_password"], "Bootstrapped admin must require password change"
    print("[+] Test 1 Passed: Step 1 Login verified credentials")

    # Test 2: MFA Setup
    res = client.post('/api/auth/mfa-setup', json={"username": "admin"})
    data = res.get_json()
    assert res.status_code == 200 and data["success"], "MFA Setup failed"
    secret = data["secret"]
    assert len(secret) == 32 and data["qr_code_uri"].startswith("data:image/svg+xml;base64,"), "Invalid MFA Setup payload"
    print("[+] Test 2 Passed: MFA Setup generated secret & QR code")

    # Test 3: MFA Verification & Session Cookie
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    res = client.post('/api/auth/mfa-verify', json={
        "username": "admin",
        "code": valid_code,
        "secret": secret
    })
    data = res.get_json()
    assert res.status_code == 200 and data["success"], f"MFA Verification failed: {data.get('message')}"
    print("[+] Test 3 Passed: Step 2 MFA Verification issued session cookie")

    # Test 4: Auth Me (/api/auth/me)
    res = client.get('/api/auth/me')
    data = res.get_json()
    assert data.get("authenticated") and data.get("username") == "admin", "Session authentication check failed"
    print("[+] Test 4 Passed: GET /api/auth/me returned authenticated user context")

    # Test 5: IAM User Management (/api/iam/users)
    auth_manager.delete_user("analyst1")
    res = client.post('/api/iam/users', json={
        "username": "analyst1",
        "role": "soc_analyst",
        "password": "Analyst1Pass@2026!",
        "confirm_password": "Analyst1Pass@2026!",
        "admin_password": "Admin@2026Secure!"
    })
    data = res.get_json()
    assert res.status_code == 200 and data["success"], f"Failed to create user in IAM: {data.get('message')}"
    print("[+] Test 5 Passed: Root Admin authorized and created SOC Analyst user 'analyst1'")

    # Test 6: Splunk SSO Redirect Route (/api/auth/splunk-sso)
    res = client.get('/api/auth/splunk-sso')
    assert res.status_code in [302, 303], "Splunk SSO route should issue redirect"
    assert "13.205.90.142:8000" in res.location, f"Invalid Splunk SSO redirect URL: {res.location}"
    print("[+] Test 6 Passed: Splunk SSO redirect ticket engine operational")

    print("\nALL PHASE 2 API & IAM TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_phase2()
