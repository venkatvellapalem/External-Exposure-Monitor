import sys
import os
sys.path.insert(0, os.path.abspath("."))

from core.auth import AuthManager

def test_phase1():
    print("=== Testing AuthManager Core Engine ===")
    auth = AuthManager()

    # Test 1: Admin User Loading
    admin = auth.get_user("admin")
    assert admin is not None, "Admin user should be bootstrapped"
    print("[+] Test 1 Passed: Admin account bootstrapped cleanly")

    # Test 2: Password Verification
    assert auth.verify_password("Admin@2026Secure!", admin["password_hash"]), "Default admin password verification failed"
    print("[+] Test 2 Passed: Bcrypt password verification succeeded")

    # Test 3: Password Complexity Validator
    weak_pass = "Short123!"
    valid, msg = auth.validate_password_complexity(weak_pass)
    assert not valid, "Weak password should be rejected"

    strong_pass = "SuperSecurePassword2026!@#"
    valid, msg = auth.validate_password_complexity(strong_pass)
    assert valid, f"Strong password should be accepted: {msg}"
    print("[+] Test 3 Passed: 16+ character strong password policy enforced")

    # Test 4: TOTP Secret & QR Code Generation
    secret = auth.generate_totp_secret()
    assert len(secret) == 32, "TOTP secret length should be 32 base32 chars"

    qr_uri = auth.generate_qr_code_base64("admin", secret)
    assert qr_uri.startswith("data:image/svg+xml;base64,"), "QR Code Data URI should start with SVG image prefix"
    print("[+] Test 4 Passed: PyOTP TOTP Secret & Base64 QR Code generated")

    # Test 5: JWT Token Engine
    token = auth.create_jwt("admin", "root_admin", mfa_verified=True)
    payload = auth.verify_jwt(token)
    assert payload is not None, "JWT token verification failed"
    assert payload["username"] == "admin" and payload["role"] == "root_admin", "JWT payload mismatch"
    print("[+] Test 5 Passed: JWT session token created and verified")

    print("\nALL PHASE 1 CORE AUTH TESTS PASSED!")

if __name__ == "__main__":
    test_phase1()
