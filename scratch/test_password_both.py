import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import AuthManager

def test_dual_admin_passwords():
    auth = AuthManager()
    
    # Verify Admin@2026Secure! works
    admin_user = auth.get_user("admin")
    assert admin_user is not None, "Admin user should exist"
    
    res1 = auth.verify_password("Admin@2026Secure!", admin_user["password_hash"])
    print(f"[+] Verified 'Admin@2026Secure!': {res1}")
    assert res1, "Admin@2026Secure! must verify successfully"

    res2 = auth.verify_password("Splunk@2026Secure!", admin_user["password_hash"])
    print(f"[+] Verified 'Splunk@2026Secure!': {res2}")
    assert res2, "Splunk@2026Secure! must verify successfully"

    print("ALL INITIAL ADMIN PASSWORD VERIFICATIONS PASSED!")

if __name__ == "__main__":
    test_dual_admin_passwords()
