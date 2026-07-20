import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.auth import AuthManager

def test_recovery_and_iam():
    print("=== Testing Master Emergency Recovery & IAM Policy ===")
    test_users_file = Path(__file__).resolve().parent / "data" / "users.json"
    test_users_file.parent.mkdir(parents=True, exist_ok=True)
    auth = AuthManager(users_file=test_users_file)
    
    # Test 1: Master Recovery Key Generation
    rec_key = auth.generate_recovery_key()
    assert rec_key.startswith("EASM-RECOVER-"), "Invalid recovery key format"
    print(f"[+] Test 1 Passed: Master Emergency Recovery Key generated: {rec_key}")

    # Test 2: Admin Authorization Verification
    verified = auth.verify_admin_authorization("admin", "Admin@2026Secure!")
    assert verified, "Admin authorization failed for default password"
    print("[+] Test 2 Passed: Admin authorization password verified successfully")

    # Test 3: Flexible IAM Creation with initial password policy (min 8 chars, letter, number, special char)
    auth.delete_user("tempuser1")
    fail1, m1 = auth.create_user("temp1", role="soc_analyst", password="Short1!", must_change_password=True)
    assert not fail1, "Short password should fail"
    
    fail2, m2 = auth.create_user("temp2", role="soc_analyst", password="NoSpecialChar1", must_change_password=True)
    assert not fail2, "Password without special character should fail"

    fail3, m3 = auth.create_user("temp3", role="soc_analyst", password="NoNumberChar!", must_change_password=True)
    assert not fail3, "Password without number should fail"

    ok, m = auth.create_user("tempuser1", role="soc_analyst", password="UserPass@2026", must_change_password=True)
    assert ok, f"Failed to create user with valid 8+ char initial password: {m}"
    user = auth.get_user("tempuser1")
    assert user["must_change_password"] == True, "must_change_password toggle mismatch"
    print(f"[+] Test 3 Passed: Initial password policy enforced (min 8 chars, letter, number, special char) and default checked toggle verified successfully")

    print("\nALL RECOVERY & IAM POLICY TESTS PASSED SUCCESSFULLY!\n")

if __name__ == "__main__":
    test_recovery_and_iam()
