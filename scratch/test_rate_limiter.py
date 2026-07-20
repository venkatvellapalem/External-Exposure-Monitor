import sys
import os
from pathlib import Path
sys.path.insert(0, os.path.abspath("."))

from core.auth import RateLimiter, AuthManager, _get_fernet_key
from cryptography.fernet import Fernet

def test_security_enhancements():
    print("=== Testing Smart RateLimiter & AES-256 Fernet Vault Encryption ===")

    # Test 1: RateLimiter 5 Failed Attempts Cooldown
    rl = RateLimiter()
    test_ip = "192.168.1.100"

    for i in range(4):
        msg = rl.record_failure(test_ip)
        allowed, check_msg = rl.check_ip(test_ip)
        assert allowed, f"Attempt {i+1} should still be allowed"

    # 5th attempt triggers 10-min cooldown
    msg = rl.record_failure(test_ip)
    allowed, check_msg = rl.check_ip(test_ip)
    assert not allowed, "5th attempt must trigger cooldown block"
    assert "cooling period active" in check_msg, f"Unexpected cooldown message: {check_msg}"
    print("[+] Test 1 Passed: 5 failed attempts triggered 10-minute cooling period")

    # Test 2: Cooldown Violations & Permanent Lockout
    test_ip2 = "10.0.0.99"
    # Violation 1
    for _ in range(5): rl.record_failure(test_ip2)
    # Bypass time check for test and simulate Violation 2
    rl.ip_data[test_ip2]["cooldown_until"] = None
    for _ in range(5): rl.record_failure(test_ip2)
    # Violation 3
    rl.ip_data[test_ip2]["cooldown_until"] = None
    for _ in range(5): rl.record_failure(test_ip2)

    allowed, lock_msg = rl.check_ip(test_ip2)
    assert not allowed and "PERMANENTLY BLOCKED" in lock_msg, "3 cooldown violations must trigger PERMANENT LOCKOUT"
    print("[+] Test 2 Passed: 3 cooldown violations triggered PERMANENT IP LOCKOUT")

    # Test 3: AES-256 Fernet Encrypted Vault Storage
    auth = AuthManager()
    vault_path = Path("data/users.vault")
    assert vault_path.exists(), "data/users.vault file must exist"

    encrypted_bytes = vault_path.read_bytes()
    fernet = Fernet(_get_fernet_key())
    decrypted_str = fernet.decrypt(encrypted_bytes).decode('utf-8')
    assert "admin" in decrypted_str, "Decrypted vault must contain bootstrapped admin user"
    print("[+] Test 3 Passed: AES-256 Fernet Encrypted Vault created and decrypted")

    print("\nALL SECURITY ENHANCEMENT TESTS PASSED!")

if __name__ == "__main__":
    test_security_enhancements()
