import os
import re
import json
import io
import base64
import datetime
from pathlib import Path
import bcrypt
import pyotp
import qrcode
import jwt
from core.logger import get_logger

logger = get_logger()

JWT_SECRET = os.getenv("JWT_SECRET", "easm_super_secure_jwt_secret_key_2026_mits")
JWT_ALGORITHM = "HS256"

class AuthManager:
    """Enterprise-grade Auth and IAM Engine supporting RBAC, salted bcrypt hashing, TOTP MFA, and JWT session tokens."""

    def __init__(self, users_file: str = "data/users.json"):
        target_path = Path(users_file)
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            test_file = target_path.parent / ".write_test"
            test_file.touch()
            test_file.unlink()
            self.users_file = target_path
        except (OSError, PermissionError):
            self.users_file = Path("/tmp/data/users.json")
            self.users_file.parent.mkdir(parents=True, exist_ok=True)

        self._ensure_users_file()

    def _ensure_users_file(self):
        """Bootstraps default Root Admin user if database doesn't exist."""
        if not self.users_file.exists():
            self._bootstrap_admin()

    def _bootstrap_admin(self):
        """Creates initial root_admin account: admin / Admin@2026Secure!"""
        admin_pass_hash = self.hash_password("Admin@2026Secure!")
        admin_user = {
            "username": "admin",
            "password_hash": admin_pass_hash,
            "role": "root_admin",
            "must_change_password": True,
            "mfa_enabled": False,
            "mfa_secret": "",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        users_data = {"admin": admin_user}
        self._save_users(users_data)
        logger.info("[+] Bootstrapped initial Root Admin account ('admin')")

    def _load_users(self) -> dict:
        if not self.users_file.exists():
            self._bootstrap_admin()
        try:
            with self.users_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_users(self, data: dict):
        try:
            with self.users_file.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"[!] Failed to save users database: {e}")

    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes plaintext password using salted bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verifies password against stored bcrypt hash."""
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False

    @staticmethod
    def validate_password_complexity(password: str) -> tuple[bool, str]:
        """Enforces 16+ character strong password policy (uppercase, lowercase, number, special char)."""
        if len(password) < 16:
            return False, "Password must be at least 16 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one number."
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
            return False, "Password must contain at least one special character (!@#$%^&*)."
        return True, "Password compliant."

    @staticmethod
    def generate_totp_secret() -> str:
        """Generates a random 32-character base32 secret key for TOTP."""
        return pyotp.random_base32()

    @staticmethod
    def generate_qr_code_base64(username: str, secret: str, org_name: str = "EASM Engine") -> str:
        """Generates a scannable QR code PNG image as a base64 Data URI."""
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name=org_name)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{img_str}"

    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verifies 6-digit TOTP code against secret key."""
        if not secret or not code:
            return False
        totp = pyotp.TOTP(secret)
        # Allow 1 time step drift (30 seconds before/after)
        return totp.verify(code.strip(), valid_window=1)

    @staticmethod
    def create_jwt(username: str, role: str, mfa_verified: bool = False, hours: int = 12) -> str:
        """Creates a signed JWT session token."""
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
        payload = {
            "username": username,
            "role": role,
            "mfa_verified": mfa_verified,
            "exp": exp
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_jwt(token: str) -> dict:
        """Verifies JWT token signature and expiration."""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except Exception:
            return None

    def get_user(self, username: str) -> dict:
        users = self._load_users()
        return users.get(username)

    def list_users(self) -> list:
        users = self._load_users()
        result = []
        for u, d in users.items():
            result.append({
                "username": d.get("username"),
                "role": d.get("role"),
                "mfa_enabled": d.get("mfa_enabled", False),
                "must_change_password": d.get("must_change_password", False),
                "created_at": d.get("created_at")
            })
        return result

    def create_user(self, username: str, role: str = "soc_analyst") -> tuple[bool, str, str]:
        """Creates a new user account with temporary password 'TempPass@2026Secure!' requiring password reset."""
        users = self._load_users()
        if username in users:
            return False, "Username already exists.", ""

        temp_pass = "TempPass@2026Secure!"
        users[username] = {
            "username": username,
            "password_hash": self.hash_password(temp_pass),
            "role": role,
            "must_change_password": True,
            "mfa_enabled": False,
            "mfa_secret": "",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._save_users(users)
        logger.info(f"[+] Created user account '{username}' with role '{role}'")
        return True, f"User {username} created successfully.", temp_pass

    def delete_user(self, username: str) -> tuple[bool, str]:
        if username == "admin":
            return False, "Root Admin account cannot be deleted."
        users = self._load_users()
        if username not in users:
            return False, "User not found."
        del users[username]
        self._save_users(users)
        logger.info(f"[-] Deleted user account '{username}'")
        return True, f"User {username} deleted successfully."

    def update_password(self, username: str, new_password: str) -> tuple[bool, str]:
        valid, msg = self.validate_password_complexity(new_password)
        if not valid:
            return False, msg

        users = self._load_users()
        user = users.get(username)
        if not user:
            return False, "User not found."

        user["password_hash"] = self.hash_password(new_password)
        user["must_change_password"] = False
        users[username] = user
        self._save_users(users)
        logger.info(f"[+] Password updated for user '{username}'")
        return True, "Password updated successfully."

    def save_mfa_secret(self, username: str, secret: str) -> tuple[bool, str]:
        users = self._load_users()
        user = users.get(username)
        if not user:
            return False, "User not found."

        user["mfa_secret"] = secret
        user["mfa_enabled"] = True
        users[username] = user
        self._save_users(users)
        logger.info(f"[+] TOTP MFA enabled for user '{username}'")
        return True, "MFA enabled successfully."
