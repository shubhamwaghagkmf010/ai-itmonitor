import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Union, Optional
import jwt
import bcrypt
from backend.app.core.config import settings


def secure_equals(supplied: Optional[str], expected: str) -> bool:
    """Compares a secret sent by a client with the real one in constant time. A plain `==` stops at
    the first different character, so the time a rejection takes tells an attacker how much of a
    guess was right."""
    if supplied is None:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_BYTES = 72  # bcrypt ignores (or, in newer versions, rejects) anything past this

_COMMON_PASSWORDS = {
    "password", "password1", "password12", "password123", "passw0rd", "p@ssw0rd", "p@ssword",
    "qwerty", "qwertyuiop", "qwerty123", "letmein", "welcome", "welcome1", "welcome123",
    "admin", "admin123", "administrator", "changeme", "change_me", "iloveyou", "monkey", "dragon",
    "abc123", "abcdefghij", "1234567890", "0123456789", "1q2w3e4r5t", "123456789", "12345678",
    "ai-itmonitor", "aiitmonitor", "itmonitor", "changeme#admin1", "changeme#eng1",
}


def check_password_policy(password: str, email: Optional[str] = None) -> Optional[str]:
    """Returns why a new password is not acceptable, or None if it is. Length and an avoid-the-obvious
    list matter far more than composition rules, so those are what is enforced."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes long."
    lowered = password.strip().lower()
    if lowered in _COMMON_PASSWORDS or ("password" in lowered and len(set(lowered)) < 12):
        return "That password is too common; choose something less guessable."
    if len(set(password)) < 5:
        return "Password uses too few different characters."
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            return "Password must not contain your user name."
    return None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies plaintext password against a stored bcrypt hash. Anything unusable (a password
    longer than bcrypt accepts, a damaged stored hash) is simply a failed login, not a server error."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    """Generates a secure bcrypt hash string from plaintext."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None,
                        token_version: int = 0) -> str:
    """Generates an encoded JWT access token with expiration. `tv` is the user's token version at the
    time of issue; raising the version on the user (password change, disable, "log out everywhere")
    makes every older token fail."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "sub": str(subject),
        "tv": int(token_version or 0),
    }
    encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt
