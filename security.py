"""Password hashing and JWT handling."""
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings

# We call bcrypt directly rather than going through passlib.
#
# passlib 1.7.4 is incompatible with bcrypt >= 4.1: on first use it runs an
# internal capability probe that feeds an over-length password to bcrypt, and
# modern bcrypt raises ValueError instead of silently truncating. The result is
# a hard 500 on every registration. passlib is effectively unmaintained, and
# bcrypt's own API is small enough that the abstraction was buying us nothing.
BCRYPT_ROUNDS = 12
BCRYPT_MAX_BYTES = 72


def _truncate(plain: str) -> bytes:
    """bcrypt operates on at most 72 bytes. Truncate on a byte boundary that
    does not split a multi-byte character, so non-ASCII passwords still work."""
    raw = plain.encode("utf-8")
    if len(raw) <= BCRYPT_MAX_BYTES:
        return raw
    return raw[:BCRYPT_MAX_BYTES].decode("utf-8", errors="ignore").encode("utf-8")


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_truncate(plain), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_truncate(plain), hashed.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(
    subject: str, extra: Optional[Dict[str, Any]] = None, expires_minutes: Optional[int] = None
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload: Dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": settings.APP_NAME,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


def content_fingerprint(text: str) -> str:
    """SHA-256 of the analysed content.

    Two uses: de-duplicating repeat submissions, and giving every generated
    report a verifiable link back to the exact bytes that were analysed.
    """
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
