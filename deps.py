"""Shared route dependencies: current user resolution and rate limiting."""
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_access_token

bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> Dict:
    """Require a valid token. Raises 401 otherwise."""
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to continue",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(creds.credentials)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session has expired. Sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload["sub"]
    if not ObjectId.is_valid(user_id):
        raise HTTPException(status_code=401, detail="Invalid session")

    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists")

    user["id"] = str(user["_id"])
    return user


async def get_optional_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> Optional[Dict]:
    """Resolve a user if a token is present, but never block the request.

    Analysis is deliberately usable without an account. A person being scammed
    right now should not have to register before getting an answer.
    """
    if creds is None:
        return None
    payload = decode_access_token(creds.credentials)
    if not payload or not payload.get("sub"):
        return None
    user_id = payload["sub"]
    if not ObjectId.is_valid(user_id):
        return None
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        user["id"] = str(user["_id"])
    return user


async def require_analyst(user: Dict = Depends(get_current_user)) -> Dict:
    if user.get("role") not in ("analyst", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This view is restricted to cyber cell analysts",
        )
    return user


# ---------------------------------------------------------------- rate limiter

_HITS: Dict[str, Deque[float]] = defaultdict(deque)


class RateLimiter:
    """Fixed-window in-memory limiter.

    Per-process, so it is approximate behind multiple workers. That is an
    accepted trade-off: it exists to stop a runaway client burning Gemini quota,
    not as a security control. Swap in Redis when you scale horizontally.
    """

    def __init__(self, per_minute: Optional[int] = None) -> None:
        self.limit = per_minute or settings.RATE_LIMIT_PER_MINUTE

    async def __call__(self, request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        auth = request.headers.get("authorization", "")
        key = f"{client}:{auth[-24:]}" if auth else client

        now = time.time()
        window = _HITS[key]
        while window and now - window[0] > 60:
            window.popleft()

        if len(window) >= self.limit:
            retry = int(60 - (now - window[0])) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Try again in {retry} seconds.",
                headers={"Retry-After": str(retry)},
            )
        window.append(now)


rate_limit = RateLimiter()
analyse_rate_limit = RateLimiter(per_minute=settings.ANALYZE_RATE_LIMIT_PER_MINUTE)
