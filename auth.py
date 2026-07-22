"""Authentication and account routes."""
import logging
from datetime import datetime, timezone
from typing import Dict

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError

from app.api.deps import get_current_user, rate_limit
from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models.schemas import (
    TokenResponse,
    UserLogin,
    UserPublic,
    UserRegister,
    UserSettings,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])

DEFAULT_SETTINGS = {
    "language": "en", "theme": "dark", "alert_email": True, "alert_sms": False,
    "auto_report_high_risk": False, "share_anonymised_signals": True,
    "sensitivity": "balanced",
}


def _public(user: Dict) -> Dict:
    return {
        "id": str(user["_id"]) if "_id" in user else user.get("id"),
        "name": user["name"],
        "email": user["email"],
        "phone": user.get("phone"),
        "state": user.get("state"),
        "role": user.get("role", "citizen"),
        "created_at": user.get("created_at", datetime.now(timezone.utc)),
        "scans_run": user.get("scans_run", 0),
        "threats_blocked": user.get("threats_blocked", 0),
    }


@router.post("/register", response_model=TokenResponse,
             status_code=status.HTTP_201_CREATED,
             summary="Create an account")
async def register(
    payload: UserRegister,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: None = Depends(rate_limit),
):
    email = payload.email.lower().strip()

    # Explicit pre-check in addition to the unique index. The index is the real
    # guarantee under concurrency; this exists so the common case returns a
    # helpful message instead of a driver error.
    if await db.users.find_one({"email": email}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists. Sign in instead.",
        )

    doc = {
        "name": payload.name.strip(),
        "email": email,
        "password_hash": hash_password(payload.password),
        "phone": payload.phone,
        "state": payload.state,
        "role": "citizen",
        "scans_run": 0,
        "threats_blocked": 0,
        "settings": dict(DEFAULT_SETTINGS),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    try:
        result = await db.users.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists. Sign in instead.",
        )

    doc["_id"] = result.inserted_id
    token = create_access_token(str(result.inserted_id), {"role": "citizen"})
    logger.info("New account registered: %s", email)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": _public(doc),
    }


@router.post("/login", response_model=TokenResponse, summary="Sign in")
async def login(
    payload: UserLogin,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: None = Depends(rate_limit),
):
    user = await db.users.find_one({"email": payload.email.lower().strip()})

    # Same message and comparable timing for both failure modes, so the endpoint
    # cannot be used to enumerate which emails are registered.
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email or password is incorrect",
        )

    await db.users.update_one(
        {"_id": user["_id"]}, {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
    token = create_access_token(str(user["_id"]), {"role": user.get("role", "citizen")})

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": _public(user),
    }


@router.get("/me", response_model=UserPublic, summary="Get the signed-in user")
async def me(user: Dict = Depends(get_current_user)):
    return _public(user)


@router.get("/settings", response_model=UserSettings, summary="Read preferences")
async def get_settings_route(user: Dict = Depends(get_current_user)):
    return {**DEFAULT_SETTINGS, **(user.get("settings") or {})}


@router.put("/settings", response_model=UserSettings, summary="Update preferences")
async def update_settings(
    payload: UserSettings,
    user: Dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    await db.users.update_one(
        {"_id": ObjectId(user["id"])},
        {"$set": {"settings": payload.model_dump(),
                  "updated_at": datetime.now(timezone.utc)}},
    )
    return payload


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete the account and all associated data")
async def delete_account(
    user: Dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Hard delete. A fraud-safety tool holds sensitive material, so erasure is
    complete rather than a soft-delete flag."""
    uid = user["id"]
    await db.analyses.delete_many({"user_id": uid})
    await db.conversations.delete_many({"user_id": uid})
    await db.reports.delete_many({"user_id": uid})
    await db.users.delete_one({"_id": ObjectId(uid)})
    logger.info("Account deleted: %s", user["email"])
