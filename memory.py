"""Conversation memory backed by MongoDB.

LangChain's in-process memory classes die with the worker. Since we run multiple
uvicorn workers behind a load balancer, memory has to live in the database or a
user's second message lands on a worker that has never seen them.

We keep a rolling window of MAX_TURNS and a running summary of everything older,
so a long conversation stays inside the token budget without losing context.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

MAX_TURNS = 24          # messages kept verbatim
SUMMARISE_AFTER = 30    # trigger point for compaction


def new_session_id() -> str:
    return f"sess_{uuid.uuid4().hex[:16]}"


def _title_from(message: str) -> str:
    clean = " ".join(message.strip().split())
    return (clean[:52] + "…") if len(clean) > 52 else clean or "New conversation"


async def get_history(
    db: AsyncIOMotorDatabase, session_id: str, user_id: Optional[str]
) -> List[Dict[str, str]]:
    doc = await db.conversations.find_one({"session_id": session_id})
    if not doc:
        return []
    if user_id and doc.get("user_id") and doc["user_id"] != user_id:
        logger.warning("Session %s requested by non-owner", session_id)
        return []

    history: List[Dict[str, str]] = []
    if doc.get("summary"):
        history.append({
            "role": "assistant",
            "content": f"[Earlier context] {doc['summary']}",
        })
    history.extend(
        {"role": m["role"], "content": m["content"]} for m in doc.get("messages", [])
    )
    return history


async def append_turn(
    db: AsyncIOMotorDatabase,
    session_id: str,
    user_id: Optional[str],
    user_message: str,
    assistant_message: str,
    meta: Optional[Dict] = None,
) -> int:
    now = datetime.now(timezone.utc)
    turns = [
        {"role": "user", "content": user_message, "created_at": now, "meta": {}},
        {"role": "assistant", "content": assistant_message, "created_at": now,
         "meta": meta or {}},
    ]

    existing = await db.conversations.find_one({"session_id": session_id})
    if existing is None:
        await db.conversations.insert_one({
            "session_id": session_id,
            "user_id": user_id,
            "title": _title_from(user_message),
            "messages": turns,
            "summary": "",
            "created_at": now,
            "updated_at": now,
        })
        return len(turns)

    await db.conversations.update_one(
        {"session_id": session_id},
        {"$push": {"messages": {"$each": turns}}, "$set": {"updated_at": now}},
    )

    doc = await db.conversations.find_one({"session_id": session_id})
    messages = doc.get("messages", [])
    if len(messages) > SUMMARISE_AFTER:
        await _compact(db, session_id, doc)
        doc = await db.conversations.find_one({"session_id": session_id})
        messages = doc.get("messages", [])
    return len(messages)


async def _compact(db: AsyncIOMotorDatabase, session_id: str, doc: Dict) -> None:
    """Fold the oldest turns into a text summary to bound the context window."""
    messages = doc.get("messages", [])
    overflow = messages[:-MAX_TURNS]
    kept = messages[-MAX_TURNS:]
    if not overflow:
        return

    lines = [f"{m['role']}: {m['content'][:200]}" for m in overflow]
    prior = doc.get("summary", "")
    summary = (prior + " " if prior else "") + " | ".join(lines)
    summary = summary[-2500:]

    await db.conversations.update_one(
        {"session_id": session_id},
        {"$set": {"messages": kept, "summary": summary}},
    )
    logger.info("Compacted session %s: %d turns folded", session_id, len(overflow))


async def list_sessions(
    db: AsyncIOMotorDatabase, user_id: str, limit: int = 30
) -> List[Dict]:
    cursor = (
        db.conversations.find({"user_id": user_id})
        .sort("updated_at", -1)
        .limit(limit)
    )
    out = []
    async for doc in cursor:
        out.append({
            "session_id": doc["session_id"],
            "title": doc.get("title", "Conversation"),
            "message_count": len(doc.get("messages", [])),
            "updated_at": doc.get("updated_at"),
        })
    return out


async def delete_session(
    db: AsyncIOMotorDatabase, session_id: str, user_id: str
) -> bool:
    result = await db.conversations.delete_one(
        {"session_id": session_id, "user_id": user_id}
    )
    return result.deleted_count > 0
