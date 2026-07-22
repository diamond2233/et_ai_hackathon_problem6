"""MongoDB connection lifecycle and index management.

We use Motor (async PyMongo) so database calls never block the event loop while
Gemini requests are in flight.
"""
import logging
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, TEXT
from pymongo.errors import ServerSelectionTimeoutError

from app.core.config import settings

logger = logging.getLogger(__name__)


class Database:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    connected: bool = False


mongo = Database()


def get_db() -> AsyncIOMotorDatabase:
    """FastAPI dependency. Raises early if the DB was never initialised."""
    if mongo.db is None:
        raise RuntimeError("Database not initialised. Did startup run?")
    return mongo.db


async def connect_to_mongo() -> None:
    logger.info("Connecting to MongoDB at %s", settings.MONGODB_URI.split("@")[-1])
    mongo.client = AsyncIOMotorClient(
        settings.MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        uuidRepresentation="standard",
    )
    mongo.db = mongo.client[settings.MONGODB_DB]
    try:
        await mongo.client.admin.command("ping")
        mongo.connected = True
        logger.info("MongoDB connection established")
        await ensure_indexes()
    except ServerSelectionTimeoutError:
        mongo.connected = False
        logger.error("MongoDB unreachable. API will start but data routes will fail.")


async def close_mongo_connection() -> None:
    if mongo.client is not None:
        mongo.client.close()
        mongo.connected = False
        logger.info("MongoDB connection closed")


async def ensure_indexes() -> None:
    """Idempotent. Safe to run on every boot."""
    db = mongo.db

    await db.users.create_index([("email", ASCENDING)], unique=True)

    await db.analyses.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
    await db.analyses.create_index([("threat_type", ASCENDING)])
    await db.analyses.create_index([("risk_score", DESCENDING)])
    await db.analyses.create_index([("created_at", DESCENDING)])
    await db.analyses.create_index([("content_hash", ASCENDING)])

    await db.complaints.create_index([("state", ASCENDING), ("created_at", DESCENDING)])
    await db.complaints.create_index([("scam_type", ASCENDING)])
    await db.complaints.create_index([("status", ASCENDING)])
    await db.complaints.create_index([("complaint_id", ASCENDING)], unique=True)

    await db.hotspots.create_index([("state", ASCENDING)])
    await db.hotspots.create_index([("risk_level", ASCENDING)])

    await db.scam_corpus.create_index([("scam_type", ASCENDING)])
    await db.scam_corpus.create_index([("text", TEXT)])

    await db.conversations.create_index([("user_id", ASCENDING), ("updated_at", DESCENDING)])
    await db.conversations.create_index([("session_id", ASCENDING)], unique=True)

    await db.reports.create_index([("report_id", ASCENDING)], unique=True)
    await db.reports.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])

    logger.info("Indexes ensured")
