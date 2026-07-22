"""Seed MongoDB from the generated dataset.

Run standalone:
    cd backend && python -m app.services.seed
    cd backend && python -m app.services.seed --reset

Idempotent by default: it will not duplicate data if the collections already
hold records. Pass --reset to wipe and reload.
"""
import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.core.config import settings
from app.core.database import close_mongo_connection, connect_to_mongo, mongo
from app.core.security import hash_password

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger("seed")

DATASET_DIR = os.getenv(
    "DATASET_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "..", "dataset"),
)

DEMO_USERS = [
    {"name": "Demo Citizen", "email": "demo@sentinelai.in", "password": "sentinel123",
     "role": "citizen", "state": "Bihar"},
    {"name": "Cyber Cell Analyst", "email": "analyst@sentinelai.in",
     "password": "sentinel123", "role": "analyst", "state": "Maharashtra"},
    {"name": "Bank Fraud Desk", "email": "bank@sentinelai.in", "password": "sentinel123",
     "role": "institution", "state": "Karnataka"},
]


def _load(name: str) -> Any:
    path = os.path.abspath(os.path.join(DATASET_DIR, name))
    if not os.path.exists(path):
        logger.error("Missing %s — run: python scripts/generate_dataset.py", path)
        sys.exit(1)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _parse_dates(rows: List[Dict], fields: List[str]) -> List[Dict]:
    """ISO strings from the JSON dataset become real datetimes for Mongo."""
    for row in rows:
        for f in fields:
            if isinstance(row.get(f), str):
                try:
                    row[f] = datetime.fromisoformat(row[f].replace("Z", "+00:00"))
                except ValueError:
                    row[f] = datetime.now(timezone.utc)
    return rows


async def seed(reset: bool = False) -> None:
    await connect_to_mongo()
    db = mongo.db
    if db is None or not mongo.connected:
        logger.error("Cannot reach MongoDB at %s", settings.MONGODB_URI)
        sys.exit(1)

    collections = ["complaints", "hotspots", "state_stats", "scam_corpus",
                   "statistics", "users"]

    if reset:
        for c in collections:
            await db[c].delete_many({})
        await db.analyses.delete_many({})
        await db.conversations.delete_many({})
        logger.info("Collections reset")

    # -- users -------------------------------------------------------------
    for u in DEMO_USERS:
        existing = await db.users.find_one({"email": u["email"]})
        if existing:
            continue
        await db.users.insert_one({
            "name": u["name"],
            "email": u["email"],
            "password_hash": hash_password(u["password"]),
            "role": u["role"],
            "state": u["state"],
            "phone": None,
            "scans_run": 0,
            "threats_blocked": 0,
            "settings": {
                "language": "en", "theme": "dark", "alert_email": True,
                "alert_sms": False, "auto_report_high_risk": False,
                "share_anonymised_signals": True, "sensitivity": "balanced",
            },
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        })
    logger.info("Demo users ready (%d)", len(DEMO_USERS))

    # -- complaints --------------------------------------------------------
    if await db.complaints.count_documents({}) == 0:
        complaints = _parse_dates(_load("complaints.json"), ["created_at", "updated_at"])
        await db.complaints.insert_many(complaints)
        logger.info("Inserted %d complaints", len(complaints))
    else:
        logger.info("Complaints already present, skipping")

    # -- hotspots ----------------------------------------------------------
    if await db.hotspots.count_documents({}) == 0:
        spots = _load("hotspots.json")
        await db.hotspots.insert_many(spots)
        logger.info("Inserted %d hotspots", len(spots))

    # -- state stats -------------------------------------------------------
    if await db.state_stats.count_documents({}) == 0:
        states = _load("state_stats.json")
        await db.state_stats.insert_many(states)
        logger.info("Inserted %d state records", len(states))

    # -- scam corpus (also feeds the similarity matcher) --------------------
    if await db.scam_corpus.count_documents({}) == 0:
        messages = _parse_dates(_load("scam_messages.json"), ["reported_at"])
        docs = [{
            "message_id": m["id"],
            "text": m["text"],
            "scam_type": m["label"],
            "is_scam": m["is_scam"],
            "channel": m["channel"],
            "language": m["language"],
            "state": m["state"],
            "city": m["city"],
            "expected_risk": m["expected_risk"],
            "reported_at": m["reported_at"],
        } for m in messages]
        await db.scam_corpus.insert_many(docs)
        logger.info("Inserted %d corpus messages", len(docs))

    # -- statistics snapshot -----------------------------------------------
    if await db.statistics.count_documents({}) == 0:
        stats = _load("statistics.json")
        stats["_kind"] = "dataset_snapshot"
        await db.statistics.insert_one(stats)
        logger.info("Inserted statistics snapshot")

    # -- summary -----------------------------------------------------------
    print("\n  Seed complete")
    for c in ["users", "complaints", "hotspots", "state_stats", "scam_corpus"]:
        print(f"    {c:<14} {await db[c].count_documents({}):>6}")
    print("\n  Login with  demo@sentinelai.in / sentinel123\n")

    await close_mongo_connection()


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed the SentinelAI database")
    ap.add_argument("--reset", action="store_true", help="wipe collections first")
    args = ap.parse_args()
    asyncio.run(seed(reset=args.reset))


if __name__ == "__main__":
    main()
