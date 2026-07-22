"""Dashboard analytics.

All aggregation happens inside MongoDB rather than in Python. With 500 demo
records either approach is instant, but the pipelines below are the ones that
still work at 5 million records, and writing them now costs nothing.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.data.red_flags import THREAT_LABELS

logger = logging.getLogger(__name__)


async def _count(db: AsyncIOMotorDatabase, coll: str, query: Dict) -> int:
    return await db[coll].count_documents(query)


async def headline_cards(db: AsyncIOMotorDatabase) -> List[Dict[str, Any]]:
    """The four numbers at the top of the dashboard, with 30-day deltas."""
    now = datetime.now(timezone.utc)
    d30 = now - timedelta(days=30)
    d60 = now - timedelta(days=60)

    total = await _count(db, "complaints", {})
    recent = await _count(db, "complaints", {"created_at": {"$gte": d30}})
    prior = await _count(db, "complaints", {"created_at": {"$gte": d60, "$lt": d30}})
    delta = ((recent - prior) / prior * 100) if prior else 0.0

    loss_pipeline = [{"$group": {"_id": None, "total": {"$sum": "$amount_lost"},
                                 "recovered": {"$sum": "$amount_recovered"}}}]
    loss_doc = await db.complaints.aggregate(loss_pipeline).to_list(1)
    total_loss = loss_doc[0]["total"] if loss_doc else 0.0
    recovered = loss_doc[0].get("recovered", 0.0) if loss_doc else 0.0

    da_total = await _count(db, "complaints", {"scam_type": "digital_arrest"})
    da_recent = await _count(db, "complaints",
                             {"scam_type": "digital_arrest", "created_at": {"$gte": d30}})
    da_prior = await _count(db, "complaints",
                            {"scam_type": "digital_arrest",
                             "created_at": {"$gte": d60, "$lt": d30}})
    da_delta = ((da_recent - da_prior) / da_prior * 100) if da_prior else 0.0

    scans = await _count(db, "analyses", {})
    blocked = await _count(db, "analyses", {"risk_score": {"$gte": 60}})

    return [
        {"label": "Total complaints", "value": float(total),
         "delta_pct": round(delta, 1), "unit": ""},
        {"label": "Reported loss", "value": round(total_loss, 2),
         "delta_pct": None, "unit": "INR"},
        {"label": "Digital arrest cases", "value": float(da_total),
         "delta_pct": round(da_delta, 1), "unit": ""},
        {"label": "Threats blocked", "value": float(blocked),
         "delta_pct": None, "unit": f"of {scans} scans"},
    ]


async def scam_type_breakdown(db: AsyncIOMotorDatabase) -> List[Dict[str, Any]]:
    pipeline = [
        {"$group": {"_id": "$scam_type", "count": {"$sum": 1},
                    "amount_lost": {"$sum": "$amount_lost"}}},
        {"$sort": {"count": -1}},
    ]
    rows = await db.complaints.aggregate(pipeline).to_list(50)
    total = sum(r["count"] for r in rows) or 1
    return [
        {
            "scam_type": r["_id"],
            "label": THREAT_LABELS.get(r["_id"], r["_id"].replace("_", " ").title()),
            "count": r["count"],
            "amount_lost": round(r["amount_lost"], 2),
            "share_pct": round(r["count"] / total * 100, 2),
        }
        for r in rows
    ]


async def monthly_trend(db: AsyncIOMotorDatabase, months: int = 12) -> List[Dict[str, Any]]:
    since = datetime.now(timezone.utc) - timedelta(days=months * 31)
    pipeline = [
        {"$match": {"created_at": {"$gte": since}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m", "date": "$created_at"}},
            "complaints": {"$sum": 1},
            "amount_lost": {"$sum": "$amount_lost"},
            "digital_arrest": {
                "$sum": {"$cond": [{"$eq": ["$scam_type", "digital_arrest"]}, 1, 0]}
            },
        }},
        {"$sort": {"_id": 1}},
    ]
    rows = await db.complaints.aggregate(pipeline).to_list(months + 2)
    return [
        {"month": r["_id"], "complaints": r["complaints"],
         "amount_lost": round(r["amount_lost"], 2),
         "digital_arrest": r["digital_arrest"]}
        for r in rows
    ]


async def top_states(db: AsyncIOMotorDatabase, limit: int = 10) -> List[Dict[str, Any]]:
    pipeline = [
        {"$group": {"_id": "$state", "complaints": {"$sum": 1},
                    "amount_lost": {"$sum": "$amount_lost"}}},
        {"$sort": {"complaints": -1}},
        {"$limit": limit},
    ]
    rows = await db.complaints.aggregate(pipeline).to_list(limit)
    out = []
    for r in rows:
        c = r["complaints"]
        level = "critical" if c >= 45 else "high" if c >= 28 else "medium" if c >= 14 else "low"
        out.append({"state": r["_id"], "complaints": c,
                    "amount_lost": round(r["amount_lost"], 2), "risk_level": level})
    return out


async def hotspots(db: AsyncIOMotorDatabase, limit: int = 60) -> List[Dict[str, Any]]:
    cursor = db.hotspots.find({}, {"_id": 0}).sort("complaints", -1).limit(limit)
    return await cursor.to_list(limit)


async def recent_complaints(db: AsyncIOMotorDatabase, limit: int = 8) -> List[Dict[str, Any]]:
    cursor = db.complaints.find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
    rows = await cursor.to_list(limit)
    # Privacy: the dashboard is an operational view, not a victim registry.
    for r in rows:
        if r.get("victim_name"):
            parts = r["victim_name"].split()
            r["victim_name"] = f"{parts[0]} {parts[-1][0]}." if len(parts) > 1 else parts[0]
    return rows


async def risk_distribution(db: AsyncIOMotorDatabase) -> Dict[str, int]:
    pipeline = [
        {"$bucket": {
            "groupBy": "$risk_score",
            "boundaries": [0, 35, 60, 80, 101],
            "default": "other",
            "output": {"count": {"$sum": 1}},
        }}
    ]
    rows = await db.complaints.aggregate(pipeline).to_list(10)
    labels = {0: "safe", 35: "suspicious", 60: "high_risk", 80: "critical"}
    out = {"safe": 0, "suspicious": 0, "high_risk": 0, "critical": 0}
    for r in rows:
        key = labels.get(r["_id"])
        if key:
            out[key] = r["count"]
    return out


async def analysis_activity(db: AsyncIOMotorDatabase, days: int = 14) -> List[Dict[str, Any]]:
    """Live scan volume from the product itself, not the seeded corpus."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"created_at": {"$gte": since}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "scans": {"$sum": 1},
            "threats": {"$sum": {"$cond": [{"$gte": ["$risk_score", 60]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ]
    rows = await db.analyses.aggregate(pipeline).to_list(days + 2)
    return [{"date": r["_id"], "scans": r["scans"], "threats": r["threats"]} for r in rows]


async def build_dashboard(db: AsyncIOMotorDatabase) -> Dict[str, Any]:
    """Single round trip for the whole dashboard."""
    import asyncio

    cards, types, monthly, states, spots, recent, dist = await asyncio.gather(
        headline_cards(db),
        scam_type_breakdown(db),
        monthly_trend(db),
        top_states(db),
        hotspots(db),
        recent_complaints(db),
        risk_distribution(db),
    )
    return {
        "cards": cards,
        "scam_types": types,
        "monthly": monthly,
        "top_states": states,
        "hotspots": spots,
        "recent_complaints": recent,
        "risk_distribution": dist,
        "generated_at": datetime.now(timezone.utc),
    }
