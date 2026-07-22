"""Threat analysis endpoints — the core of the product."""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import analyse_rate_limit, get_current_user, get_optional_user
from app.core.database import get_db
from app.models.schemas import AnalyzeRequest, BulkAnalyzeRequest
from app.services import detector

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["Threat Analysis"])


async def _persist(
    db: AsyncIOMotorDatabase, result: Dict, user: Optional[Dict]
) -> str:
    """Store the analysis and update the user's counters."""
    doc = dict(result)
    doc["user_id"] = user["id"] if user else None
    doc["created_at"] = datetime.now(timezone.utc)
    inserted = await db.analyses.insert_one(doc)

    if user:
        inc = {"scans_run": 1}
        if result["risk_score"] >= 60:
            inc["threats_blocked"] = 1
        await db.users.update_one({"_id": ObjectId(user["id"])}, {"$inc": inc})

    return str(inserted.inserted_id)


@router.post("", summary="Analyse a message for fraud indicators")
async def analyze_message(
    payload: AnalyzeRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Optional[Dict] = Depends(get_optional_user),
    _: None = Depends(analyse_rate_limit),
):
    """Run the four-layer fusion pipeline over a single message.

    Authentication is optional by design. Someone in the middle of a scam call
    should get an answer without being asked to sign up first.
    """
    try:
        result = await detector.analyse(
            content=payload.content,
            channel=payload.channel.value,
            sender=payload.sender,
            language=payload.language,
            include_llm=payload.include_llm,
        )
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")

    analysis_id = await _persist(db, result, user)
    result["id"] = analysis_id
    return result


@router.post("/bulk", summary="Analyse up to 25 messages at once")
async def analyze_bulk(
    payload: BulkAnalyzeRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Optional[Dict] = Depends(get_optional_user),
    _: None = Depends(analyse_rate_limit),
):
    """Used by institutions triaging a batch, and by our own benchmark harness.

    The LLM layer is forced off above 10 items: 25 sequential Gemini calls would
    blow the request timeout, and the deterministic layers already carry the
    detection.
    """
    force_deterministic = len(payload.items) > 10

    async def run(item: AnalyzeRequest) -> Dict:
        return await detector.analyse(
            content=item.content,
            channel=item.channel.value,
            sender=item.sender,
            language=item.language,
            include_llm=item.include_llm and not force_deterministic,
        )

    results = await asyncio.gather(*[run(i) for i in payload.items],
                                   return_exceptions=True)

    out: List[Dict] = []
    for item, res in zip(payload.items, results):
        if isinstance(res, Exception):
            logger.error("Bulk item failed: %s", res)
            out.append({"error": str(res), "content_preview": item.content[:80]})
            continue
        res["id"] = await _persist(db, res, user)
        out.append(res)

    scored = [r for r in out if "risk_score" in r]
    return {
        "count": len(out),
        "deterministic_only": force_deterministic,
        "summary": {
            "critical": sum(1 for r in scored if r["risk_score"] >= 80),
            "high_risk": sum(1 for r in scored if 60 <= r["risk_score"] < 80),
            "suspicious": sum(1 for r in scored if 35 <= r["risk_score"] < 60),
            "safe": sum(1 for r in scored if r["risk_score"] < 35),
        },
        "results": out,
    }


@router.get("/history", summary="List the signed-in user's past analyses")
async def history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    threat_type: Optional[str] = None,
    min_risk: Optional[int] = Query(None, ge=0, le=100),
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Dict = Depends(get_current_user),
):
    query: Dict = {"user_id": user["id"]}
    if threat_type:
        query["threat_type"] = threat_type
    if min_risk is not None:
        query["risk_score"] = {"$gte": min_risk}

    total = await db.analyses.count_documents(query)
    cursor = (
        db.analyses.find(query)
        .sort("created_at", -1)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )

    items = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        items.append(doc)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/stats", summary="Aggregate stats for the signed-in user")
async def user_stats(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Dict = Depends(get_current_user),
):
    pipeline = [
        {"$match": {"user_id": user["id"]}},
        {"$group": {
            "_id": "$threat_type",
            "count": {"$sum": 1},
            "avg_risk": {"$avg": "$risk_score"},
        }},
        {"$sort": {"count": -1}},
    ]
    by_type = await db.analyses.aggregate(pipeline).to_list(30)

    total = await db.analyses.count_documents({"user_id": user["id"]})
    blocked = await db.analyses.count_documents(
        {"user_id": user["id"], "risk_score": {"$gte": 60}}
    )

    return {
        "total_scans": total,
        "threats_blocked": blocked,
        "safe_rate_pct": round((total - blocked) / total * 100, 1) if total else 0.0,
        "by_threat_type": [
            {"threat_type": r["_id"], "count": r["count"],
             "avg_risk": round(r["avg_risk"], 1)}
            for r in by_type
        ],
    }


@router.get("/{analysis_id}", summary="Fetch one analysis by ID")
async def get_analysis(
    analysis_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Optional[Dict] = Depends(get_optional_user),
):
    if not ObjectId.is_valid(analysis_id):
        raise HTTPException(status_code=400, detail="Malformed analysis ID")

    doc = await db.analyses.find_one({"_id": ObjectId(analysis_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # An analysis created while signed in stays private to that account.
    if doc.get("user_id") and (not user or user["id"] != doc["user_id"]):
        raise HTTPException(status_code=403, detail="This analysis belongs to another account")

    doc["id"] = str(doc.pop("_id"))
    return doc
