"""Conversational fraud-safety assistant with persistent memory."""
import logging
import re
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import analyse_rate_limit, get_current_user, get_optional_user
from app.core.database import get_db
from app.data.red_flags import RECOMMENDATIONS, THREAT_LABELS
from app.models.schemas import ChatRequest, ChatResponse
from app.services import detector, memory
from app.services.llm import chat_with_llm

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/chat", tags=["AI Assistant"])

# Detection runs on every chat turn — it costs ~1 ms, so there is no reason to
# gate it. This threshold only decides whether the UI treats the turn as a
# "pasted message" and surfaces the risk score chip.
PASTE_THRESHOLD = 90
DETECT_MIN_LENGTH = 20

SUGGESTIONS_DEFAULT = [
    "What is a digital arrest scam?",
    "I got a call saying my parcel had drugs in it",
    "How do I report fraud to 1930?",
    "Is this UPI request safe?",
]

SUGGESTIONS_AFTER_THREAT = [
    "What should I do right now?",
    "How do I file a complaint?",
    "Can I get my money back?",
    "Generate a report I can submit",
]

CRISIS_PATTERNS = re.compile(
    r"(i (have |just )?(sent|transferred|paid|lost)|money (is )?gone|"
    r"they (have|took) my|already paid|i gave (them |him |her )?(the )?otp)",
    re.IGNORECASE,
)


def _fallback_reply(message: str, analysis: Optional[Dict]) -> str:
    """Deterministic assistant used when Gemini is unavailable.

    The product must still be useful to a frightened person at 2 a.m. with a
    dead API key.
    """
    if analysis and analysis["risk_score"] >= 50:
        label = THREAT_LABELS.get(analysis["threat_type"], "fraud")
        recs = analysis.get("recommendations", [])[:4]
        steps = "\n".join(f"{i}. {r}" for i, r in enumerate(recs, 1))
        return (
            f"This looks like **{label}** — risk score {analysis['risk_score']}/100.\n\n"
            f"{analysis['explanation']}\n\n"
            f"**What to do now:**\n{steps}\n\n"
            f"If money has already left your account, call **1930** immediately. "
            f"Transactions reported in the first hour can often still be frozen."
        )

    if CRISIS_PATTERNS.search(message):
        return (
            "Act now, in this order:\n\n"
            "1. Call **1930** (National Cyber Crime Helpline). Do this before anything "
            "else — banks can freeze a transfer that is reported quickly.\n"
            "2. Call your bank and ask them to block the account and raise a "
            "chargeback.\n"
            "3. File at **cybercrime.gov.in** and keep the acknowledgement number.\n"
            "4. Do not delete any messages, call logs or screenshots. They are evidence.\n\n"
            "This is not your fault — these operations are professionally run. "
            "Reporting quickly is the single thing that most affects recovery."
        )

    if analysis and analysis["risk_score"] < 35:
        return (
            "I did not find fraud indicators in that message. It does not match any "
            "campaign in our corpus.\n\nThat said, if it asks you to pay, log in or "
            "share a code, verify it through a number or app you look up yourself "
            "rather than one provided in the message."
        )

    return (
        "Paste the message, email or call transcript you received and I will analyse "
        "it line by line.\n\nThe rules that protect you in almost every case:\n"
        "• No agency in India can place you under 'digital arrest' — the power does "
        "not exist.\n"
        "• No bank or officer will ever ask for an OTP, PIN or CVV.\n"
        "• You never enter a UPI PIN to *receive* money.\n\n"
        "If you have already lost money, call **1930** now."
    )


@router.post("", response_model=ChatResponse, summary="Send a message to the assistant")
async def chat(
    payload: ChatRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Optional[Dict] = Depends(get_optional_user),
    _: None = Depends(analyse_rate_limit),
):
    session_id = payload.session_id or memory.new_session_id()
    user_id = user["id"] if user else None

    history = await memory.get_history(db, session_id, user_id)

    # If it reads like a pasted scam message, analyse it properly and feed the
    # findings to the model instead of letting it free-associate.
    analysis: Optional[Dict] = None
    if len(payload.message) >= DETECT_MIN_LENGTH:
        try:
            analysis = await detector.analyse(
                content=payload.message, channel="unknown",
                language=payload.language, include_llm=False,
            )
        except Exception as exc:
            logger.warning("Inline analysis failed: %s", exc)

    llm_input = payload.message
    if analysis:
        llm_input = (
            f"{payload.message}\n\n"
            f"[SentinelAI detection engine findings — risk {analysis['risk_score']}/100, "
            f"classified as {analysis['threat_type']}, indicators: "
            f"{', '.join(f['label'] for f in analysis['red_flags'][:5]) or 'none'}. "
            f"Use these findings in your reply.]"
        )

    reply = await chat_with_llm(llm_input, history, payload.language)
    llm_used = reply is not None
    if not reply:
        reply = _fallback_reply(payload.message, analysis)

    history_length = await memory.append_turn(
        db, session_id, user_id, payload.message, reply,
        meta={"risk_score": analysis["risk_score"] if analysis else None,
              "llm_used": llm_used},
    )

    high_risk = analysis is not None and analysis["risk_score"] >= 60
    # Only surface the score chip when the user actually pasted a message,
    # rather than on every conversational turn.
    show_score = analysis is not None and len(payload.message) >= PASTE_THRESHOLD
    return {
        "session_id": session_id,
        "reply": reply,
        "suggestions": SUGGESTIONS_AFTER_THREAT if high_risk else SUGGESTIONS_DEFAULT,
        "detected_threat": analysis["threat_type"] if (analysis and high_risk) else None,
        "risk_score": analysis["risk_score"] if show_score else None,
        "llm_used": llm_used,
        "history_length": history_length,
    }


@router.get("/sessions", summary="List the user's conversations")
async def list_sessions(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Dict = Depends(get_current_user),
):
    return {"sessions": await memory.list_sessions(db, user["id"])}


@router.get("/sessions/{session_id}", summary="Fetch a conversation transcript")
async def get_session(
    session_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Dict = Depends(get_current_user),
):
    doc = await db.conversations.find_one({"session_id": session_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if doc.get("user_id") and doc["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="This conversation belongs to another account")

    return {
        "session_id": session_id,
        "title": doc.get("title", "Conversation"),
        "messages": [
            {"role": m["role"], "content": m["content"],
             "created_at": m.get("created_at"), "meta": m.get("meta", {})}
            for m in doc.get("messages", [])
        ],
        "summary": doc.get("summary", ""),
        "updated_at": doc.get("updated_at"),
    }


@router.delete("/sessions/{session_id}", status_code=204, summary="Delete a conversation")
async def delete_session(
    session_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: Dict = Depends(get_current_user),
):
    if not await memory.delete_session(db, session_id, user["id"]):
        raise HTTPException(status_code=404, detail="Conversation not found")
