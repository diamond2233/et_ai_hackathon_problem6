"""The fusion engine — orchestrates all four detection layers into one verdict.

Pipeline:
    L1 rules (40%)  ->  L2 campaign similarity (25%)  ->  L3 structural (15%)
                    ->  L4 Gemini reasoning (20%)  ->  weighted fusion

If L4 is unavailable its weight is redistributed proportionally across L1-L3, so
the score stays on the same 0-100 scale instead of silently capping at 80.
"""
import logging
import time
from typing import Any, Dict, Optional

from app.core.config import settings
from app.core.security import content_fingerprint
from app.data.red_flags import RECOMMENDATIONS, THREAT_LABELS
from app.services import rules as rule_engine
from app.services.llm import analyse_with_llm
from app.services.similarity import matcher

logger = logging.getLogger(__name__)


def _verdict_from_score(score: float) -> str:
    if score >= settings.RISK_THRESHOLD_CRITICAL:
        return "critical"
    if score >= settings.RISK_THRESHOLD_HIGH:
        return "high_risk"
    if score >= settings.RISK_THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "likely_safe"


def _compute_confidence(
    rule_flags: list, similarity: float, llm_result: Optional[Dict], text_len: int
) -> int:
    """How much we trust our own verdict.

    Deliberately separate from risk. A short message with one weak flag is
    low-confidence even if the risk score is mid-range — and we say so rather
    than projecting false certainty at a frightened user.
    """
    confidence = 42.0

    high_sev = [f for f in rule_flags if f["severity"] >= 4]
    confidence += min(28.0, len(high_sev) * 11.0)
    confidence += min(10.0, len(rule_flags) * 2.0)

    if similarity >= 0.70:
        confidence += 20
    elif similarity >= 0.50:
        confidence += 13
    elif similarity >= 0.30:
        confidence += 6

    if llm_result:
        confidence += 8
        # Agreement between independent layers is the strongest confidence signal.
        llm_conf = llm_result.get("confidence", 60)
        confidence += (llm_conf - 60) * 0.15

    if text_len < 40:
        confidence -= 18
    elif text_len < 90:
        confidence -= 8

    return int(max(20, min(97, confidence)))


async def analyse(
    content: str,
    channel: str = "unknown",
    sender: Optional[str] = None,
    language: str = "en",
    include_llm: bool = True,
) -> Dict[str, Any]:
    """Run the full pipeline and return a complete AnalysisResult payload."""
    started = time.perf_counter()

    # ---- L1: deterministic rules ----------------------------------------
    rule_flags, rule_score, threat_votes = rule_engine.run_rules(content)
    safe_signals, suppression = rule_engine.find_safe_signals(content)

    # ---- L2: campaign fingerprint ---------------------------------------
    campaign, similarity = matcher.best(content)
    campaign_name = campaign["name"] if campaign else None
    campaign_threat = campaign["threat"] if campaign else None

    # A strong match to a *safe* template is evidence of safety, not of threat.
    if campaign_threat == "safe" and similarity >= 0.45:
        similarity_score_component = 0.0
    else:
        similarity_score_component = similarity * 100.0

    # ---- L3: structural signals -----------------------------------------
    structural_score, structural_notes = rule_engine.structural_signals(
        content, channel, sender
    )

    # ---- L4: LLM reasoning ----------------------------------------------
    llm_result = None
    if include_llm:
        llm_result = await analyse_with_llm(
            content=content,
            channel=channel,
            rule_flags=rule_flags,
            rule_score=rule_score,
            campaign_name=campaign_name,
            similarity=similarity,
            structural_notes=structural_notes,
        )

    llm_score = float(llm_result["llm_risk"]) if llm_result else 0.0

    # ---- Weighted fusion -------------------------------------------------
    w = {
        "rules": settings.WEIGHT_RULES,
        "similarity": settings.WEIGHT_SIMILARITY,
        "structural": settings.WEIGHT_STRUCTURAL,
        "llm": settings.WEIGHT_LLM,
    }
    if llm_result is None:
        # Redistribute the LLM weight rather than letting the ceiling drop.
        base = w["rules"] + w["similarity"] + w["structural"]
        factor = 1.0 / base
        w = {"rules": w["rules"] * factor, "similarity": w["similarity"] * factor,
             "structural": w["structural"] * factor, "llm": 0.0}

    final = (
        rule_score * w["rules"]
        + similarity_score_component * w["similarity"]
        + structural_score * w["structural"]
        + llm_score * w["llm"]
    )

    # Suppression. Applied after fusion so it can pull down a score that every
    # layer inflated for the same superficial reason (e.g. the word "OTP"
    # appearing in a legitimate bank alert).
    final -= suppression

    # Safety override: a severity-5 flag cannot produce a "looks fine" verdict.
    # Digital arrest indicators are too consequential to average away.
    critical_codes = {f["code"] for f in rule_flags if f["severity"] == 5}
    # Strong suppression evidence disarms the override — otherwise a genuine
    # bank SMS that mentions a PIN would be permanently pinned at 78.
    if suppression >= 30:
        critical_codes = set()
    if critical_codes:
        final = max(final, 78.0)
    if "DA_DIGITAL_ARREST" in critical_codes:
        final = max(final, 92.0)
    if len(critical_codes) >= 2:
        final = max(final, 88.0)

    final = round(max(0.0, min(100.0, final)), 1)

    # ---- Threat classification ------------------------------------------
    threat_type = rule_engine.classify_threat(
        threat_votes, campaign_threat, similarity
    )
    if llm_result and llm_result.get("threat_type") not in (None, "unknown"):
        # Trust the LLM label only when the deterministic layer had no opinion.
        if threat_type in ("safe", "unknown") and final >= settings.RISK_THRESHOLD_SUSPICIOUS:
            threat_type = llm_result["threat_type"]

    if final < settings.RISK_THRESHOLD_SUSPICIOUS:
        threat_type = "safe"

    verdict = _verdict_from_score(final)
    confidence = _compute_confidence(rule_flags, similarity, llm_result, len(content))

    # Low confidence on a mid-range score should read as "we don't know", not as
    # a false all-clear. This is the single most important UX call in the product.
    if confidence < 45 and verdict in ("suspicious", "likely_safe") and rule_flags:
        verdict = "inconclusive"

    # ---- Explanation & recommendations -----------------------------------
    if llm_result and llm_result.get("explanation"):
        explanation = llm_result["explanation"]
    else:
        explanation = _build_fallback_explanation(
            rule_flags, threat_type, final, campaign_name, similarity
        )

    recommendations = (
        llm_result["recommendations"]
        if llm_result and llm_result.get("recommendations")
        else RECOMMENDATIONS.get(threat_type, RECOMMENDATIONS["unknown"])
    )

    entities = rule_engine.extract_entities(content)
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    return {
        "content_hash": content_fingerprint(content),
        "content_preview": content[:280],
        "channel": channel,
        "sender": sender,
        "risk_score": int(round(final)),
        "confidence": confidence,
        "verdict": verdict,
        "threat_type": threat_type,
        "red_flags": rule_flags,
        "entities": entities,
        "explanation": explanation,
        "recommendations": list(recommendations),
        "similar_campaign": campaign_name if similarity >= 0.25 else None,
        "similarity_score": round(similarity, 3),
        "manipulation_tactics": llm_result.get("manipulation_tactics", []) if llm_result else [],
        "victim_impact": llm_result.get("victim_impact", "") if llm_result else "",
        "structural_notes": structural_notes,
        "safe_signals": safe_signals,
        "breakdown": {
            "rules": round(rule_score, 1),
            "similarity": round(similarity_score_component, 1),
            "structural": round(structural_score, 1),
            "llm": round(llm_score, 1),
            "suppression": round(suppression, 1),
            "weights": {k: round(v, 3) for k, v in w.items()},
            "final": final,
        },
        "llm_used": llm_result is not None,
        "model_version": (
            f"sentinel-fusion-1.0+{settings.GEMINI_MODEL}"
            if llm_result else "sentinel-fusion-1.0+deterministic"
        ),
        "processing_ms": elapsed_ms,
    }


def _build_fallback_explanation(
    flags: list, threat_type: str, score: float, campaign: Optional[str],
    similarity: float,
) -> str:
    """Deterministic prose used when Gemini is unavailable.

    This is why the product never shows an empty verdict card during a demo with
    no internet.
    """
    label = THREAT_LABELS.get(threat_type, "Unclassified")

    if not flags and score < settings.RISK_THRESHOLD_SUSPICIOUS:
        return ("No known fraud indicators were found in this message. It does not "
                "match any active campaign in our corpus. Continue to verify any "
                "payment request through a channel you look up yourself.")

    top = flags[:3]
    parts = [f"This message shows {len(flags)} fraud indicator"
             f"{'s' if len(flags) != 1 else ''} consistent with {label.lower()}."]

    if top:
        named = ", ".join(f["label"].lower() for f in top)
        parts.append(f"The strongest signals are: {named}.")

    if campaign and similarity >= 0.45:
        parts.append(f"It closely matches a known active campaign — "
                     f"\"{campaign}\" — at {int(similarity * 100)}% textual similarity.")

    if threat_type == "digital_arrest":
        parts.append("There is no legal power called 'digital arrest' in India. "
                     "Disconnect immediately and call 1930.")

    return " ".join(parts)
