"""Layer 1 and 3 of the detection pipeline: deterministic rules + structural signals.

This module never calls the network. If Gemini is unreachable, SentinelAI still
returns a defensible verdict from here.
"""
import re
from collections import Counter
from typing import Dict, List, Tuple

from app.data.red_flags import COMPILED_FLAGS, COMPILED_SAFE, MAX_SEVERITY_SUM

# ------------------------------------------------------------------ extraction

ENTITY_PATTERNS = {
    "phone": re.compile(r"(?:\+91[\-\s]?|0)?[6-9]\d{9}\b"),
    "upi": re.compile(r"\b[\w.\-]{2,256}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|paytm|"
                      r"apl|ibl|upi|axl|okbizaxis)\b", re.IGNORECASE),
    "url": re.compile(r"\b(?:https?://|www\.)[^\s<>\"']{4,}", re.IGNORECASE),
    "email": re.compile(r"\b[\w.\-+]+@[\w\-]+\.[\w.\-]{2,}\b"),
    "account": re.compile(r"\b\d{11,18}\b"),
    "ifsc": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    "amount": re.compile(r"(?:₹|rs\.?|inr)\s?[\d,]+(?:\.\d{1,2})?(?:\s?(?:lakh|crore|"
                         r"lac|k))?", re.IGNORECASE),
}

AGENCY_PATTERN = re.compile(
    r"\b(CBI|ED|Enforcement Directorate|NCB|Narcotics Control Bureau|TRAI|Customs|"
    r"Income Tax|Cyber Crime|Crime Branch|RBI|NIA|Interpol)\b", re.IGNORECASE
)

# Domains that are legitimately allowed to appear in Indian financial messages.
TRUSTED_DOMAINS = {
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "npci.org.in", "rbi.org.in", "incometax.gov.in", "cybercrime.gov.in",
    "uidai.gov.in", "india.gov.in", "epfindia.gov.in", "irctc.co.in",
}

SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
                   "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly"}


def extract_entities(text: str) -> List[Dict[str, str]]:
    """Pull actionable identifiers out of the message.

    These become the pivot points an investigator uses to link cases, so we keep
    them structured rather than burying them in prose.
    """
    found: List[Dict[str, str]] = []
    seen = set()

    for etype, pattern in ENTITY_PATTERNS.items():
        for match in pattern.findall(text):
            value = match if isinstance(match, str) else match[0]
            value = value.strip().rstrip(".,;:")
            key = (etype, value.lower())
            if key in seen or len(value) < 3:
                continue
            seen.add(key)

            note = None
            if etype == "url":
                host = re.sub(r"^https?://", "", value).split("/")[0].lower()
                host = host[4:] if host.startswith("www.") else host
                if host in SHORTENER_HOSTS:
                    note = "URL shortener — destination hidden"
                elif not any(host.endswith(d) for d in TRUSTED_DOMAINS):
                    note = "Domain not on the verified institution list"
            elif etype == "upi":
                note = "Verify the payee name in your UPI app before any transfer"
            elif etype == "account":
                note = "Beneficiary account — quote this when reporting to 1930"
            elif etype == "phone":
                note = "Report this number at cybercrime.gov.in"

            found.append({"type": etype, "value": value, "risk_note": note})

    for agency in set(m.upper() for m in AGENCY_PATTERN.findall(text)):
        found.append({
            "type": "agency",
            "value": agency,
            "risk_note": "Claimed authority — verify only on the agency's published number",
        })

    return found[:40]


def find_safe_signals(text: str) -> Tuple[List[Dict], float]:
    """Detect markers of genuine institutional messaging.

    Returns (signals_found, total_suppression_weight).
    """
    found: List[Dict] = []
    total = 0.0
    for sig in COMPILED_SAFE:
        for rx in sig["regex"]:
            m = rx.search(text)
            if m:
                found.append({
                    "code": sig["code"],
                    "label": sig["label"],
                    "matched_text": m.group(0)[:80],
                    "weight": sig["weight"],
                })
                total += sig["weight"]
                break
    return found, total


def run_rules(text: str) -> Tuple[List[Dict], float, Counter]:
    """Evaluate every red flag against the text.

    Returns (flags_fired, normalised_score_0_100, threat_votes).
    """
    fired: List[Dict] = []
    votes: Counter = Counter()
    severity_sum = 0.0

    for flag in COMPILED_FLAGS:
        # A negative pattern vetoes the flag entirely. This is what stops a
        # genuine "never share this OTP" warning from being read as a request
        # for the OTP.
        if any(nrx.search(text) for nrx in flag.get("negative_regex", [])):
            continue

        matched_text = None
        for rx in flag["regex"]:
            m = rx.search(text)
            if m:
                matched_text = m.group(0)[:80]
                break
        if matched_text is None:
            continue

        fired.append({
            "code": flag["code"],
            "category": flag["category"],
            "label": flag["label"],
            "severity": flag["severity"],
            "matched_text": matched_text,
            "explanation": flag["why"],
        })
        severity_sum += flag["severity"]

    # Compounding: several independent flags is far worse than one loud flag.
    if len(fired) >= 3:
        severity_sum *= 1.15
    if len(fired) >= 6:
        severity_sum *= 1.10

    score = min(100.0, (severity_sum / MAX_SEVERITY_SUM) * 100.0)
    fired.sort(key=lambda f: -f["severity"])
    votes = build_threat_votes(fired)
    return fired, round(score, 2), votes


def structural_signals(text: str, channel: str, sender: str | None) -> Tuple[float, List[str]]:
    """Layer 3: signals from message shape rather than message meaning."""
    notes: List[str] = []
    score = 0.0

    urls = ENTITY_PATTERNS["url"].findall(text)
    for u in urls:
        host = re.sub(r"^https?://", "", u).split("/")[0].lower()
        host = host[4:] if host.startswith("www.") else host
        if host in SHORTENER_HOSTS:
            score += 22
            notes.append(f"Shortened link hides its destination ({host})")
        elif not any(host.endswith(d) for d in TRUSTED_DOMAINS):
            score += 12
            notes.append(f"Unverified domain: {host}")
        if re.search(r"\d+\.\d+\.\d+\.\d+", host):
            score += 20
            notes.append("Link points at a raw IP address")
        if host.count("-") >= 2:
            score += 8
            notes.append("Hyphen-stuffed hostname, typical of lookalike domains")

    if len(urls) > 2:
        score += 8
        notes.append("Multiple links in a single message")

    # Sender shape. Indian bank/OTP senders use 6-char alphanumeric header IDs.
    if sender:
        s = sender.strip()
        if re.fullmatch(r"(?:\+91)?[6-9]\d{9}", s.replace(" ", "")):
            if channel in ("sms", "whatsapp"):
                score += 14
                notes.append("Financial-sounding message sent from a personal mobile number")
        elif re.fullmatch(r"[A-Z]{2}-[A-Z]{6}", s.upper()):
            notes.append("Registered DLT sender header present")
            score -= 6

    # Money + urgency in the same breath is the core scam grammar.
    has_amount = bool(ENTITY_PATTERNS["amount"].search(text))
    has_urgency = bool(re.search(r"urgent|immediat|within \d+|expire|last (chance|warning)"
                                 r"|today|now", text, re.IGNORECASE))
    if has_amount and has_urgency:
        score += 14
        notes.append("A specific amount paired with a deadline")

    caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(caps_words) >= 4:
        score += 6
        notes.append("Heavy use of capitals for pressure")

    if len(text) < 25:
        score -= 8
        notes.append("Very short message, limited signal")

    if re.search(r"do not share this (otp|code) with anyone", text, re.IGNORECASE):
        score -= 18
        notes.append("Contains the standard bank anti-fraud warning")

    return max(0.0, min(100.0, score)), notes


# Indicators that prove something is wrong without saying *what* is wrong.
# A shortened link appears in courier, lottery and job scams alike, so letting
# it vote at full strength drags every classification toward "phishing".
GENERIC_CODES = {
    "PH_SUSPICIOUS_URL", "PH_LOOKALIKE_DOMAIN", "PH_CREDENTIAL_PAGE",
    "GN_EXTREME_URGENCY", "GN_AUTHORITY_LANGUAGE", "GN_GRAMMAR_ANOMALY",
    "GN_UNKNOWN_SENDER_MONEY", "GN_UNTRACEABLE_PAYMENT", "LT_ADVANCE_FEE",
}
GENERIC_VOTE_WEIGHT = 0.4


def build_threat_votes(fired: List[Dict]) -> Counter:
    """Weight each flag's vote by how specific it is to one threat type."""
    from app.data.red_flags import FLAG_BY_CODE

    votes: Counter = Counter()
    for flag in fired:
        meta = FLAG_BY_CODE.get(flag["code"])
        if not meta:
            continue
        weight = flag["severity"]
        if flag["code"] in GENERIC_CODES:
            weight *= GENERIC_VOTE_WEIGHT
        for threat in meta["threats"]:
            votes[threat] += weight
    return votes


def classify_threat(votes: Counter, similarity_threat: str | None,
                    similarity_score: float) -> str:
    """Decide the threat label from rule votes plus campaign similarity.

    Rule votes are the primary signal, but they are a bag-of-indicators and get
    genuinely ambiguous when a scam borrows another category's machinery — a
    courier scam that uses a shortened link looks a lot like phishing. When the
    top two candidates are close, we let the campaign matcher break the tie,
    because it reads the message as a whole rather than as isolated indicators.
    """
    # A very strong campaign match is decisive on its own.
    if similarity_threat and similarity_score >= 0.55 and similarity_threat != "safe":
        return similarity_threat

    if not votes:
        return "safe"

    ranked = votes.most_common()
    best_threat, best_weight = ranked[0]

    contenders = [t for t, w in ranked if w >= best_weight * 0.85]

    # Digital arrest wins any close call. It is the highest-harm category in the
    # problem space, and the cost of under-calling it is someone staying on a
    # video call for eleven hours.
    if "digital_arrest" in contenders:
        return "digital_arrest"

    # Moderate campaign match breaks a near-tie between rule votes.
    if (len(contenders) > 1 and similarity_threat in contenders
            and similarity_score >= 0.35):
        return similarity_threat

    return best_threat
