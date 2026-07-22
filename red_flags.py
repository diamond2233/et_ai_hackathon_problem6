"""The deterministic detection knowledge base.

Every entry produces an explainable, citable red flag. This layer runs in
single-digit milliseconds, works with zero network access, and is the reason
SentinelAI can justify a verdict in court-usable language rather than
"the model said so".

Fields:
  code      stable identifier, used in reports and audit trails
  category  grouping shown in the UI
  label     human-readable name
  severity  1..5, contributes to the weighted rule score
  patterns  regex alternatives, matched case-insensitively
  threats   threat types this flag points toward
  why       plain-language explanation shown to the citizen
"""
import re
from typing import Dict, List

RED_FLAGS: List[Dict] = [
    # ------------------------------------------------ digital arrest (highest)
    {
        "code": "DA_DIGITAL_ARREST",
        "category": "Digital Arrest",
        "label": "Explicit 'digital arrest' claim",
        "severity": 5,
        "patterns": [r"digital arrest", r"digital custody", r"virtual arrest",
                     r"online arrest", r"डिजिटल अरेस्ट"],
        "threats": ["digital_arrest"],
        "why": "No Indian law enforcement agency has any power called 'digital arrest'. "
               "The term exists only in scams. This alone is conclusive.",
    },
    {
        "code": "DA_AGENCY_IMPERSONATION",
        "category": "Digital Arrest",
        "label": "Impersonation of a central agency",
        "severity": 4,
        "patterns": [r"\bCBI\b", r"\bE\.?D\.?\b(?!\w)", r"Enforcement Directorate",
                     r"Narcotics Control Bureau", r"\bNCB\b", r"Customs Department",
                     r"Cyber Crime Branch", r"\bTRAI\b", r"Income Tax Department",
                     r"Crime Branch", r"Anti[- ]?Terrorism", r"\bRBI\b official"],
        "threats": ["digital_arrest", "bank_fraud"],
        "why": "Central agencies never make first contact by phone, WhatsApp or video "
               "call. They issue written notices under CrPC/BNSS through the local "
               "police station.",
    },
    {
        "code": "DA_VIDEO_CALL_CUSTODY",
        "category": "Digital Arrest",
        "label": "Demand to stay on video call",
        "severity": 5,
        "patterns": [r"stay on (the )?(video )?call", r"do not (disconnect|cut|end)",
                     r"keep (the )?camera on", r"remain (on|in) (video|skype)",
                     r"24 hours? surveillance", r"under (our )?observation"],
        "threats": ["digital_arrest"],
        "why": "Forcing a victim to remain on camera is the signature technique of a "
               "digital arrest. It prevents them from consulting anyone.",
    },
    {
        "code": "DA_ISOLATION",
        "category": "Digital Arrest",
        "label": "Instruction to isolate from family",
        "severity": 5,
        "patterns": [r"do not (tell|inform|contact|call) (anyone|your family|your "
                     r"relatives|police)", r"keep this confidential", r"strictly "
                     r"confidential", r"national secrec", r"official secrets act",
                     r"no one should know"],
        "threats": ["digital_arrest"],
        "why": "Isolation is coercion, not procedure. Real investigations never ask "
               "you to hide contact from your family or your lawyer.",
    },
    {
        "code": "DA_ARREST_THREAT",
        "category": "Coercion",
        "label": "Threat of arrest or non-bailable warrant",
        "severity": 4,
        "patterns": [r"non[- ]?bailable", r"arrest warrant", r"warrant (has been )?"
                     r"issued", r"you will be arrested", r"immediate arrest",
                     r"lookout circular", r"custody within"],
        "threats": ["digital_arrest"],
        "why": "Warrants are served in person by police with documentation. They are "
               "never announced over a phone call demanding money.",
    },
    {
        "code": "DA_PARCEL_NARCOTICS",
        "category": "Digital Arrest",
        "label": "Parcel / narcotics seizure pretext",
        "severity": 4,
        "patterns": [r"parcel (containing|with|has been)", r"courier (containing|seized)",
                     r"\bMDMA\b", r"narcotics", r"illegal (items|substances|passports)",
                     r"your Aadhaar (was|has been) (used|linked)", r"money laundering"],
        "threats": ["digital_arrest", "courier"],
        "why": "The fake seized-parcel story is the most common opening move in "
               "digital arrest cases reported to the I4C.",
    },
    {
        "code": "DA_VERIFICATION_TRANSFER",
        "category": "Financial Coercion",
        "label": "'Verification' transfer to a government account",
        "severity": 5,
        "patterns": [r"verif(y|ication) (of )?(your )?(funds|account|money)",
                     r"transfer .{0,30}(RBI|Supreme Court|government) account",
                     r"refundable", r"will be returned (after|once)",
                     r"secure (government )?account", r"escrow account"],
        "threats": ["digital_arrest", "bank_fraud"],
        "why": "No agency ever asks you to transfer money to 'verify' it. There is no "
               "such procedure in Indian law.",
    },

    # ----------------------------------------------------------- banking / KYC
    {
        "code": "BF_KYC_EXPIRY",
        "category": "Bank Fraud",
        "label": "KYC expiry / account blocking threat",
        "severity": 3,
        "patterns": [r"kyc (update|expired|pending|verification)", r"account (will be|"
                     r"has been) (blocked|suspended|frozen|deactivated)",
                     r"re[- ]?activate your account", r"panel? card (update|link)"],
        "threats": ["kyc_fraud", "bank_fraud"],
        "why": "Banks do not complete KYC over SMS links. RBI requires in-person or "
               "verified in-app flows.",
    },
    {
        "code": "BF_CREDENTIAL_REQUEST",
        "category": "Credential Theft",
        "label": "Request for OTP, PIN, CVV or password",
        "severity": 5,
        "patterns": [
            r"(share|send|provide|tell|give|confirm|enter|verify|forward)\b[^.]{0,40}"
            r"\b(otp|one[- ]?time password|pin|cvv|password|card number)\b",
            r"\b(otp|cvv|pin)\b[^.]{0,30}\b(share|send|provide|forward|tell)\b",
            r"\b(atm|upi|debit card|credit card) pin\b",
            r"net ?banking (id|password|credentials)",
            r"card (number|details).{0,25}(expiry|cvv)",
        ],
        "negative": [
            r"(do not|don'?t|never|kindly do not|please do not)\s+(share|disclose|reveal)",
            r"no one (from|at) .{0,20}(bank|company) will (ever )?ask",
            r"bank never asks",
        ],
        "threats": ["bank_fraud", "phishing", "upi_fraud"],
        "why": "No bank, no police officer and no payment app will ever ask for an "
               "OTP, PIN or CVV. Anyone who does is committing fraud.",
    },
    {
        "code": "BF_REMOTE_ACCESS",
        "category": "Device Takeover",
        "label": "Remote access or unknown APK install",
        "severity": 5,
        "patterns": [r"any ?desk", r"team ?viewer", r"quick ?support", r"screen shar",
                     r"install (this|the) (app|apk)", r"\.apk\b",
                     r"download .{0,20}from the link"],
        "threats": ["bank_fraud", "upi_fraud"],
        "why": "Remote-access tools hand your screen and your banking session to the "
               "attacker. Legitimate support never requires them.",
    },

    # ------------------------------------------------------------------- UPI
    {
        "code": "UPI_COLLECT_REQUEST",
        "category": "UPI Fraud",
        "label": "Collect request framed as incoming money",
        "severity": 4,
        "patterns": [r"accept (the )?request to receive", r"approve .{0,20}to (get|"
                     r"receive)", r"enter (your )?upi pin to receive",
                     r"scan .{0,15}qr .{0,15}to receive", r"collect request",
                     r"(cashback|refund|amount) .{0,40}(accept|approve) the (collect )?request",
                     r"received a cashback of"],
        "threats": ["upi_fraud"],
        "why": "You never enter a UPI PIN to receive money. Entering a PIN always "
               "sends money out of your account.",
    },
    {
        "code": "UPI_REFUND_TRICK",
        "category": "UPI Fraud",
        "label": "Accidental transfer / refund request",
        "severity": 3,
        "patterns": [r"(sent|transferred) (by )?mistake", r"wrong (account|number|upi)",
                     r"kindly (return|refund|send back)", r"please return the amount"],
        "threats": ["upi_fraud"],
        "why": "The 'wrong transfer' story uses a fake credit SMS to make you send "
               "real money back.",
    },

    # -------------------------------------------------------------- phishing
    {
        "code": "PH_SUSPICIOUS_URL",
        "category": "Phishing",
        "label": "Shortened or lookalike link",
        "severity": 4,
        "patterns": [r"bit\.ly", r"tinyurl", r"t\.co/", r"is\.gd", r"cutt\.ly",
                     r"rb\.gy", r"shorturl", r"\b\w+-?(sbi|hdfc|icici|axis|paytm|"
                     r"phonepe|npci)\w*\.(xyz|top|online|info|club|site|link|buzz)"],
        "threats": ["phishing"],
        "why": "Shortened links hide the real destination. Banks always use their own "
               "verified domain.",
    },
    {
        "code": "PH_LOOKALIKE_DOMAIN",
        "category": "Phishing",
        "label": "Lookalike government or bank domain",
        "severity": 4,
        "patterns": [r"gov\.(?!in\b)\w+", r"\bindia-?gov\b", r"\bnpci-?verify\b",
                     r"\b(sbi|hdfc|icici|axis)[-.]?(secure|verify|update|kyc)\b",
                     r"incometax[-.]?refund"],
        "threats": ["phishing"],
        "why": "Genuine Indian government sites end in .gov.in or .nic.in. Everything "
               "else is impersonation.",
    },
    {
        "code": "PH_CREDENTIAL_PAGE",
        "category": "Phishing",
        "label": "Login or verification page prompt",
        "severity": 3,
        "patterns": [r"click here to (verify|login|update|confirm)",
                     r"log ?in to (verify|confirm|restore)", r"verify your identity",
                     r"confirm your (details|identity|account)",
                     r"(re[- ]?verify|update your details) (immediately|now|at)",
                     r"(aadhaar|account|connection) .{0,30}(has been |will be )?"
                     r"(suspended|deactivated|discontinued)",
                     r"secure your account",
                     r"unauthorised login|unauthorized login",
                     r"update your payment method"],
        "threats": ["phishing"],
        "why": "Credential-harvesting pages copy the real site pixel for pixel. Always "
               "type the address yourself.",
    },

    # ------------------------------------------------------- lottery / prizes
    {
        "code": "LT_PRIZE_WIN",
        "category": "Lottery Scam",
        "label": "Unsolicited prize or lottery win",
        "severity": 4,
        "patterns": [r"congratulations.{0,40}(won|winner|selected)", r"lucky (draw|"
                     r"winner)", r"lottery", r"kbc\b", r"kaun banega", r"prize money",
                     r"you have won", r"bumper (prize|offer)"],
        "threats": ["lottery"],
        "why": "You cannot win a lottery you never entered. The prize is bait for the "
               "'processing fee' that follows.",
    },
    {
        "code": "LT_ADVANCE_FEE",
        "category": "Advance Fee",
        "label": "Processing / clearance fee demanded",
        "severity": 4,
        "patterns": [r"processing fee", r"clearance (fee|charge)", r"registration "
                     r"(fee|charge)", r"gst (charges|payment) of", r"security deposit",
                     r"refundable deposit", r"convenience fee of"],
        "threats": ["lottery", "job_scam", "loan_scam", "courier"],
        "why": "Genuine winnings, jobs and loans never require money up front. Advance "
               "fee is the entire business model of the scam.",
    },

    # ---------------------------------------------------------------- courier
    {
        "code": "CR_CUSTOMS_HOLD",
        "category": "Courier Scam",
        "label": "Parcel held at customs / duty demanded",
        "severity": 3,
        "patterns": [r"(parcel|package|shipment|consignment) .{0,30}(held|stuck|"
                     r"detained|pending)", r"customs (duty|clearance|charge)",
                     r"delivery (failed|attempt failed)", r"reschedule your delivery",
                     r"update your (address|delivery)", r"redelivery fee",
                     r"could not be delivered"],
        "threats": ["courier"],
        "why": "Couriers collect duty at delivery through official channels, never via "
               "an SMS link to a personal wallet.",
    },

    # ------------------------------------------------------------ job / loan
    {
        "code": "JB_WORK_FROM_HOME",
        "category": "Job Scam",
        "label": "Task-based work-from-home earnings",
        "severity": 3,
        "patterns": [r"work from home.{0,40}(earn|income|daily)", r"part[- ]?time job",
                     r"earn (rs\.?|₹)? ?\d{3,}", r"daily (income|payout)",
                     r"like and (subscribe|rate)", r"prepaid task",
                     r"telegram .{0,25}(task|job|earn|group to start)",
                     r"(resume|cv) has been shortlisted",
                     r"(security|joining) deposit .{0,25}(confirm|joining|laptop)",
                     r"data entry (work|job)", r"payment daily|daily payout"],
        "threats": ["job_scam"],
        "why": "Task-based earning schemes pay small amounts first, then demand large "
               "deposits to 'unlock' withdrawals.",
    },
    {
        "code": "LN_INSTANT_LOAN",
        "category": "Loan Scam",
        "label": "Instant loan without documentation",
        "severity": 3,
        "patterns": [r"instant (personal )?loan", r"pre[- ]?approved",
                     r"loan .{0,25}without .{0,15}(document|cibil|paperwork)",
                     r"no (cibil|credit) check", r"without any documents",
                     r"loan approved.{0,30}click", r"0\s?% interest",
                     r"credited in \d+ minutes?"],
        "threats": ["loan_scam"],
        "why": "Unregulated loan apps harvest your contacts and photos, then extort "
               "you. Check the RBI-registered NBFC list first.",
    },

    # --------------------------------------------------------- investment
    {
        "code": "IV_GUARANTEED_RETURNS",
        "category": "Investment Fraud",
        "label": "Guaranteed or outsized returns",
        "severity": 4,
        "patterns": [r"guaranteed\s+\w{0,10}\s?(returns?|profit|income)",
                     r"\d{2,}\s?% (monthly|return|profit|guaranteed|per month)",
                     r"(returns?|profit) of \d{2,}\s?%",
                     r"double your (money|investment)",
                     r"risk[- ]?free|zero risk|fully risk",
                     r"insider (tip|information)", r"vip trading|trading group",
                     r"arbitrage opportunity"],
        "threats": ["investment"],
        "why": "SEBI prohibits guaranteed-return promises. Any such claim is either "
               "unregistered or outright fraud.",
    },

    # ------------------------------------------------------------ sextortion
    {
        "code": "SX_EXPLICIT_BLACKMAIL",
        "category": "Sextortion",
        "label": "Blackmail over recorded content",
        "severity": 5,
        "patterns": [r"(recorded|screen ?recorded) (your|the) (video|screen|call)",
                     r"will (upload|share|post) .{0,25}(video|photo)",
                     r"your contacts will", r"viral (kar|karunga|on youtube)",
                     r"morph(ed)? (photo|video)", r"obscene (content|video|material)",
                     r"your video is with us", r"nude|explicit (video|photo)",
                     r"settlement (fee|amount) to close the case"],
        "threats": ["sextortion"],
        "why": "Sextortion gangs almost never hold real material and never stop after "
               "payment. Report to 1930 and preserve everything.",
    },

    # ----------------------------------------------- generic pressure markers
    {
        "code": "GN_EXTREME_URGENCY",
        "category": "Pressure Tactics",
        "label": "Artificial time pressure",
        "severity": 3,
        "patterns": [r"within (the next )?\d+ (minute|hour)", r"immediately",
                     r"urgent(ly)?", r"last (warning|chance|reminder)",
                     r"expires? (today|in \d+)", r"act now", r"final notice",
                     r"before .{0,10}(midnight|today)"],
        "threats": ["phishing", "bank_fraud", "digital_arrest"],
        "why": "Urgency is engineered to stop you from thinking or verifying. Real "
               "institutions give you time.",
    },
    {
        "code": "GN_AUTHORITY_LANGUAGE",
        "category": "Pressure Tactics",
        "label": "Legal jargon used as intimidation",
        "severity": 2,
        "patterns": [r"section \d+ of", r"under (the )?(ipc|bns|pmla|it act)",
                     r"legal (action|proceedings)", r"fir (has been|will be) (filed|"
                     r"registered)", r"court (summons|proceedings)", r"prosecution"],
        "threats": ["digital_arrest", "bank_fraud"],
        "why": "Scammers quote real sections to sound credible. Verify any notice at "
               "the issuing agency's official number, never the one provided.",
    },
    {
        "code": "GN_UNTRACEABLE_PAYMENT",
        "category": "Payment Red Flag",
        "label": "Untraceable payment method demanded",
        "severity": 4,
        "patterns": [r"gift card", r"google play (card|code)", r"amazon (voucher|card)",
                     r"crypto(currency)?", r"\busdt\b", r"bitcoin", r"binance",
                     r"western union"],
        "threats": ["lottery", "sextortion", "investment"],
        "why": "Gift cards and crypto are chosen because they cannot be reversed or "
               "traced. No genuine institution accepts them.",
    },
    {
        "code": "GN_UNKNOWN_SENDER_MONEY",
        "category": "Payment Red Flag",
        "label": "Payment to a personal account",
        "severity": 3,
        "patterns": [r"@(ok|y)?(axis|hdfc|icici|sbi|paytm|ybl|upi|apl|ibl)\b",
                     r"account (no\.?|number)[: ]+\d{9,}", r"ifsc[: ]+[A-Z]{4}0",
                     r"scan (this )?qr", r"phone ?pe (number|no)"],
        "threats": ["upi_fraud", "bank_fraud"],
        "why": "Government fines and bank dues are never collected into a personal UPI "
               "handle or savings account.",
    },
    {
        "code": "GN_GRAMMAR_ANOMALY",
        "category": "Linguistic Signal",
        "label": "Mass-mailer formatting artefacts",
        "severity": 1,
        "patterns": [r"[A-Z]{6,}\s+[A-Z]{6,}", r"!{2,}", r"\bDear (Customer|User|Sir/"
                     r"Madam)\b", r"kindly do the needful", r"revert back"],
        "threats": ["phishing", "lottery"],
        "why": "Generic salutations and shouting capitals indicate bulk-sent fraud, "
               "not a message meant for you.",
    },
]

# ---------------------------------------------------------------------------
# Suppression signals.
#
# Detection systems that only ever add points drift toward flagging everything,
# and a citizen tool that cries wolf gets uninstalled. These are markers of
# genuine institutional messaging; each one subtracts from the risk score.
# ---------------------------------------------------------------------------
SAFE_SIGNALS = [
    {
        "code": "SF_ANTI_FRAUD_WARNING",
        "label": "Contains the standard bank anti-fraud warning",
        "weight": 32,
        "patterns": [r"(do not|don'?t|never) share (this )?(otp|pin|code|password)",
                     r"no one from .{0,25}bank will (ever )?ask",
                     r"bank never asks for"],
    },
    {
        "code": "SF_MASKED_ACCOUNT",
        "label": "Uses a masked account number, as regulation requires",
        "weight": 18,
        "patterns": [r"\ba/?c\.? ?(no\.? ?)?x{2,}\d{2,}", r"\bxx+\d{3,}\b",
                     r"account ending (in|with) \d{3,}"],
    },
    {
        "code": "SF_OFFICIAL_HELPLINE",
        "label": "Quotes a published toll-free helpline",
        "weight": 14,
        "patterns": [r"\b1800[ -]?\d{3}[ -]?\d{4}\b", r"\b1930\b",
                     r"\b180[03]\d{6,8}\b"],
    },
    {
        "code": "SF_NO_ACTION_NEEDED",
        "label": "Explicitly states no action or payment is required",
        "weight": 20,
        "patterns": [r"no action is required", r"no payment is due",
                     r"already prepaid", r"ignore this message if",
                     r"this is only an? (alert|notification|reminder)"],
    },
    {
        "code": "SF_DLT_SENDER",
        "label": "Sent through a registered DLT header",
        "weight": 10,
        "patterns": [r"-\s?(SBI|HDFC Bank|ICICI Bank|Axis Bank|NPCI|RBI)\s*$"],
    },
]

COMPILED_SAFE = [
    {**sig, "regex": [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in sig["patterns"]]}
    for sig in SAFE_SIGNALS
]

# Pre-compile once at import. Detection stays in the microsecond range per flag.
COMPILED_FLAGS = [
    {
        **flag,
        "regex": [re.compile(p, re.IGNORECASE) for p in flag["patterns"]],
        "negative_regex": [
            re.compile(p, re.IGNORECASE) for p in flag.get("negative", [])
        ],
    }
    for flag in RED_FLAGS
]

FLAG_BY_CODE = {f["code"]: f for f in RED_FLAGS}

# Maximum achievable rule severity, used to normalise the rule sub-score.
MAX_SEVERITY_SUM = 13.0

THREAT_LABELS = {
    "digital_arrest": "Digital Arrest Scam",
    "bank_fraud": "Bank Fraud",
    "upi_fraud": "UPI Fraud",
    "phishing": "Phishing",
    "lottery": "Lottery / Prize Scam",
    "courier": "Courier / Parcel Scam",
    "job_scam": "Job Scam",
    "loan_scam": "Loan App Scam",
    "investment": "Investment Fraud",
    "kyc_fraud": "KYC Fraud",
    "sextortion": "Sextortion",
    "safe": "No Threat Detected",
    "unknown": "Unclassified",
}

# Safety advice keyed by threat type. Deterministic fallback when the LLM is off.
RECOMMENDATIONS = {
    "digital_arrest": [
        "Disconnect the call now. Staying on the line is what the scam depends on.",
        "No agency in India can place you under 'digital arrest'. The term is fictional.",
        "Call 1930 (National Cyber Crime Helpline) and tell one family member immediately.",
        "Do not transfer any amount for 'verification'. No such procedure exists.",
        "Screenshot the caller ID, save the video call log, and file at cybercrime.gov.in.",
    ],
    "bank_fraud": [
        "Never share OTP, PIN or CVV. Your bank already has every detail it needs.",
        "Call the number printed on the back of your card, not the one in the message.",
        "If you shared credentials, block the card and call 1930 within the golden hour.",
        "Check your account statement for unfamiliar debits before you do anything else.",
    ],
    "upi_fraud": [
        "You never enter a UPI PIN to receive money. Entering it always sends money out.",
        "Reject any pending collect request and report it inside your UPI app.",
        "Report the handle to NPCI through your payment app's dispute flow.",
        "If money left your account, call 1930 immediately. Fast reporting enables holds.",
    ],
    "phishing": [
        "Do not open the link. Type the official address into your browser yourself.",
        "Genuine Indian government sites end in .gov.in or .nic.in only.",
        "If you entered credentials, change that password everywhere it was reused.",
        "Forward the message to report.phishing@sbi.co.in or your bank's abuse address.",
    ],
    "lottery": [
        "You cannot win a lottery you never entered.",
        "Any request for a fee to release a prize confirms the fraud.",
        "Block the sender and report at cybercrime.gov.in.",
    ],
    "courier": [
        "Track the parcel only on the courier's official website using your own booking ID.",
        "Customs duty is never collected through an SMS link or a personal UPI handle.",
        "If they mention narcotics or a police case, it is a digital arrest setup. Hang up.",
    ],
    "job_scam": [
        "Legitimate employers never ask you to deposit money to start earning.",
        "Verify the company on the MCA portal before sharing any document.",
        "Never send Aadhaar or PAN scans to a recruiter on WhatsApp or Telegram.",
    ],
    "loan_scam": [
        "Check the lender against the RBI list of registered NBFCs before installing anything.",
        "Deny contacts, photos and SMS permissions to any loan app.",
        "Harassment by recovery agents is a criminal offence. Report it at 1930.",
    ],
    "investment": [
        "SEBI prohibits guaranteed-return promises. Verify the advisor on the SEBI portal.",
        "Leave any trading group that pressures you to deposit before a deadline.",
        "Withdraw a small amount early. Blocked withdrawals confirm the fraud.",
    ],
    "kyc_fraud": [
        "Complete KYC only inside your bank's official app or at a branch.",
        "Banks never send KYC links by SMS or WhatsApp.",
        "Call your branch on its published landline to confirm any KYC claim.",
    ],
    "sextortion": [
        "Do not pay. Payment always leads to further demands.",
        "Preserve the chat, the number and the profile. Do not delete anything.",
        "Report at cybercrime.gov.in under 'Women/Child related crime' for priority handling.",
        "Call 1930. You are the victim of a crime here, and reporting is confidential.",
    ],
    "safe": [
        "No fraud indicators were detected in this message.",
        "Still verify any payment request through a channel you looked up yourself.",
        "Never share OTP, PIN or CVV regardless of who is asking.",
    ],
    "unknown": [
        "Treat this as unverified until you confirm it independently.",
        "Contact the organisation using a number you looked up yourself.",
        "Do not click links or share credentials until verified.",
    ],
}
