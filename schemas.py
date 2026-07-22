"""All request/response schemas for the SentinelAI API."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.common import (
    Channel,
    ComplaintStatus,
    MongoModel,
    ThreatType,
    Verdict,
    utcnow,
)

# ---------------------------------------------------------------- users / auth


class UserRegister(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    phone: Optional[str] = Field(default=None, max_length=20)
    state: Optional[str] = Field(default=None, max_length=60)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if v.isdigit() or v.isalpha():
            raise ValueError("Password must mix letters and numbers")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserPublic(MongoModel):
    id: str
    name: str
    email: EmailStr
    phone: Optional[str] = None
    state: Optional[str] = None
    role: str = "citizen"
    created_at: datetime
    scans_run: int = 0
    threats_blocked: int = 0


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserPublic


class UserSettings(BaseModel):
    language: str = "en"
    theme: str = "dark"
    alert_email: bool = True
    alert_sms: bool = False
    auto_report_high_risk: bool = False
    share_anonymised_signals: bool = True
    sensitivity: str = "balanced"  # strict | balanced | lenient


# ------------------------------------------------------------------- analysis


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=3, max_length=12000)
    channel: Channel = Channel.UNKNOWN
    sender: Optional[str] = Field(default=None, max_length=120)
    language: str = "en"
    include_llm: bool = True

    @field_validator("content")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Content cannot be blank")
        return v.strip()


class RedFlag(BaseModel):
    code: str
    category: str
    label: str
    severity: int = Field(ge=1, le=5)
    matched_text: Optional[str] = None
    explanation: str


class ExtractedEntity(BaseModel):
    type: str  # phone | upi | url | account | amount | agency | email
    value: str
    risk_note: Optional[str] = None


class ScoreBreakdown(BaseModel):
    rules: float
    similarity: float
    structural: float
    llm: float
    weights: Dict[str, float]
    final: float


class AnalysisResult(MongoModel):
    id: Optional[str] = None
    content_hash: str
    content_preview: str
    channel: Channel
    sender: Optional[str] = None

    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    verdict: Verdict
    threat_type: ThreatType

    red_flags: List[RedFlag] = []
    entities: List[ExtractedEntity] = []
    explanation: str
    recommendations: List[str] = []
    similar_campaign: Optional[str] = None
    similarity_score: Optional[float] = None

    breakdown: ScoreBreakdown
    llm_used: bool = False
    model_version: str
    processing_ms: int
    created_at: datetime = Field(default_factory=utcnow)
    user_id: Optional[str] = None


class BulkAnalyzeRequest(BaseModel):
    items: List[AnalyzeRequest] = Field(min_length=1, max_length=25)


# ------------------------------------------------------------------ complaints


class ComplaintCreate(BaseModel):
    scam_type: ThreatType
    channel: Channel = Channel.UNKNOWN
    description: str = Field(min_length=10, max_length=4000)
    amount_lost: float = Field(default=0, ge=0)
    state: str
    city: Optional[str] = None
    suspect_contact: Optional[str] = None
    analysis_id: Optional[str] = None


class Complaint(MongoModel):
    id: Optional[str] = None
    complaint_id: str
    user_id: Optional[str] = None
    scam_type: ThreatType
    channel: Channel
    description: str
    amount_lost: float = 0
    state: str
    city: Optional[str] = None
    suspect_contact: Optional[str] = None
    status: ComplaintStatus = ComplaintStatus.OPEN
    risk_score: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# ------------------------------------------------------------------------ chat


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    session_id: Optional[str] = None
    language: str = "en"


class ChatMessage(BaseModel):
    role: str  # user | assistant
    content: str
    created_at: datetime = Field(default_factory=utcnow)
    meta: Dict[str, Any] = {}


class ChatResponse(BaseModel):
    session_id: str
    reply: str
    suggestions: List[str] = []
    detected_threat: Optional[ThreatType] = None
    risk_score: Optional[int] = None
    llm_used: bool = False
    history_length: int = 0


class ConversationSummary(BaseModel):
    session_id: str
    title: str
    message_count: int
    updated_at: datetime


# ------------------------------------------------------------------- analytics


class StatCard(BaseModel):
    label: str
    value: float
    delta_pct: Optional[float] = None
    unit: str = ""


class ScamTypeStat(BaseModel):
    scam_type: str
    label: str
    count: int
    amount_lost: float
    share_pct: float


class MonthlyPoint(BaseModel):
    month: str
    complaints: int
    amount_lost: float
    digital_arrest: int


class StateStat(BaseModel):
    state: str
    complaints: int
    amount_lost: float
    risk_level: str


class Hotspot(BaseModel):
    name: str
    state: str
    lat: float
    lng: float
    complaints: int
    amount_lost: float
    risk_level: str
    dominant_scam: str


class DashboardResponse(BaseModel):
    cards: List[StatCard]
    scam_types: List[ScamTypeStat]
    monthly: List[MonthlyPoint]
    top_states: List[StateStat]
    hotspots: List[Hotspot]
    recent_complaints: List[Complaint]
    risk_distribution: Dict[str, int]
    generated_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------- reports


class ReportRequest(BaseModel):
    analysis_id: str
    include_recommendations: bool = True
    reporter_name: Optional[str] = None


class ReportMeta(BaseModel):
    report_id: str
    analysis_id: str
    created_at: datetime
    download_url: str
    sha256: str
