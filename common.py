"""Shared model plumbing: ObjectId serialisation, enums, pagination."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, List, TypeVar

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, GetCoreSchemaHandler
from pydantic_core import core_schema

T = TypeVar("T")


class PyObjectId(str):
    """Lets Pydantic v2 accept a bson ObjectId and emit it as a string."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(cls.validate)

    @classmethod
    def validate(cls, v: Any) -> str:
        if isinstance(v, ObjectId):
            return str(v)
        if isinstance(v, str) and ObjectId.is_valid(v):
            return v
        if isinstance(v, str):
            return v
        raise ValueError("Invalid ObjectId")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MongoModel(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str, datetime: lambda d: d.isoformat()},
    )


class ThreatType(str, Enum):
    DIGITAL_ARREST = "digital_arrest"
    BANK_FRAUD = "bank_fraud"
    UPI_FRAUD = "upi_fraud"
    PHISHING = "phishing"
    LOTTERY = "lottery"
    COURIER = "courier"
    JOB_SCAM = "job_scam"
    LOAN_SCAM = "loan_scam"
    INVESTMENT = "investment"
    KYC_FRAUD = "kyc_fraud"
    SEXTORTION = "sextortion"
    SAFE = "safe"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    CRITICAL = "critical"
    HIGH_RISK = "high_risk"
    SUSPICIOUS = "suspicious"
    LIKELY_SAFE = "likely_safe"
    INCONCLUSIVE = "inconclusive"


class Channel(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    EMAIL = "email"
    CALL_TRANSCRIPT = "call_transcript"
    UNKNOWN = "unknown"


class ComplaintStatus(str, Enum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Paginated(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    pages: int = Field(default=0)
