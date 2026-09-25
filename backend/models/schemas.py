from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RuleID(str, Enum):
    RULE_1 = "RULE_1_SI_FN_MISMATCH"
    RULE_2 = "RULE_2_USN_BASIC_INFO_CHANGE"
    RULE_3 = "RULE_3_TIMESTAMP_ZEROING"
    RULE_4 = "RULE_4_SUSPICIOUS_SEQUENCE"
    RULE_5 = "RULE_5_LOGFILE_CORROBORATION"


class TimestampSet(BaseModel):
    created: str
    modified: str
    mft_modified: str
    accessed: str


class LogfileCorroboration(BaseModel):
    corroborated: bool
    details: str


class ParsedRecord(BaseModel):
    record_id: str
    source: str  # "MFT" | "UsnJrnl" | "LogFile"
    file_reference: str
    parent_file_reference: Optional[str] = None
    file_name: str
    full_path: str
    is_directory: bool
    std_info_times: TimestampSet
    file_name_times: Optional[TimestampSet] = None
    usn_reason: Optional[List[str]] = None
    usn_timestamp: Optional[str] = None
    logfile_operation: Optional[str] = None
    logfile_timestamp: Optional[str] = None
    raw: Dict[str, Any]


class DetectionResult(BaseModel):
    scenario_id: str
    file_reference: str
    full_path: str
    rule_id: str
    triggered: bool
    score_contribution: int
    evidence: Dict[str, Any]
    logfile_corroboration: Optional[LogfileCorroboration] = None


class RiskScore(BaseModel):
    scenario_id: str
    file_reference: str
    full_path: str
    total_score: int
    risk_level: str
    triggered_rules: List[str]


class TimelineEvent(BaseModel):
    timestamp: str
    source: str  # "MFT" | "UsnJrnl" | "LogFile"
    file_reference: str
    full_path: str
    event_type: str
    details: Dict[str, Any]