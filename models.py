from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# Domain enums & constants
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class ActionType(str, Enum):
    TRIAGE = "triage"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    CONTAIN = "contain"
    RESOLVE = "resolve"
    QUERY_LOGS = "query_logs"
    WRITE_REPORT = "write_report"
    MARK_FALSE_POSITIVE = "mark_false_positive"


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models — Action / Observation / Reward / State
# ─────────────────────────────────────────────────────────────────────────────

class CyberSOCAction(BaseModel):
    """Action an agent can take in the CyberSOC environment."""
    action_type: ActionType = Field(..., description="Type of SOC action to perform")
    alert_id: str = Field(..., description="Target alert ID (e.g. 'ALT-001')")
    severity_assessment: Optional[Severity] = Field(None, description="Agent's severity assessment (for triage)")
    log_query: Optional[str] = Field(None, description="Log field to query (for query_logs)")
    report_text: Optional[str] = Field(None, description="Incident report content (for write_report)")
    reasoning: Optional[str] = Field(None, description="Agent's reasoning for this action")


class AlertObservation(BaseModel):
    alert_id: str
    title: str
    description: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    severity: Severity
    status: AlertStatus
    mitre_technique: Optional[str]
    available_actions: List[str]
    log_data: Optional[Dict[str, str]] = None
    analyst_notes: List[str] = Field(default_factory=list)


class CyberSOCObservation(BaseModel):
    """Full observation returned after each step."""
    active_alerts: List[AlertObservation]
    current_alert_id: Optional[str]
    step_result: str
    action_feedback: str
    threat_intel: Optional[str]
    metrics: Dict[str, Any]
    queue_depth: int
    shift_time_remaining: int


class CyberSOCReward(BaseModel):
    """Structured reward breakdown."""
    total: float
    triage_accuracy: float
    investigation_depth: float
    response_speed: float
    false_positive_penalty: float
    escalation_correctness: float
    report_quality: float


class CyberSOCState(BaseModel):
    """Full internal state (returned by state())."""
    episode_id: str
    task_name: str
    step: int
    max_steps: int
    alerts: Dict[str, Any]
    resolved_alerts: List[str]
    false_positives_marked: List[str]
    escalated_alerts: List[str]
    contained_alerts: List[str]
    actions_taken: List[Dict]
    cumulative_reward: float
    done: bool


class StepResult(BaseModel):
    observation: CyberSOCObservation
    reward: float
    done: bool
    info: Dict[str, Any]
