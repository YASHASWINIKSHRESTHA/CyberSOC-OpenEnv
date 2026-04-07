"""
CyberSOC-OpenEnv: A real-world Cybersecurity Security Operations Center environment.

An AI agent acts as a Tier-1 SOC Analyst, triaging security alerts, investigating
incidents, escalating threats, and writing incident reports. This simulates the
exact workflow used in real enterprise SOC teams worldwide.

OpenEnv spec compliant: step() / reset() / state() + openenv.yaml
"""

from __future__ import annotations

import copy
import json
import random
import textwrap
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from models import (
    Severity,
    AlertStatus,
    ActionType,
    CyberSOCAction,
    AlertObservation,
    CyberSOCObservation,
    CyberSOCReward,
    CyberSOCState,
    StepResult,
)


# ─────────────────────────────────────────────────────────────────────────────
# Alert & Log data models
# ─────────────────────────────────────────────────────────────────────────────

ALERT_LIBRARY = [
    {
        "id": "ALT-001",
        "title": "Suspicious PowerShell Execution Detected",
        "description": "PowerShell launched with encoded command from non-admin user account on workstation WS-042.",
        "source_ip": "192.168.10.42",
        "dest_ip": "185.220.101.45",
        "severity": Severity.HIGH,
        "true_positive": True,
        "attack_type": "Malware Dropper",
        "ioc": "185.220.101.45",
        "mitre": "T1059.001",
        "log_hints": {
            "process_tree": "explorer.exe → cmd.exe → powershell.exe -EncodedCommand JABj...",
            "network": "Outbound TCP 443 to 185.220.101.45 (Tor exit node)",
            "user": "jsmith (standard user, no admin rights)",
            "file": "Dropped: C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe"
        },
        "correct_actions": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE, ActionType.WRITE_REPORT],
        "resolution": "CONTAIN"
    },
    {
        "id": "ALT-002",
        "title": "Multiple Failed SSH Login Attempts",
        "description": "1,247 failed SSH login attempts from single IP in 10 minutes targeting prod-db-01.",
        "source_ip": "45.33.32.156",
        "dest_ip": "10.0.1.50",
        "severity": Severity.MEDIUM,
        "true_positive": True,
        "attack_type": "Brute Force",
        "ioc": "45.33.32.156",
        "mitre": "T1110.001",
        "log_hints": {
            "auth": "1247 × 'Failed password for root from 45.33.32.156 port 52xxx'",
            "network": "Rate: ~120 attempts/min, source is known Shodan scanner range",
            "firewall": "No existing block rule for this IP range"
        },
        "correct_actions": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.RESOLVE],
        "resolution": "CONTAIN"
    },
    {
        "id": "ALT-003",
        "title": "Antivirus Alert: EICAR Test File",
        "description": "AV flagged EICAR test string in /tmp/test.txt on dev workstation DEV-007.",
        "source_ip": "192.168.20.7",
        "dest_ip": None,
        "severity": Severity.LOW,
        "true_positive": False,
        "attack_type": "Test/Benign",
        "ioc": None,
        "mitre": None,
        "log_hints": {
            "av": "Detection: EICAR-Test-File (not a virus)",
            "user": "dev-user (developer, regularly runs AV tests)",
            "file": "/tmp/test.txt - created 2 min ago, standard EICAR string"
        },
        "correct_actions": [ActionType.INVESTIGATE, ActionType.MARK_FALSE_POSITIVE],
        "resolution": "FALSE_POSITIVE"
    },
    {
        "id": "ALT-004",
        "title": "Data Exfiltration: Abnormal S3 Bucket Access",
        "description": "IAM user 'svc-backup' downloaded 47GB from production S3 bucket in 8 minutes.",
        "source_ip": "203.0.113.99",
        "dest_ip": "s3.amazonaws.com",
        "severity": Severity.CRITICAL,
        "true_positive": True,
        "attack_type": "Data Exfiltration",
        "ioc": "203.0.113.99",
        "mitre": "T1567.002",
        "log_hints": {
            "cloudtrail": "GetObject × 18,432 calls, user=svc-backup, IP=203.0.113.99",
            "geo": "Source IP geolocates to Romania (normal usage: US-East)",
            "iam": "svc-backup last used from US-East-1; MFA not enabled",
            "s3": "Bucket: prod-customer-data (PII, PCI in scope)"
        },
        "correct_actions": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE, ActionType.WRITE_REPORT],
        "resolution": "CONTAIN"
    },
    {
        "id": "ALT-005",
        "title": "Lateral Movement: Pass-the-Hash Detected",
        "description": "WMI remote execution from compromised host HR-PC-012 to finance server FIN-SRV-01.",
        "source_ip": "192.168.30.12",
        "dest_ip": "192.168.5.10",
        "severity": Severity.CRITICAL,
        "true_positive": True,
        "attack_type": "Lateral Movement",
        "ioc": "192.168.30.12",
        "mitre": "T1550.002",
        "log_hints": {
            "winevent": "EventID 4624 Logon Type 3, NTLM, account: CORP\\svc-admin",
            "edr": "Mimikatz artifacts detected on HR-PC-012 (sekurlsa::logonpasswords)",
            "network": "WMI traffic from HR-PC-012 → FIN-SRV-01 (unusual path)",
            "timeline": "Compromise chain: ALT-001 host → HR-PC-012 → FIN-SRV-01"
        },
        "correct_actions": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE, ActionType.WRITE_REPORT],
        "resolution": "CONTAIN"
    },
    {
        "id": "ALT-006",
        "title": "Phishing Email: Credential Harvesting Link",
        "description": "Email with lookalike domain 'micros0ft-login.com' sent to 34 employees.",
        "source_ip": "198.51.100.22",
        "dest_ip": None,
        "severity": Severity.HIGH,
        "true_positive": True,
        "attack_type": "Phishing",
        "ioc": "micros0ft-login.com",
        "mitre": "T1566.002",
        "log_hints": {
            "email": "From: support@micros0ft-login.com, Subject: 'Action Required: MFA Reset'",
            "url": "http://micros0ft-login.com/signin — registered 2 days ago",
            "clicks": "7 employees clicked; 2 entered credentials per proxy logs",
            "dns": "Domain resolves to bulletproof hosting in RU"
        },
        "correct_actions": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE, ActionType.WRITE_REPORT],
        "resolution": "CONTAIN"
    },
]

LOG_DATABASE: Dict[str, Dict] = {alert["id"]: alert["log_hints"] for alert in ALERT_LIBRARY}


# ─────────────────────────────────────────────────────────────────────────────
# Models are now in models.py


# ─────────────────────────────────────────────────────────────────────────────
# Main Environment
# ─────────────────────────────────────────────────────────────────────────────

class CyberSOCEnv:
    """
    CyberSOC-OpenEnv: Cybersecurity SOC Incident Response Environment.

    An agent acts as a Tier-1 SOC Analyst across a realistic shift.
    Alerts arrive with real-world indicators; the agent must triage,
    investigate, contain threats, escalate critical incidents, identify
    false positives, and write incident reports.

    Tasks:
      - easy:   Triage 2 alerts (1 true positive, 1 false positive)
      - medium: Full investigation cycle on a brute-force + phishing campaign
      - hard:   Multi-stage APT response (lateral movement + data exfiltration)
    """

    TASKS = {
        "easy": {
            "alert_ids": ["ALT-003", "ALT-002"],
            "description": "Triage two alerts: identify the false positive and handle the brute-force.",
            "max_steps": 12,
            "required_actions": {
                "ALT-003": [ActionType.INVESTIGATE, ActionType.MARK_FALSE_POSITIVE],
                "ALT-002": [ActionType.INVESTIGATE, ActionType.CONTAIN],
            }
        },
        "medium": {
            "alert_ids": ["ALT-006", "ALT-001"],
            "description": "Investigate a phishing campaign and malware dropper; escalate and contain.",
            "max_steps": 18,
            "required_actions": {
                "ALT-006": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE],
                "ALT-001": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE],
            }
        },
        "hard": {
            "alert_ids": ["ALT-004", "ALT-005", "ALT-001"],
            "description": "Respond to a full APT chain: exfiltration + lateral movement + initial compromise. Write reports.",
            "max_steps": 25,
            "required_actions": {
                "ALT-004": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE, ActionType.WRITE_REPORT],
                "ALT-005": [ActionType.INVESTIGATE, ActionType.CONTAIN, ActionType.ESCALATE, ActionType.WRITE_REPORT],
                "ALT-001": [ActionType.INVESTIGATE, ActionType.CONTAIN],
            }
        }
    }

    def __init__(self, task: str = "easy", seed: Optional[int] = None):
        if task not in self.TASKS:
            raise ValueError(f"Unknown task '{task}'. Choose from: {list(self.TASKS.keys())}")
        self.task_name = task
        self.task_cfg = self.TASKS[task]
        self.seed = seed
        if seed is not None:
            random.seed(seed)
        self._state: Optional[CyberSOCState] = None
        self._alerts_data: Dict[str, dict] = {}

    # ── OpenEnv API ────────────────────────────────────────────────────────

    def reset(self) -> StepResult:
        """Reset environment to initial state and return first observation."""
        episode_id = str(uuid.uuid4())[:8]
        alert_ids = self.task_cfg["alert_ids"]

        alerts = {}
        for aid in alert_ids:
            src = next(a for a in ALERT_LIBRARY if a["id"] == aid)
            alerts[aid] = {
                **src,
                "status": AlertStatus.NEW,
                "actions_taken": [],
                "analyst_notes": [],
                "log_queried": False,
                "timestamp": f"2024-04-07T14:{random.randint(10,59)}:00Z"
            }

        self._alerts_data = alerts
        self._randomize_alerts()  # 🎲 Top Tier: Procedural Variance

        self._state = CyberSOCState(
            episode_id=episode_id,
            task_name=self.task_name,
            step=0,
            max_steps=self.task_cfg["max_steps"],
            alerts={k: self._serialize_alert(v) for k, v in alerts.items()},
            resolved_alerts=[],
            false_positives_marked=[],
            escalated_alerts=[],
            contained_alerts=[],
            actions_taken=[],
            cumulative_reward=0.0,
            done=False,
        )

        obs = self._build_observation(
            step_result=f"🚨 SOC Shift Started | Episode {episode_id} | Task: {self.task_name.upper()}",
            action_feedback=f"You have {len(alert_ids)} alerts in queue. Begin triage. Task: {self.task_cfg['description']}",
            current_alert_id=alert_ids[0],
        )
        return StepResult(observation=obs, reward=0.0, done=False, info={"episode_id": episode_id})

    def step(self, action: CyberSOCAction) -> StepResult:
        """Execute one analyst action and return next observation."""
        if self._state is None:
            raise RuntimeError("Call reset() before step()")
        if self._state.done:
            raise RuntimeError("Episode is done. Call reset().")

        self._state.step += 1
        step = self._state.step

        reward, feedback, step_result, error = self._execute_action(action)

        self._state.cumulative_reward += reward
        self._state.actions_taken.append({
            "step": step,
            "action": action.action_type,
            "alert_id": action.alert_id,
            "reward": reward,
        })
        self._state.alerts = {k: self._serialize_alert(v) for k, v in self._alerts_data.items()}

        done = self._check_done()
        self._state.done = done

        obs = self._build_observation(
            step_result=step_result,
            action_feedback=feedback,
            current_alert_id=action.alert_id,
            error=error,
        )

        return StepResult(observation=obs, reward=round(reward, 4), done=done, info={
            "step": step,
            "cumulative_reward": self._state.cumulative_reward,
            "error": error,
        })

    def state(self) -> CyberSOCState:
        """Return full internal state snapshot."""
        if self._state is None:
            raise RuntimeError("Call reset() first.")
        return self._state

    def score(self) -> float:
        """Compute normalized final score [0.0, 1.0]."""
        if self._state is None:
            return 0.0001  # Minimum score even if not started
        score = self._compute_final_score()
        return round(min(max(score, 0.0001), 0.9999), 4)

    # ── Action Execution ───────────────────────────────────────────────────

    def _execute_action(self, action: CyberSOCAction):
        alert_id = action.alert_id
        act = action.action_type
        reward = 0.0
        feedback = ""
        step_result = ""
        error = None

        if alert_id not in self._alerts_data:
            return -0.1, f"❌ Alert {alert_id} not found in queue.", "Invalid alert ID.", "Alert not found"

        alert = self._alerts_data[alert_id]
        status = alert["status"]

        # ── TRIAGE ──
        if act == ActionType.TRIAGE:
            if status != AlertStatus.NEW:
                return -0.05, f"Alert {alert_id} already triaged (status: {status}).", "Redundant triage.", None
            alert["status"] = AlertStatus.INVESTIGATING
            if action.severity_assessment:
                correct_sev = alert["severity"]
                if action.severity_assessment == correct_sev:
                    reward = 0.15
                    feedback = f"✅ Correct severity: {correct_sev}. Alert moved to INVESTIGATING."
                elif abs(list(Severity).index(action.severity_assessment) - list(Severity).index(correct_sev)) == 1:
                    reward = 0.07
                    feedback = f"⚠️ Severity off by one tier. Actual: {correct_sev}."
                else:
                    reward = -0.05
                    feedback = f"❌ Incorrect severity. Actual: {correct_sev}. Miscategorization risks SLA breach."
            else:
                reward = 0.08
                feedback = f"Alert {alert_id} opened for investigation."
            step_result = f"TRIAGE → {alert_id}: {alert['title']}"
            alert["actions_taken"].append(ActionType.TRIAGE)

        # ── INVESTIGATE ──
        elif act == ActionType.INVESTIGATE:
            if ActionType.INVESTIGATE in alert["actions_taken"]:
                return 0.0, "Already investigated this alert.", "Duplicate investigate.", None
            alert["status"] = AlertStatus.INVESTIGATING
            reward = 0.20
            ioc = alert.get("ioc")
            mitre = alert.get("mitre")
            intel = ""
            if ioc:
                intel = f"🔍 IOC {ioc} flagged in ThreatFox (confidence: HIGH). "
            if mitre:
                intel += f"MITRE: {mitre} — {alert.get('attack_type', 'Unknown')}."
            feedback = f"Investigation opened. {intel} Query logs for deeper context."
            step_result = f"INVESTIGATE → {alert_id}"
            alert["actions_taken"].append(ActionType.INVESTIGATE)
            alert["analyst_notes"].append(f"Step {self._state.step}: Investigation initiated.")

        # ── QUERY LOGS ──
        elif act == ActionType.QUERY_LOGS:
            log_hints = LOG_DATABASE.get(alert_id, {})
            if not log_hints:
                return 0.0, "No logs available for this alert.", "No log data.", None
            if alert["log_queried"]:
                return 0.0, "Logs already retrieved.", "Duplicate log query.", None
            alert["log_queried"] = True
            reward = 0.15
            query_field = action.log_query or "all"
            if query_field in log_hints:
                log_out = {query_field: log_hints[query_field]}
            else:
                log_out = log_hints
            feedback = f"📋 Log data retrieved:\n" + "\n".join(f"  [{k.upper()}] {v}" for k, v in log_out.items())
            step_result = f"QUERY_LOGS → {alert_id}"
            alert["analyst_notes"].append(f"Step {self._state.step}: Logs retrieved.")

        # ── CONTAIN ──
        elif act == ActionType.CONTAIN:
            if alert_id in self._state.contained_alerts:
                return -0.02, "Already contained.", "Duplicate contain.", None
            if not alert["true_positive"]:
                reward = -0.20
                feedback = f"❌ WRONG: {alert_id} is a false positive! Containment on FP = operational disruption."
            else:
                reward = 0.25
                alert["status"] = AlertStatus.RESOLVED
                self._state.contained_alerts.append(alert_id)
                feedback = f"✅ Threat contained. Source blocked, host isolated. Great response time."
            step_result = f"CONTAIN → {alert_id}"
            alert["actions_taken"].append(ActionType.CONTAIN)

        # ── ESCALATE ──
        elif act == ActionType.ESCALATE:
            if alert_id in self._state.escalated_alerts:
                return -0.02, "Already escalated.", "Duplicate escalation.", None
            required = self.task_cfg["required_actions"].get(alert_id, [])
            if ActionType.ESCALATE in required:
                reward = 0.20
                self._state.escalated_alerts.append(alert_id)
                feedback = f"✅ Escalated to Tier-2/CISO. Correct for severity {alert['severity']}."
            else:
                reward = -0.10
                feedback = f"⚠️ Unnecessary escalation. This alert ({alert['severity']}) should be handled at Tier-1."
            step_result = f"ESCALATE → {alert_id}"
            alert["actions_taken"].append(ActionType.ESCALATE)

        # ── RESOLVE ──
        elif act == ActionType.RESOLVE:
            if status == AlertStatus.RESOLVED:
                return 0.0, "Already resolved.", "Duplicate resolve.", None
            alert["status"] = AlertStatus.RESOLVED
            self._state.resolved_alerts.append(alert_id)
            required = self.task_cfg["required_actions"].get(alert_id, [])
            actions_done = set(alert["actions_taken"])
            required_set = set(required)
            completion = len(actions_done & required_set) / max(len(required_set), 1)
            reward = 0.15 * completion
            feedback = f"Alert resolved. Completion: {completion*100:.0f}% of required steps."
            step_result = f"RESOLVE → {alert_id}"
            alert["actions_taken"].append(ActionType.RESOLVE)

        # ── WRITE REPORT ──
        elif act == ActionType.WRITE_REPORT:
            if ActionType.WRITE_REPORT in alert["actions_taken"]:
                return 0.0, "Report already written.", "Duplicate report.", None
            report = action.report_text or ""
            quality = self._score_report(report, alert)
            reward = 0.20 * quality
            feedback = f"📝 Report quality score: {quality:.2f}/1.0. {'Excellent detail!' if quality > 0.7 else 'Add more IOCs, timeline, and remediation steps.'}"
            step_result = f"WRITE_REPORT → {alert_id} (quality={quality:.2f})"
            alert["actions_taken"].append(ActionType.WRITE_REPORT)
            alert["analyst_notes"].append(f"Report filed at step {self._state.step}.")

        # ── MARK FALSE POSITIVE ──
        elif act == ActionType.MARK_FALSE_POSITIVE:
            if alert_id in self._state.false_positives_marked:
                return -0.02, "Already marked as FP.", "Duplicate FP mark.", None
            if not alert["true_positive"]:
                reward = 0.30
                alert["status"] = AlertStatus.FALSE_POSITIVE
                self._state.false_positives_marked.append(alert_id)
                feedback = f"✅ Correct! {alert_id} is a false positive. Good triage saves SOC bandwidth."
            else:
                reward = -0.25
                feedback = f"❌ WRONG: {alert_id} is a REAL THREAT marked as FP. Major miss!"
            step_result = f"MARK_FP → {alert_id}"
            alert["actions_taken"].append(ActionType.MARK_FALSE_POSITIVE)

        # ⏳ Top Tier: Efficiency Policy (-0.01 per step penalty)
        reward -= 0.01
        self._state.cumulative_reward += reward
        
        return reward, feedback, step_result, error

    def _randomize_alerts(self):
        """Inject randomized IOCs and logs per episode to increase variance."""
        for alert in self._alerts_data.values():
            if alert["source_ip"]:
                parts = alert["source_ip"].split(".")
                parts[-1] = str(random.randint(1, 254))
                alert["source_ip"] = ".".join(parts)
            if alert["ioc"]:
                # Keep the same pattern but change specific IP/domain if it looks like one
                if "." in alert["ioc"] and not alert["ioc"].endswith(".com"):
                    parts = alert["ioc"].split(".")
                    parts[-1] = str(random.randint(1, 254))
                    alert["ioc"] = ".".join(parts)

    # ── Scoring & Done ─────────────────────────────────────────────────────

    def _check_done(self) -> bool:
        if self._state.step >= self._state.max_steps:
            return True
        # 🏁 Episode Boundary Fix: Smarter termination
        # All TP alerts are contained & escalated/resolved, all FP alerts are marked FP
        finished_alerts = 0
        for alert in self._alerts_data.values():
            if alert["true_positive"]:
                is_handled = (alert["status"] in [AlertStatus.RESOLVED, AlertStatus.ESCALATED]) or (ActionType.CONTAIN in alert["actions_taken"])
                if is_handled: finished_alerts += 1
            else:
                if alert["status"] == AlertStatus.FALSE_POSITIVE: finished_alerts += 1
        
        return finished_alerts == len(self._alerts_data)

    def _compute_final_score(self) -> float:
        total_possible = 0.0
        total_earned = 0.0

        for aid, required_acts in self.task_cfg["required_actions"].items():
            alert = self._alerts_data.get(aid, {})
            actions_done = set(alert.get("actions_taken", []))
            for act in required_acts:
                total_possible += 1.0
                if act in actions_done:
                    total_earned += 1.0

        # Bonus for log queries on TP alerts
        for aid, alert in self._alerts_data.items():
            if alert["true_positive"] and alert.get("log_queried"):
                total_earned += 0.5
                total_possible += 0.5

        # Penalty for FP actions on TP alerts
        for aid in self._state.false_positives_marked:
            if self._alerts_data[aid]["true_positive"]:
                total_earned -= 1.0

        raw = total_earned / max(total_possible, 1.0)
        # 🔗 Scoring Range Fix: Ensure score is strictly in (0, 1) per OpenEnv Phase 2 specs
        return round(min(max(raw, 0.0001), 0.9999), 4)

    def _score_report(self, report: str, alert: dict) -> float:
        """Score report quality based on key elements present."""
        if not report or len(report) < 50:
            return 0.1
        score = 0.0
        report_lower = report.lower()
        # Check for key report elements
        if alert.get("ioc") and alert["ioc"].lower() in report_lower:
            score += 0.2
        if alert.get("mitre") and alert["mitre"].lower() in report_lower:
            score += 0.15
        if alert.get("attack_type") and alert["attack_type"].lower() in report_lower:
            score += 0.15
        
        # 🛡️ Top Tier: Context-aware keywords
        mandatory_for_hard = ["remediation", "timeline", "impact", "root cause"]
        if self.task_name == "hard":
            for kw in mandatory_for_hard:
                if kw in report_lower: score += 0.05
            if len(report) < 200: score *= 0.8 # Penalty for short reports on hard tasks
        
        keywords = ["affected", "recommend", "action", "investigation"]
        found = sum(1 for k in keywords if k in report_lower)
        score += min(found / len(keywords), 0.5)
        return round(min(score, 1.0), 3)

    # ── Observation Builder ────────────────────────────────────────────────

    def _build_observation(self, step_result: str, action_feedback: str,
                            current_alert_id: Optional[str] = None,
                            error: Optional[str] = None) -> CyberSOCObservation:
        active_alerts = []
        for aid, alert in self._alerts_data.items():
            log_data = None
            if alert.get("log_queried"):
                log_data = LOG_DATABASE.get(aid)
            active_alerts.append(AlertObservation(
                alert_id=aid,
                title=alert["title"],
                description=alert["description"],
                source_ip=alert.get("source_ip"),
                dest_ip=alert.get("dest_ip"),
                severity=alert["severity"],
                status=alert["status"],
                mitre_technique=alert.get("mitre"),
                available_actions=[a.value for a in ActionType],
                log_data=log_data,
                analyst_notes=alert.get("analyst_notes", []),
            ))

        step = self._state.step if self._state else 0
        max_steps = self._state.max_steps if self._state else 12
        metrics = {
            "step": step,
            "max_steps": max_steps,
            "cumulative_reward": round(self._state.cumulative_reward if self._state else 0.0, 4),
            "alerts_total": len(self._alerts_data),
            "alerts_resolved": len([a for a in self._alerts_data.values()
                                    if a["status"] in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]]),
            "contained": len(self._state.contained_alerts) if self._state else 0,
            "escalated": len(self._state.escalated_alerts) if self._state else 0,
        }

        threat_intel = None
        if current_alert_id and current_alert_id in self._alerts_data:
            a = self._alerts_data[current_alert_id]
            if a.get("ioc"):
                threat_intel = f"ThreatFox: {a['ioc']} — HIGH confidence malicious. MITRE: {a.get('mitre', 'N/A')}"

        return CyberSOCObservation(
            active_alerts=active_alerts,
            current_alert_id=current_alert_id,
            step_result=step_result,
            action_feedback=action_feedback,
            threat_intel=threat_intel,
            metrics=metrics,
            queue_depth=len([a for a in self._alerts_data.values() if a["status"] == AlertStatus.NEW]),
            shift_time_remaining=max_steps - step,
        )

    def _serialize_alert(self, alert: dict) -> dict:
        """Convert alert to JSON-serializable dict."""
        out = {}
        for k, v in alert.items():
            if isinstance(v, Enum):
                out[k] = v.value
            elif isinstance(v, list):
                out[k] = [x.value if isinstance(x, Enum) else x for x in v]
            else:
                out[k] = v
        return out
