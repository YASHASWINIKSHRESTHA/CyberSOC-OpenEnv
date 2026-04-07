"""
CyberSOC-OpenEnv Graders
Three graders (easy / medium / hard) with deterministic, reproducible scoring.
Each grader runs a full episode and returns a score in [0.0, 1.0].
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_soc_env import CyberSOCEnv
from models import (
    ActionType, CyberSOCAction, Severity
)


# ─────────────────────────────────────────────────────────────────────────────
# Grader base
# ─────────────────────────────────────────────────────────────────────────────

class BaseGrader:
    task: str = ""

    def run(self) -> float:
        env = CyberSOCEnv(task=self.task, seed=42)
        env.reset()
        self._play(env)
        score = env.score()
        return round(score, 4)

    def _play(self, env: CyberSOCEnv):
        raise NotImplementedError

    def _act(self, env, **kwargs):
        action = CyberSOCAction(**kwargs)
        return env.step(action)


# ─────────────────────────────────────────────────────────────────────────────
# Easy grader — perfect agent
# ─────────────────────────────────────────────────────────────────────────────

class EasyGraderPerfect(BaseGrader):
    """
    Perfect agent for easy task.
    Expected score: ~1.0
    ALT-003 = false positive (EICAR test)
    ALT-002 = brute force SSH → investigate + contain
    """
    task = "easy"

    def _play(self, env):
        # ALT-003: investigate then mark as false positive
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-003",
                  reasoning="Checking EICAR alert context before acting")
        self._act(env, action_type=ActionType.QUERY_LOGS, alert_id="ALT-003",
                  log_query="av", reasoning="Reviewing AV log details")
        self._act(env, action_type=ActionType.MARK_FALSE_POSITIVE, alert_id="ALT-003",
                  reasoning="EICAR test file by developer, not a real threat")

        # ALT-002: investigate + contain brute force
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-002",
                  reasoning="1247 SSH failures in 10 min = brute force, very likely malicious")
        self._act(env, action_type=ActionType.QUERY_LOGS, alert_id="ALT-002",
                  log_query="auth", reasoning="Review auth log to confirm brute force pattern")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-002",
                  reasoning="Block source IP, known scanner range attacking prod-db-01")
        self._act(env, action_type=ActionType.RESOLVE, alert_id="ALT-002",
                  reasoning="Contained and documented")


class EasyGraderPartial(BaseGrader):
    """
    Partial agent — handles only one alert correctly.
    Expected score: ~0.4–0.6
    """
    task = "easy"

    def _play(self, env):
        # Only handles the FP, misses the brute force
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-003")
        self._act(env, action_type=ActionType.MARK_FALSE_POSITIVE, alert_id="ALT-003")
        # Incorrectly marks brute force as FP too — penalty
        self._act(env, action_type=ActionType.MARK_FALSE_POSITIVE, alert_id="ALT-002")


class EasyGraderPoor(BaseGrader):
    """
    Poor agent — wrong on both.
    Expected score: ~0.0–0.1
    """
    task = "easy"

    def _play(self, env):
        # Contains the false positive — wrong!
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-003")
        # Marks real brute force as FP — wrong!
        self._act(env, action_type=ActionType.MARK_FALSE_POSITIVE, alert_id="ALT-002")


# ─────────────────────────────────────────────────────────────────────────────
# Medium grader
# ─────────────────────────────────────────────────────────────────────────────

class MediumGraderPerfect(BaseGrader):
    """
    Perfect agent for medium task.
    ALT-006: phishing → investigate + contain + escalate
    ALT-001: malware dropper → investigate + contain + escalate
    Expected score: ~1.0
    """
    task = "medium"

    def _play(self, env):
        # ALT-006: phishing campaign
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-006",
                  reasoning="34 employees targeted by lookalike domain phishing")
        self._act(env, action_type=ActionType.QUERY_LOGS, alert_id="ALT-006",
                  log_query="clicks", reasoning="Check who clicked the link")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-006",
                  reasoning="Block domain micros0ft-login.com, reset credentials for 2 affected users")
        self._act(env, action_type=ActionType.ESCALATE, alert_id="ALT-006",
                  reasoning="Credential harvesting of 2 users requires CISO notification")

        # ALT-001: PowerShell dropper
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-001",
                  reasoning="Encoded PowerShell + outbound C2 traffic = active malware")
        self._act(env, action_type=ActionType.QUERY_LOGS, alert_id="ALT-001",
                  log_query="process_tree", reasoning="Map full process tree for scope")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-001",
                  reasoning="Isolate WS-042, block C2 IP 185.220.101.45 (Tor exit node)")
        self._act(env, action_type=ActionType.ESCALATE, alert_id="ALT-001",
                  reasoning="Active malware with C2 communication requires Tier-2 IR team")


class MediumGraderPartial(BaseGrader):
    """Partial agent — investigates but forgets escalation."""
    task = "medium"

    def _play(self, env):
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-006")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-006")
        # Forgot to escalate ALT-006
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-001")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-001")
        self._act(env, action_type=ActionType.ESCALATE, alert_id="ALT-001")


# ─────────────────────────────────────────────────────────────────────────────
# Hard grader
# ─────────────────────────────────────────────────────────────────────────────

class HardGraderPerfect(BaseGrader):
    """
    Perfect agent for hard task (APT chain).
    ALT-004: S3 exfil → investigate + contain + escalate + report
    ALT-005: lateral movement → investigate + contain + escalate + report
    ALT-001: initial access → investigate + contain
    Expected score: ~1.0
    """
    task = "hard"

    def _play(self, env):
        # ALT-004: Data exfiltration
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-004",
                  reasoning="IAM user downloading 47GB in 8 min from anomalous geo = exfil")
        self._act(env, action_type=ActionType.QUERY_LOGS, alert_id="ALT-004",
                  log_query="cloudtrail", reasoning="CloudTrail confirms 18k GetObject calls")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-004",
                  reasoning="Disable svc-backup IAM user, revoke sessions, block 203.0.113.99")
        self._act(env, action_type=ActionType.ESCALATE, alert_id="ALT-004",
                  reasoning="PII/PCI data exfiltration = mandatory breach notification, CISO + Legal")
        self._act(env, action_type=ActionType.WRITE_REPORT, alert_id="ALT-004",
                  report_text=(
                      "INCIDENT REPORT — ALT-004: Data Exfiltration via Compromised IAM\n"
                      "Timeline: svc-backup IAM user downloaded 47GB from prod-customer-data S3 "
                      "bucket over 8 minutes from IP 203.0.113.99 (Romania). Normal usage: US-East-1.\n"
                      "IOC: 203.0.113.99 | Attack type: Data Exfiltration (T1567.002)\n"
                      "Impact: PII and PCI data in scope. 18,432 GetObject API calls via CloudTrail.\n"
                      "Affected systems: prod-customer-data S3 bucket, svc-backup IAM role\n"
                      "Remediation: IAM user disabled, sessions revoked, IP blocked. "
                      "Recommend: Enable MFA on all service accounts, implement geo-restriction policies, "
                      "activate breach notification procedure per GDPR/PCI-DSS timeline requirements."
                  ))

        # ALT-005: Lateral movement
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-005",
                  reasoning="WMI execution HR→Finance = lateral movement, likely pass-the-hash")
        self._act(env, action_type=ActionType.QUERY_LOGS, alert_id="ALT-005",
                  log_query="edr", reasoning="EDR shows Mimikatz artifacts = credential theft confirmed")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-005",
                  reasoning="Isolate HR-PC-012 and FIN-SRV-01, reset CORP\\svc-admin credentials")
        self._act(env, action_type=ActionType.ESCALATE, alert_id="ALT-005",
                  reasoning="Mimikatz + lateral to finance server = full IR team activation needed")
        self._act(env, action_type=ActionType.WRITE_REPORT, alert_id="ALT-005",
                  report_text=(
                      "INCIDENT REPORT — ALT-005: Lateral Movement via Pass-the-Hash\n"
                      "Timeline: Compromised host HR-PC-012 performed WMI remote execution against "
                      "FIN-SRV-01. EDR confirmed Mimikatz (sekurlsa::logonpasswords) artifacts on source.\n"
                      "IOC: 192.168.30.12 (HR-PC-012) | MITRE: T1550.002 (Pass-the-Hash)\n"
                      "Attack type: Lateral Movement | Impact: Finance server potentially compromised\n"
                      "Affected systems: HR-PC-012, FIN-SRV-01, CORP\\svc-admin credential\n"
                      "Timeline correlation: Part of APT chain from ALT-001 initial compromise.\n"
                      "Remediation: Isolate both hosts, reset all NTLM credentials, deploy "
                      "Credential Guard, recommend full forensic imaging of both systems. "
                      "Action: IR team engaged, threat hunting across domain for additional PTH activity."
                  ))

        # ALT-001: Initial access
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-001",
                  reasoning="This is the initial access vector for the APT chain")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-001",
                  reasoning="Isolate WS-042 (patient zero), block C2 IP")


class HardGraderPartial(BaseGrader):
    """Partial hard agent — handles exfil well, misses lateral movement reporting."""
    task = "hard"

    def _play(self, env):
        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-004")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-004")
        self._act(env, action_type=ActionType.ESCALATE, alert_id="ALT-004")
        # No report for ALT-004

        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-005")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-005")
        # No escalate, no report for ALT-005

        self._act(env, action_type=ActionType.INVESTIGATE, alert_id="ALT-001")
        self._act(env, action_type=ActionType.CONTAIN, alert_id="ALT-001")


# ─────────────────────────────────────────────────────────────────────────────
# Grader registry & runner
# ─────────────────────────────────────────────────────────────────────────────

GRADERS = {
    "easy_perfect":   EasyGraderPerfect,
    "easy_partial":   EasyGraderPartial,
    "easy_poor":      EasyGraderPoor,
    "medium_perfect": MediumGraderPerfect,
    "medium_partial": MediumGraderPartial,
    "hard_perfect":   HardGraderPerfect,
    "hard_partial":   HardGraderPartial,
}


def run_all_graders(verbose: bool = True) -> dict:
    results = {}
    for name, GraderClass in GRADERS.items():
        grader = GraderClass()
        score = grader.run()
        results[name] = score
        if verbose:
            task_part = name.split("_")[0]
            quality = name.split("_")[1]
            emoji = "✅" if quality == "perfect" else ("⚠️" if quality == "partial" else "❌")
            print(f"  {emoji} {name:25s} → score={score:.4f}")
    return results


if __name__ == "__main__":
    print("\n🔒 CyberSOC-OpenEnv Grader Suite\n" + "─" * 50)
    results = run_all_graders(verbose=True)
    print("\n📊 Summary:")
    print(f"  Easy   perfect: {results['easy_perfect']:.4f}")
    print(f"  Easy   partial: {results['easy_partial']:.4f}")
    print(f"  Easy   poor:    {results['easy_poor']:.4f}")
    print(f"  Medium perfect: {results['medium_perfect']:.4f}")
    print(f"  Medium partial: {results['medium_partial']:.4f}")
    print(f"  Hard   perfect: {results['hard_perfect']:.4f}")
    print(f"  Hard   partial: {results['hard_partial']:.4f}")

    # Validate score ordering
    assert results["easy_perfect"] > results["easy_partial"] > results["easy_poor"], \
        "Easy grader ordering violated!"
    assert results["medium_perfect"] > results["medium_partial"], \
        "Medium grader ordering violated!"
    assert results["hard_perfect"] > results["hard_partial"], \
        "Hard grader ordering violated!"
    print("\n✅ All grader assertions passed!")
