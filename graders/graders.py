'''CyberSOC-OpenEnv Graders
Three graders (easy / medium / hard) with deterministic, reproducible scoring.
Each grader runs a full episode and returns a score in [0.0, 1.0].

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_soc_env import (
    ActionType, CyberSOCAction, CyberSOCEnv, Severity
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

# ... (rest of original graders.py content unchanged) ...
'''
