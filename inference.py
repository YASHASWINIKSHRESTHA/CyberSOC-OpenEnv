"""
CyberSOC-OpenEnv Inference Script
===================================
Runs an LLM agent as a Tier-1 SOC Analyst against all three tasks.

MANDATORY ENVIRONMENT VARIABLES:
    API_BASE_URL   The API endpoint for the LLM (default: HuggingFace router)
    MODEL_NAME     The model identifier (default: Qwen/Qwen2.5-72B-Instruct)
    HF_TOKEN       Your HuggingFace / API key

STDOUT FORMAT (strictly followed):
    [START] task=<task_name> env=cybersoc model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

import os
import sys
import json
import textwrap
from typing import List, Optional, Dict, Any

from openai import OpenAI
from cyber_soc_env import (
    ActionType, CyberSOCAction, CyberSOCEnv, Severity, StepResult
)

# ── Config ─────────────────────────────────────────────────────────────────
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY") or "hf_placeholder"
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
BENCHMARK = "cybersoc"
TEMPERATURE = 0.3
MAX_TOKENS = 512
SUCCESS_SCORE_THRESHOLD = 0.5

TASKS_TO_RUN = ["easy", "medium", "hard"]

# ── Logging ────────────────────────────────────────────────────────────────

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

# ── Prompts ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""
You are an expert Tier-1 SOC (Security Operations Center) Analyst with 5+ years of experience.
You analyze security alerts, investigate incidents using logs and threat intelligence, and respond to cybersecurity threats.

Your available actions:
- triage: Initial classification with severity assessment (LOW/MEDIUM/HIGH/CRITICAL)
- investigate: Open a full investigation on an alert
- query_logs: Pull specific log data (auth, network, file, process_tree, cloudtrail, edr, etc.)
- contain: Isolate/block the threat (use only for TRUE POSITIVES)
- escalate: Escalate to Tier-2/CISO (use for HIGH/CRITICAL confirmed threats)
- resolve: Close the alert after handling
- write_report: Write a formal incident report (required for critical incidents)
- mark_false_positive: Mark alert as FP (use only when you are CERTAIN it's benign)

Response format — output ONLY valid JSON:
{
  "action_type": "<action>",
  "alert_id": "<ALT-XXX>",
  "severity_assessment": "<LOW|MEDIUM|HIGH|CRITICAL|null>",
  "log_query": "<field_name_or_null>",
  "report_text": "<full_report_or_null>",
  "reasoning": "<your chain-of-thought>"
}

CRITICAL RULES:
1. Never contain or escalate without investigating first
2. Query logs before making containment decisions on ambiguous alerts
3. False positive marking on a real threat = catastrophic miss
4. Write detailed reports for HIGH/CRITICAL incidents (include IOCs, timeline, remediation)
5. Escalate CRITICAL severity confirmed threats always
""").strip()


def build_user_prompt(obs: Any, step: int, history: List[str]) -> str:
    alerts_summary = []
    for alert in obs.active_alerts:
        summary = (
            f"  [{alert.alert_id}] {alert.title}\n"
            f"    Status: {alert.status} | Severity: {alert.severity}\n"
            f"    Description: {alert.description}\n"
            f"    Source: {alert.source_ip or 'N/A'} → Dest: {alert.dest_ip or 'N/A'}\n"
            f"    MITRE: {alert.mitre_technique or 'Unknown'}"
        )
        if alert.log_data:
            log_lines = "\n".join(f"      [{k}] {v}" for k, v in alert.log_data.items())
            summary += f"\n    LOG DATA:\n{log_lines}"
        if alert.analyst_notes:
            summary += f"\n    Notes: {'; '.join(alert.analyst_notes[-2:])}"
        alerts_summary.append(summary)

    history_block = "\n".join(history[-6:]) if history else "None"

    return textwrap.dedent(f"""
STEP {step} | Queue depth: {obs.queue_depth} | Time remaining: {obs.shift_time_remaining} steps
Cumulative reward: {obs.metrics.get('cumulative_reward', 0):.2f}

LAST ACTION RESULT: {obs.step_result}
FEEDBACK: {obs.action_feedback}
{f'THREAT INTEL: {obs.threat_intel}' if obs.threat_intel else ''}

ACTIVE ALERTS:
{chr(10).join(alerts_summary)}

ACTION HISTORY (last 6):
{history_block}

Choose your next action. Output ONLY the JSON object.
""").strip()


# ── LLM Agent ─────────────────────────────────────────────────────────────

def get_agent_action(
    client: OpenAI,
    obs: Any,
    step: int,
    history: List[str],
    task: str,
) -> CyberSOCAction:
    """Call LLM and parse response into a CyberSOCAction."""
    user_prompt = build_user_prompt(obs, step, history)

    # Find a reasonable default alert to act on
    pending_alerts = [
        a for a in obs.active_alerts
        if a.status not in ["RESOLVED", "FALSE_POSITIVE"]
    ]
    default_alert_id = pending_alerts[0].alert_id if pending_alerts else obs.active_alerts[0].alert_id

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        raw = (completion.choices[0].message.content or "").strip()

        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        data = json.loads(raw)

        # Validate and build action
        act_type = ActionType(data.get("action_type", "investigate"))
        alert_id = data.get("alert_id", default_alert_id)
        sev = None
        if data.get("severity_assessment") and data["severity_assessment"] not in [None, "null"]:
            try:
                sev = Severity(data["severity_assessment"])
            except ValueError:
                pass

        return CyberSOCAction(
            action_type=act_type,
            alert_id=alert_id,
            severity_assessment=sev,
            log_query=data.get("log_query"),
            report_text=data.get("report_text"),
            reasoning=data.get("reasoning", ""),
        )

    except json.JSONDecodeError:
        # Fallback: investigate first pending alert
        print(f"[DEBUG] JSON parse failed, using fallback action", flush=True)
        return CyberSOCAction(
            action_type=ActionType.INVESTIGATE,
            alert_id=default_alert_id,
            reasoning="Fallback: JSON parse error",
        )
    except Exception as exc:
        print(f"[DEBUG] LLM call failed: {exc}", flush=True)
        return CyberSOCAction(
            action_type=ActionType.INVESTIGATE,
            alert_id=default_alert_id,
            reasoning=f"Fallback: {exc}",
        )


# ── Episode Runner ─────────────────────────────────────────────────────────

def run_episode(client: OpenAI, task: str) -> None:
    """Run a single episode and emit [START], [STEP]*, [END]."""
    env = CyberSOCEnv(task=task, seed=42)
    task_cfg = CyberSOCEnv.TASKS[task]
    max_steps = task_cfg["max_steps"]

    rewards: List[float] = []
    history: List[str] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=task, env=BENCHMARK, model=MODEL_NAME)

    try:
        result = env.reset()
        obs = result.observation

        for step in range(1, max_steps + 1):
            if result.done:
                break

            action = get_agent_action(client, obs, step, history, task)

            result = env.step(action)
            obs = result.observation

            reward = result.reward or 0.0
            done = result.done
            error = result.info.get("error")

            rewards.append(reward)
            steps_taken = step

            action_str = f"{action.action_type.value}('{action.alert_id}')"
            log_step(step=step, action=action_str, reward=reward, done=done, error=error)

            history.append(
                f"Step {step}: {action.action_type.value}({action.alert_id}) → reward={reward:+.2f} | {obs.action_feedback[:80]}"
            )

            if done:
                break

        score = env.score()
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as exc:
        print(f"[DEBUG] Episode error: {exc}", flush=True)

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    # Determine which tasks to run
    task_env = os.getenv("CYBERSOC_TASK", "all")
    if task_env == "all":
        tasks = TASKS_TO_RUN
    elif task_env in TASKS_TO_RUN:
        tasks = [task_env]
    else:
        print(f"[DEBUG] Unknown task '{task_env}', running all tasks.", flush=True)
        tasks = TASKS_TO_RUN

    for task in tasks:
        run_episode(client, task)


if __name__ == "__main__":
    main()
