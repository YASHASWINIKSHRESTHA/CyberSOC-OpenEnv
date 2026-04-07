"""
CyberSOC-OpenEnv FastAPI Server
Exposes: POST /reset, POST /step, GET /state, GET /tasks, GET /health
Compliant with OpenEnv spec + openenv.yaml
"""

from __future__ import annotations

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# app.mount("/static", StaticFiles(directory="static"), name="static")  # moved below app definition
from pydantic import BaseModel

from cyber_soc_env import (
    ActionType,
    CyberSOCAction,
    CyberSOCEnv,
    Severity,
    StepResult,
)

# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CyberSOC-OpenEnv",
    description="Cybersecurity SOC Incident Response — OpenEnv compatible environment",
    version="1.0.0",
)
# Mount static files directory for UI assets
app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global env registry (one per task for simplicity; production would use sessions)
_envs: Dict[str, CyberSOCEnv] = {}
_last_results: Dict[str, StepResult] = {}

VALID_TASKS = ["easy", "medium", "hard"]

# ─────────────────────────────────────────────────────────────────────────────
# Request/Response schemas
# ─────────────────────────────────────────────────────────────────────────────

class ResetRequest(BaseModel):
    task: str = "easy"
    seed: Optional[int] = None

class StepRequest(BaseModel):
    task: str = "easy"
    action_type: str
    alert_id: str
    severity_assessment: Optional[str] = None
    log_query: Optional[str] = None
    report_text: Optional[str] = None
    reasoning: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# OpenEnv endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "env": "CyberSOC-OpenEnv", "version": "1.0.0"}

@app.get("/")
async def root():
    # Serve the UI HTML file
    with open("static/index.html", "r", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(content=html, media_type="text/html")

@app.post("/reset")
async def reset(req: ResetRequest):
    if req.task not in VALID_TASKS:
        raise HTTPException(400, f"Invalid task '{req.task}'. Choose from: {VALID_TASKS}")
    env = CyberSOCEnv(task=req.task, seed=req.seed)
    _envs[req.task] = env
    result = env.reset()
    _last_results[req.task] = result
    return result.model_dump()

@app.post("/step")
async def step(req: StepRequest):
    task = req.task
    if task not in _envs:
        raise HTTPException(400, f"No active episode for task '{task}'. Call /reset first.")
    env = _envs[task]

    # Validate action type
    try:
        act_type = ActionType(req.action_type)
    except ValueError:
        raise HTTPException(400, f"Invalid action_type '{req.action_type}'. Valid: {[a.value for a in ActionType]}")

    # Validate severity if provided
    sev = None
    if req.severity_assessment:
        try:
            sev = Severity(req.severity_assessment)
        except ValueError:
            raise HTTPException(400, f"Invalid severity '{req.severity_assessment}'")

    action = CyberSOCAction(
        action_type=act_type,
        alert_id=req.alert_id,
        severity_assessment=sev,
        log_query=req.log_query,
        report_text=req.report_text,
        reasoning=req.reasoning,
    )

    try:
        result = env.step(action)
    except RuntimeError as e:
        raise HTTPException(400, str(e))

    _last_results[task] = result

    resp = result.model_dump()
    if result.done:
        resp["final_score"] = env.score()

    return resp

@app.get("/state")
async def state(task: str = "easy"):
    if task not in _envs:
        raise HTTPException(400, f"No active episode for task '{task}'. Call /reset first.")
    return _envs[task].state().model_dump()

@app.get("/score")
async def score(task: str = "easy"):
    if task not in _envs:
        raise HTTPException(400, f"No active episode for task '{task}'.")
    env = _envs[task]
    return {"task": task, "score": env.score(), "step": env.state().step}

@app.get("/tasks")
async def list_tasks():
    return {
        "tasks": [
            {
                "name": "easy",
                "description": "Triage 2 alerts (1 false positive + 1 brute-force). Identify the FP, contain the threat.",
                "difficulty": "easy",
                "max_steps": 12,
                "alerts": ["ALT-003", "ALT-002"],
                "expected_score_range": [0.7, 1.0],
            },
            {
                "name": "medium",
                "description": "Phishing campaign + malware dropper. Investigate, contain, escalate both.",
                "difficulty": "medium",
                "max_steps": 18,
                "alerts": ["ALT-006", "ALT-001"],
                "expected_score_range": [0.4, 0.8],
            },
            {
                "name": "hard",
                "description": "Full APT chain: data exfiltration + lateral movement + initial access. Report required.",
                "difficulty": "hard",
                "max_steps": 25,
                "alerts": ["ALT-004", "ALT-005", "ALT-001"],
                "expected_score_range": [0.2, 0.6],
            },
        ]
    }

@app.get("/openenv.yaml", response_class=HTMLResponse)
async def openenv_yaml():
    content = open("openenv.yaml").read()
    return HTMLResponse(content=content, media_type="text/yaml")


@app.get("/health")
async def health_check():
    return {"status": "ok"}


def main():
    port = int(os.getenv("PORT", 7860))
    uvicorn.run("server.app:app", host="0.0.0.0", port=port, reload=False)

if __name__ == "__main__":
    main()
