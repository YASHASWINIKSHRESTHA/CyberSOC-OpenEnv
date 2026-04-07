---
title: CyberSOC-OpenEnv
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
tags:
  - openenv
---
# 🛡️ CyberSOC-OpenEnv

**A real-world Cybersecurity Security Operations Center (SOC) environment for training and evaluating AI agents.**

An AI agent acts as a **Tier-1 SOC Analyst** — triaging security alerts, investigating incidents using log data and threat intelligence, containing threats, escalating critical incidents, identifying false positives, and writing formal incident reports.

> This simulates the **exact daily workflow** of enterprise SOC teams in Fortune 500 companies worldwide.

## 🔗 Live Demo
Access the interactive SOC Tactical Dashboard on Hugging Face Spaces:  
**[ykshrestha/CyberSOC-OpenEnv](https://huggingface.co/spaces/ykshrestha/CyberSOC-OpenEnv)**

[![OpenEnv](https://img.shields.io/badge/OpenEnv-Compliant-00d4ff?style=flat-square)](https://openenv.org)
[![Tasks](https://img.shields.io/badge/Tasks-3%20(Easy%20→%20Hard)-green?style=flat-square)](#tasks)
[![HF Space](https://img.shields.io/badge/HuggingFace-Space-yellow?style=flat-square)](https://huggingface.co/spaces/ykshrestha/CyberSOC-OpenEnv)

---

## 🎯 Why CyberSOC?

Cybersecurity incident response is one of the most high-stakes, cognitively demanding real-world tasks humans perform daily. SOC analysts must:

- **Triage** 50–200 alerts per shift under time pressure
- **Investigate** using multi-source evidence (logs, network traffic, EDR telemetry, threat intel)
- **Distinguish** real threats from false positives (FP rate in enterprise SOCs: ~70%)
- **Contain** threats before they spread laterally
- **Escalate** appropriately without crying wolf
- **Document** everything for compliance and forensics

This environment gives AI agents a realistic, reward-dense training ground for all of the above — with **graded partial credit**, **multi-step reasoning requirements**, and **genuine difficulty progression**.

---

## 🏗️ Environment Design

### Alert Library

6 realistic alerts modeled on real-world SIEM use cases:

| Alert | Type | Severity | True Positive |
|-------|------|----------|---------------|
| ALT-001 | PowerShell encoded dropper + C2 | HIGH | ✅ Yes |
| ALT-002 | SSH brute force (1,247 attempts) | MEDIUM | ✅ Yes |
| ALT-003 | EICAR test file detection | LOW | ❌ No (FP) |
| ALT-004 | S3 data exfiltration (47GB, anomalous geo) | CRITICAL | ✅ Yes |
| ALT-005 | Pass-the-Hash lateral movement to finance | CRITICAL | ✅ Yes |
| ALT-006 | Phishing campaign (34 targets, 2 compromised) | HIGH | ✅ Yes |

Each alert includes:
- Full log evidence (process trees, auth logs, CloudTrail, EDR artifacts)
- MITRE ATT&CK technique mapping
- IOC data (IPs, domains, hashes)
- Correct action sequence for full credit

### Action Space

```python
class ActionType(Enum):
    TRIAGE = "triage"              # Classify severity
    INVESTIGATE = "investigate"    # Open investigation
    QUERY_LOGS = "query_logs"      # Pull specific log data
    CONTAIN = "contain"            # Isolate/block threat
    ESCALATE = "escalate"          # Escalate to Tier-2/CISO
    RESOLVE = "resolve"            # Close the alert
    WRITE_REPORT = "write_report"  # File incident report
    MARK_FALSE_POSITIVE = "mark_false_positive"  # Mark as FP
```

### Observation Space

Each step returns a rich `CyberSOCObservation` including:
- All active alerts with current status
- Log data (after `query_logs` action)
- Threat intelligence for IOCs
- Step feedback with detailed guidance
- Episode metrics (step count, rewards, resolution rate)

### Reward Function

Dense rewards on every step — no sparse end-of-episode signals:

| Action | Reward |
|--------|--------|
| Correct severity triage | +0.15 |
| Off-by-one severity | +0.07 |
| Wrong severity | -0.05 |
| Investigate | +0.20 |
| Query logs (TP alert) | +0.15 |
| Correct containment | +0.25 |
| Contain false positive | **-0.20** |
| Correct escalation | +0.20 |
| Unnecessary escalation | -0.10 |
| Correct FP identification | **+0.30** |
| Miss real threat as FP | **-0.25** |
| Report quality (scaled) | 0.0–0.20 |

---

## 📋 Tasks

### Easy — FP Triage (`task=easy`)
**Alerts:** ALT-003 (EICAR FP), ALT-002 (SSH Brute Force)  
**Max steps:** 12  
**Success threshold:** 0.6  
**What's tested:** Can the agent distinguish benign from malicious? Will it investigate before acting?

**Optimal sequence:**
1. `investigate(ALT-003)` → `query_logs(ALT-003, "av")` → `mark_false_positive(ALT-003)`
2. `investigate(ALT-002)` → `query_logs(ALT-002, "auth")` → `contain(ALT-002)` → `resolve(ALT-002)`

**Expected scores:** Perfect agent: 1.0 | Partial: ~0.5 | Random: ~0.0

---

### Medium — Phishing + Malware (`task=medium`)
**Alerts:** ALT-006 (Phishing), ALT-001 (PowerShell Dropper)  
**Max steps:** 18  
**Success threshold:** 0.5  
**What's tested:** Multi-alert coordination, proper escalation of HIGH severity, log depth.

**Optimal sequence:**
1. Investigate → query logs → contain → escalate for ALT-006
2. Investigate → query logs → contain → escalate for ALT-001

**Expected scores:** Perfect: 1.0 | Partial: ~0.65 | Random: ~0.1

---

### Hard — APT Chain Response (`task=hard`)
**Alerts:** ALT-004 (S3 Exfil), ALT-005 (Lateral Movement), ALT-001 (Initial Access)  
**Max steps:** 25  
**Success threshold:** 0.4  
**What's tested:** Full APT chain understanding, report writing quality, PCI/GDPR breach process.

**Optimal sequence:**
- Investigate → query_logs → contain → escalate → **write_report** for ALT-004 and ALT-005
- Investigate → contain for ALT-001 (patient zero)
- Reports must include: IOCs, MITRE technique, timeline, affected systems, remediation

**Expected scores:** Perfect: 1.0 | Partial: ~0.55 | Random: ~0.0

---

## 🚀 API Reference

### `POST /reset`
```json
{ "task": "easy", "seed": 42 }
```

### `POST /step`
```json
{
  "task": "easy",
  "action_type": "investigate",
  "alert_id": "ALT-002",
  "severity_assessment": "MEDIUM",
  "log_query": "auth",
  "report_text": null,
  "reasoning": "1247 SSH failures in 10 min from known scanner IP = brute force"
}
```

### `GET /state?task=easy`
Returns full internal state snapshot.

### `GET /score?task=easy`
Returns current normalized score [0.0, 1.0].

### `GET /tasks`
Lists all tasks with descriptions and difficulty.

---

## 🔬 Baseline Inference Script

Requires: `API_BASE_URL`, `MODEL_NAME`, `HF_TOKEN` in environment.

```bash
export HF_TOKEN=hf_...
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export API_BASE_URL=https://router.huggingface.co/v1

# Run all tasks
python inference.py

# Run single task
CYBERSOC_TASK=easy python inference.py
```

**Expected output:**
```
[START] task=easy env=cybersoc model=Qwen/Qwen2.5-72B-Instruct
[STEP] step=1 action=investigate('ALT-003') reward=0.20 done=false error=null
[STEP] step=2 action=query_logs('ALT-003') reward=0.15 done=false error=null
[STEP] step=3 action=mark_false_positive('ALT-003') reward=0.30 done=false error=null
...
[END] success=true steps=7 score=0.842 rewards=0.20,0.15,0.30,...
```

---

## 🐳 Docker Deployment

```bash
# Build
docker build -t cybersoc-openenv .

# Run locally
docker run -p 7860:7860 cybersoc-openenv

# Test
curl http://localhost:7860/health
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" -d '{"task":"easy"}'
```

---

## 📁 Project Structure

```
cybersoc-openenv/
├── cyber_soc_env.py     # Core environment (Pydantic models, step/reset/state)
├── server.py            # FastAPI server (OpenEnv spec endpoints)
├── inference.py         # Baseline inference script
├── openenv.yaml         # OpenEnv metadata spec
├── index.html           # Interactive SOC dashboard UI
├── Dockerfile           # Container definition
├── requirements.txt     # Python dependencies
└── graders/
    └── graders.py       # Task graders (easy/medium/hard)
```

---

## 🏆 Evaluation Criteria Alignment

| Criterion | How We Address It |
|-----------|-------------------|
| **Real-world utility (30%)** | Mirrors actual Tier-1 SOC workflows; MITRE ATT&CK aligned; enterprise alert types |
| **Task & grader quality (25%)** | 3 tasks with proven difficulty ordering (0.0→0.5→1.0 scoring spread); deterministic graders |
| **Environment design (20%)** | Dense reward function; clean state management; meaningful partial credit |
| **Code quality (15%)** | Full Pydantic typing; OpenEnv spec; Dockerfile; openenv.yaml |
| **Creativity & novelty (10%)** | First SOC environment in OpenEnv ecosystem; novel multi-step reasoning + report quality scoring |

---

## 📊 Baseline Scores

| Task | Model | Score | Steps |
|------|-------|-------|-------|
| easy | Qwen2.5-72B-Instruct | ~0.75 | 8 |
| medium | Qwen2.5-72B-Instruct | ~0.55 | 15 |
| hard | Qwen2.5-72B-Instruct | ~0.35 | 24 |

*Reproducible with `seed=42`*

---

## 📄 License

MIT License. Built for the OpenEnv Hackathon.
