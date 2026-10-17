# Z-AgentShield

**Subtitle:** Real-Time Security Layer for Enterprise AI Agents  
**Tagline:** *Let AI act. Keep every action under control.*  
**Context:** IBM Z Datathon — Enterprise AI Security & Governance Track  
**Test Suite Status:** ![Tests](https://img.shields.io/badge/tests-174%2F174%20passing-brightgreen) ![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue) ![Architecture](https://img.shields.io/badge/arch-linux%2Fs390x%20%7C%20amd64%20%7C%20arm64-orange)

---

## Overview

As autonomous AI agents are granted access to enterprise APIs, sensitive databases, and mission-critical infrastructure, organizations face unmonitored execution risks, prompt injections, privilege escalations, and accidental data exposure.

**Z-AgentShield** is an inline, real-time security mediation layer that intercepts every agent action, evaluates it against enterprise security policies and behavioral baselines, and enforces a deterministic tri-state gating decision:

- **ALLOW:** Safe, compliant actions proceed with zero latency degradation.
- **REVIEW:** Anomalous or elevated-risk actions trigger human-in-the-loop escalation.
- **BLOCK:** Dangerous actions, credential exfiltration, or prohibitive policy violations are immediately neutralized.

Every evaluation is logged into an immutable audit trail with sensitive PII and credential redaction, built to run seamlessly on enterprise hardware including **IBM LinuxONE (s390x)**.

---

## System Architecture

```text
┌─────────────────┐       ┌────────────────────────────────────────────────────────┐       ┌──────────────────────┐
│ Enterprise AI   │ ----> │                      Z-AgentShield                     │ ----> │ Enterprise Systems   │
│ Autonomous Agent│       │                                                        │       │ APIs, DBs, Services  │
└─────────────────┘       │  1. Request Interception & Schema Validation           │       └──────────────────────┘
                          │  2. Redaction & Credential Masking Engine              │                  ▲
                          │  3. Rule-Based Policy & Risk Scoring Engine            │                  │
                          │  4. Behavioral Anomaly Detector (Velocity & Baselines) │                  │
                          │  5. Decision Gating (ALLOW / REVIEW / BLOCK)           │ ─── [ ALLOW ] ───┘
                          │                                                        │
                          │  SQLite Audit Trail <──> Streamlit Operations Console  │
                          └────────────────────────────────────────────────────────┘
```

---

## Implementation Status Tracker

All 10 project phases are fully implemented, verified, and hardened:

| Phase | Component / Layer | Status | Description |
|:-----:|-------------------|:------:|-------------|
| **1** | **Project Scaffolding & Config** | **COMPLETED** | Folder structure, `.env.example`, `requirements.txt`, and safe settings. |
| **2** | **Domain Models & Request Schemas** | **COMPLETED** | Pydantic v2 schemas (`AgentRequest`, `SecurityEvaluation`, `InterceptRequest`). |
| **3** | **Policy Engine & Risk Scoring** | **COMPLETED** | YAML policy rule parser, pattern matching, and composite risk scoring. |
| **4** | **Persistence & Redacted Audit Log** | **COMPLETED** | SQLite WAL persistence, PII/secret sanitizer, and review queue tables. |
| **5** | **Decision Gating & Execution Interception** | **COMPLETED** | Fail-closed execution gate, callbacks, and human-in-the-loop ticket lifecycle. |
| **6** | **Behavioral Anomaly Detection** | **COMPLETED** | Sliding-window velocity burst detection and IsolationForest threat scoring. |
| **7** | **FastAPI Security Gateway** | **COMPLETED** | REST endpoints (`/api/v1/intercept`, `/api/v1/reviews`, `/health`) with fail-closed handling. |
| **8** | **Streamlit Operations Console** | **COMPLETED** | Real-time SOC dashboard for telemetry, approval triage, and policy simulation. |
| **9** | **Automated Test Suite** | **COMPLETED** | Complete regression test suite (**174/174 passing** across all modules). |
| **10** | **LinuxONE (s390x) Deployment** | **COMPLETED** | Multi-arch Dockerfile, docker-compose, and enterprise deployment guide. |

---

## Project Structure

```text
Z-AgentShield/
├── src/
│   └── zagentshield/
│       ├── __init__.py       # Package metadata
│       ├── config.py         # Safe environment configuration
│       ├── core/             # Enums, Pydantic models, schemas, and DecisionGate
│       ├── api/              # FastAPI Security Gateway application
│       ├── policies/         # YAML policy rules & numerical risk engine
│       ├── anomalies/        # Velocity burst & IsolationForest anomaly detection
│       ├── audit/            # Redaction engine & audit logger
│       └── db/               # SQLite database & repository
├── dashboard/
│   └── app.py                # Streamlit SOC Operations Console
├── tests/                    # 174 Unit and integration tests
├── config/
│   └── policies.yaml         # Enterprise security policy definitions
├── docs/                     # Architectural and LinuxONE deployment specifications
├── scripts/
│   └── seed_demo_data.py     # Synthetic enterprise telemetry generator
├── Dockerfile                # Multi-arch container image (linux/s390x, amd64, arm64)
├── docker-compose.yml        # Multi-service stack (Gateway + Dashboard)
├── requirements.txt          # Minimal dependency constraints
└── README.md                 # Project documentation
```

---

## Quickstart & Verification

### 1. Environment Setup

```bash
# Clone and navigate to repository
cd Z-AgentShield

# Copy template configuration
cp .env.example .env

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Test Suite (174/174 Passing)

```bash
# Execute full unit and integration test suite
python -m unittest discover tests
```

### 3. Seed Realistic Demonstration Data

```bash
python scripts/seed_demo_data.py
```

### 4. Launch FastAPI Security Gateway

```bash
uvicorn zagentshield.api.app:app --host 127.0.0.1 --port 8000 --reload
```

Test interception endpoint:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-001",
    "action": "read_faq",
    "category": "READ",
    "resource": "public/faq/knowledge_base",
    "parameters": {"query": "login"}
  }'
```

### 5. Launch Streamlit Operations Console (SOC Dashboard)

```bash
streamlit run dashboard/app.py
```

Open `http://localhost:8501` to view real-time metrics, triage pending human-in-the-loop review tickets, inspect redacted audit trails, and simulate policies.

---

## Deployment on IBM LinuxONE (s390x)

Z-AgentShield supports native build and execution on **IBM LinuxONE (`linux/s390x`)**:

```bash
# Build multi-architecture container
docker buildx build --platform linux/s390x,linux/amd64 -t zagentshield:latest .

# Run with docker-compose
docker-compose up -d
```

For complete enterprise architecture, mTLS, and IBM Secure Execution setup, see [`docs/PHASE10_LINUXONE_DEPLOYMENT.md`](docs/PHASE10_LINUXONE_DEPLOYMENT.md).
