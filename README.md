# AI Agent Identity & Access Security Platform

A security platform for managing and monitoring **Non-Human Identities (NHIs)** such as AI agents and MCP-based tools.

The project applies traditional IAM and security principles to AI agents by implementing **identity discovery, risk assessment, RBAC authorization, Just-In-Time (JIT) access, real-time revocation, behavioral detection, and SIEM-based monitoring**.

## Security Lifecycle

```text
Discover → Assess Risk → Authenticate → Authorize → Grant JIT Access
                                         ↓
                              Monitor → Detect → Revoke
```

## Key Features

### NHI / AI Agent Discovery
Scans a project/repository to identify AI agents, roles, credentials, tools, permissions, MCP servers, and MCP permissions.

### NHI Risk Scoring
Each NHI receives a **0–100 risk score** based on:
- Credential Risk
- Privilege Risk
- Exposure Risk
- Blast Radius

Example:
```text
customer-support-agent → 64/100 HIGH
research-agent         → 68/100 HIGH
```

### RBAC Authorization
Role-Based Access Control prevents agents from requesting arbitrary permissions.

```text
Role: support-agent

Allowed:
    ticket:read
    ticket:write

Denied:
    customer:write
    user:write
    admin:write
```

### Just-In-Time Access
Permissions are granted only when required for a specific task.

```text
Agent → Access Request → RBAC Validation → JIT Grant → Short-lived JWT → Protected API
```

Each grant contains the agent identity, role, permission, task ID, grant ID, and expiration time.

### Token Scope Enforcement
JWTs are scoped to the granted permission. A `ticket:read` token cannot be used for a `customer:write` operation.

Expected result:
```text
HTTP 403 Forbidden
```

### Real-Time Token Revocation
Redis-backed shared state allows previously valid access grants to be revoked immediately rather than relying only on JWT expiration.

```text
Before revoke → 200 OK
After revoke  → 401 Unauthorized
```

### Behavioral Threat Detection
Repeated denied authorization requests from the same NHI within a short time window trigger a privilege-escalation alert.

```text
customer:write → DENIED
user:write     → DENIED
admin:write    → DENIED

PRIVILEGE_ESCALATION
Severity: HIGH
```

### Wazuh SIEM Integration
Application security events are written to `logs/audit.jsonl`. Wazuh consumes the structured JSON events and applies custom detection rules.

Example:
```text
Rule ID: 100100
Level: 12
NHI attempted denied administrative permission
```

The resulting Wazuh alerts are surfaced in the Streamlit security dashboard.

## Adversarial Security Testing

The project validates its controls through simulated attacks:

### Privilege Escalation
Unauthorized permissions such as `customer:write`, `user:write`, and `admin:write` are rejected by RBAC.

### Token Scope Abuse
A token issued for `ticket:read` is tested against a `customer:write` operation and receives `403 Forbidden`.

### Token Replay After Revocation
A valid token is tested before and after its grant is revoked:

```text
Before revoke → 200 OK
After revoke  → 401 Unauthorized
```

## Architecture

```text
                    ┌──────────────────────┐
                    │     NHI Scanner      │
                    │ Agents / Tools / MCP │
                    │ Credentials          │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │     Risk Engine      │
                    │ Credential / Privilege│
                    │ Exposure / Blast     │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │   JIT Access Broker  │
                    │       FastAPI        │
                    │ RBAC / JWT / Revoke  │
                    └───────┬───────┬──────┘
                            │       │
                       ┌────▼───┐   │
                       │ Redis  │   │
                       │ Grant  │   │
                       │ State  │   │
                       └────────┘   ↓
                         ┌──────────────────┐
                         │  Protected APIs  │
                         │ JWT + Scope      │
                         │ Enforcement      │
                         └────────┬─────────┘
                                  ↓
                         ┌──────────────────┐
                         │  Audit Logging   │
                         │     JSONL         │
                         └────────┬─────────┘
                                  ↓
                         ┌──────────────────┐
                         │      Wazuh       │
                         │       SIEM       │
                         │ Detection Rules  │
                         └────────┬─────────┘
                                  ↓
                         ┌──────────────────┐
                         │ Streamlit Console│
                         └──────────────────┘
```

## Technology Stack

**Backend:** Python, FastAPI, REST APIs, JWT

**Identity & Security:** IAM, RBAC, NHI Security, AI Agent Security, MCP Security, JIT Access, Least Privilege, Token Revocation, Threat Detection

**Infrastructure:** Redis, Docker, Wazuh SIEM

**Dashboard:** Streamlit, Pandas

**Development:** Git, GitHub, Python Virtual Environment

## Project Structure

```text
ai-agent-identity-security/
├── agent/
│   └── client.py
├── broker/
│   └── api.py
├── protected_api/
│   └── api.py
├── scanner/
│   ├── scanner.py
│   ├── analyzers/
│   ├── detection/
│   └── risk/
├── dashboard/
│   ├── app.py
│   └── styles.css
├── logs/
│   └── audit.jsonl
├── .env
├── .gitignore
└── README.md
```

## Challenges & Engineering Decisions

### Stateless JWT vs. Real-Time Revocation
Short-lived JWTs alone cannot provide immediate revocation. Redis was introduced as shared state for tracking active and revoked grants.

### Detecting AI-Agent Privilege Escalation
Authentication logs alone do not establish malicious intent. Behavioral detection was added to identify repeated denied requests from the same NHI within a defined time window.

### Wazuh Custom Log Integration
Custom AI-agent audit events required structured JSON logging, Wazuh JSON decoding, custom rules, ruleset testing, and validation through real attack simulations.

The final implementation successfully generated a **Level 12 Wazuh alert** for a denied administrative permission request.

### Explainable Risk Scoring
Instead of assigning arbitrary risk labels, the platform separates risk into credential, privilege, exposure, and blast-radius dimensions so that the reason behind an NHI's risk level is visible.

### Safe Security Testing
Protected APIs are intentionally mocked so privilege escalation, token abuse, revocation, and SIEM detection can be demonstrated without interacting with real production systems.

## Current Security Demonstration

```text
AI Agent
   ↓
Unauthorized Permission Request
   ↓
JIT Broker
   ↓
RBAC DENIED
   ↓
Audit Log
   ↓
Wazuh Rule 100100
   ↓
HIGH-SEVERITY ALERT
   ↓
Security Dashboard
```

## Future Improvements

- ABAC / policy-based authorization
- OAuth 2.0 / workload identity integration
- Short-lived credentials for external services
- Automated NHI remediation
- Agent behavior baselining
- ML-based anomaly detection
- More comprehensive MCP security policies
- Automated response to high-risk identities
- Additional SIEM/SOAR integrations

## Disclaimer

This project is an educational security research and portfolio implementation. External services and production credentials are not used for attack simulations. Protected APIs are intentionally mocked to demonstrate identity, authorization, monitoring, and detection controls safely.
